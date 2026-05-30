# utils/anvil_verifier.py
import os
import re
import asyncio
from pathlib import Path

# --- 0. PATH RESOLUTION (OS-AGNOSTIC ROOT CONTEXT) ---
UTILS_DIR = Path(__file__).parent.resolve()
BASE_DIR = UTILS_DIR.parent.resolve()
SANDBOX_DIR = BASE_DIR / "anvil_sandbox"

async def initialize_sandbox():
    """
    Asynchronously initializes the Foundry test suite inside the sandbox directory.
    Uses non-blocking process creation.
    """
    if not os.path.exists(SANDBOX_DIR):
        print("🛠️ Initializing Anvil Sandbox environment...")
        process = await asyncio.create_subprocess_exec(
            "forge", "init", str(SANDBOX_DIR), "--no-commit",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()
        print("✅ Sandbox Ready.")

def extract_solidity_code(report_text: str) -> str:
    """
    Pulls raw Solidity test blocks out of markdown or unstructured string payloads.
    """
    if not report_text:
        return ""
    # Check if string is already raw Solidity code instead of markdown wrapper
    if "contract " in report_text and "import " in report_text and "```" not in report_text:
        return report_text.strip()
        
    match = re.search(r"```solidity\n(.*?)```", report_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return ""

async def run_dynamic_verification(report_or_code: str, rpc_url: str) -> bool:
    """
    Asynchronously writes the AI-generated property fuzzer down to disk, spins up
    an isolated mainnet Anvil fork sandbox, and strictly validates execution metrics.

    Returns:
        True if the exploit successfully breaks contract properties under fuzzing conditions.
        False if the test fails, code fails to compile, or loops infinitely.
    """
    await initialize_sandbox()
    
    poc_code = extract_solidity_code(report_or_code)
    if not poc_code:
        print("⚠️ [SANDBOX SKIP] No valid Solidity PoC payload isolated. Dropping execution window.")
        return False

    test_file_path = SANDBOX_DIR / "test" / "ZeroDayExploit.t.sol"
    
    # Non-blocking file I/O operations block context switching using basic open paths safely
    with open(test_file_path, "w", encoding="utf-8") as f:
        f.write(poc_code)

    print("🔥 Spinning up non-blocking Anvil Mainnet Fork environment...")
    
    try:
        # Launch non-blocking background task worker context
        process = await asyncio.create_subprocess_exec(
            "forge", "test", "--fork-url", rpc_url, "--match-path", "test/ZeroDayExploit.t.sol",
            cwd=str(SANDBOX_DIR),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Enforce execution timeout limits natively using the async I/O framework
        stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=60.0)
        output = stdout_bytes.decode(errors="ignore") + stderr_bytes.decode(errors="ignore")
        
        # --- TECHNICAL INVARIANT MATRIX RUNS ---
        if "Compiler run failed" in output:
            print("❌ [SANDBOX REJECT] AI generated uncompilable Solidity layout structures.")
            return False
            
        # PROOF OF WORK VERIFICATION: Enforce property-based testing signatures
        # Ensures that the system actually executed a fuzz test profile instead of standard code paths
        if "(runs: " not in output and "fuzz" not in output.lower():
            print("⚠️ [SANDBOX REJECT] Threat model rejected: AI generated static assertions instead of dynamic property fuzzing.")
            return False
            
        if "Failing tests:" in output or "FAIL." in output:
            print("🛡️ [SANDBOX REJECT] Protocol invariant held under fuzzing pressure. False positive caught.")
            return False
            
        if "Passing tests:" in output or "OK." in output:
            print("🚨 [SANDBOX CONFIRMED] CRITICAL: Invariant broken! Fuzzer successfully breached execution boundaries.")
            return True

    except asyncio.TimeoutExpired:
        print("⏳ [SANDBOX TIMEOUT] Execution loop terminated: Code caused an infinite math loop.")
        return False
    except Exception as e:
        print(f"⚠️ [SANDBOX OS ERROR] System runtime error processing fork layout: {e}")
        return False

    return False