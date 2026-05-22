# Vulnerability Report: Unofficial Sdk Supply Chain

**Vulnerability Category:** Unofficial Sdk Supply Chain Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
The `WormholeTransceiver.sol` contract imports and uses components from the `wormhole-solidity-sdk`. Specifically, it imports `"wormhole-solidity-sdk/libraries/BytesParsing.sol"` and `"wormhole-solidity-sdk/interfaces/IWormhole.sol"`. According to the historical security reference, the `wormhole-solidity-sdk` version `0.9.0` from npm is an unofficial deployment. The official Wormhole team has confirmed that npm packages published by `sullof <francesco@sullo.co>` are not their official release, and the only approved version is `v0.1.0` available on GitHub, recommending `forge install wormhole-foundation/wormhole-solidity-sdk@v0.1.0`. Using an unofficial SDK introduces significant supply chain security vulnerabilities, compatibility issues, and maintenance challenges, as the codebase relies on unverified third-party code. An attacker could potentially compromise this unofficial package to inject malicious code into the bridge's core cross-chain messaging functionality.

---

## 2. Theoretical Exploit Scenario
1.  **Compromise Unofficial SDK**: An attacker identifies that the WormholeTransceiver contract relies on the unofficial `wormhole-solidity-sdk` from npm.
2.  **Inject Malicious Code**: The attacker gains control over the unofficial npm package or its distribution channel.
3.  **Deploy Malicious Contract**: The attacker injects malicious code into the SDK, which could then be incorporated into the `WormholeTransceiver` contract during its next deployment or upgrade. For example, the malicious code could alter the `BytesParsing` logic to misinterpret VAAs or modify the `IWormhole` interface to interact with a malicious Wormhole core bridge.
4.  **Exploit Cross-Chain Transfers**: Once the compromised `WormholeTransceiver` is deployed, the attacker can leverage the injected backdoor to:
    *   Fabricate or alter cross-chain messages, potentially leading to unauthorized minting or burning of tokens (if the NTTManager relies on the transceiver's logic).
    *   Bypass VAA verification, allowing them to pass invalid or replayed messages.
    *   Redirect funds during cross-chain transfers to an address controlled by the attacker.

---

## 3. Remediation
The project should immediately migrate to the official and verified `wormhole-solidity-sdk`. The recommended action is to use `forge install wormhole-foundation/wormhole-solidity-sdk@v0.1.0` or a more recent officially sanctioned version, and update all imports in the codebase to reflect this change. All contracts that depend on this SDK, including `WormholeTransceiver.sol`, should be re-audited and redeployed with the official SDK.
