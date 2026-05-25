# Vulnerability Report: Recovery Typo Token Burn

**Vulnerability Category:** Recovery Typo Token Burn Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
The `recoverERC20` function in `MerkleDistributor2` is intended to allow the contract owner to retrieve ERC20 tokens that were accidentally sent to the contract. However, the function is incorrectly implemented, causing the tokens to be transferred to the token contract's address (`_token`) itself, rather than to the actual `owner` of the `MerkleDistributor2` contract. This effectively locks or burns any recovered tokens, making the recovery mechanism non-functional and leading to an irreversible loss of funds.

---

## 2. Theoretical Exploit Scenario
1.  An ERC20 token (e.g., `TOKEN_A`) is accidentally sent to the `MerkleDistributor2` contract.
2.  The `owner` of `MerkleDistributor2` calls `recoverERC20(address(TOKEN_A))` to attempt to retrieve the `TOKEN_A` tokens.
3.  The line `IERC20(_token).safeTransfer(_token, IERC20(_token).balanceOf(address(this)));` is executed.
4.  This command attempts to transfer the entire balance of `TOKEN_A` held by `MerkleDistributor2` *to the `TOKEN_A` contract itself* (address `_token`).
5.  If `TOKEN_A` is a standard ERC20 token, transferring tokens to its own contract address effectively locks them within the token contract, making them permanently inaccessible and irrecoverable by the owner or any other party. This results in the permanent loss of the tokens.

---

## 3. Remediation
Modify the `recoverERC20` function to transfer the tokens to the `owner` of the `MerkleDistributor2` contract, as originally intended.

```diff
--- a/contracts/MerkleDistributor2.sol
+++ b/contracts/MerkleDistributor2.sol
@@ -62,6 +62,6 @@
 
     function recoverERC20(address _token) public {
         require(msg.sender == owner);
-        IERC20(_token).safeTransfer(_token, IERC20(_token).balanceOf(address(this)));
+        IERC20(_token).safeTransfer(owner, IERC20(_token).balanceOf(address(this)));
     }
 }
```
