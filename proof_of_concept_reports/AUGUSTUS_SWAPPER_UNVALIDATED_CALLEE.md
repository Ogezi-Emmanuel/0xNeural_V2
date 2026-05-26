# Vulnerability Report: Augustus Swapper Unvalidated Callee

**Vulnerability Category:** Augustus Swapper Unvalidated Callee Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
The `performSimpleSwap` function allows an unprivileged user to execute arbitrary external calls to any contract address with arbitrary calldata and value. This is facilitated by the `externalCall` function, which is called within a loop using user-provided `callees` (target addresses) and `exchangeData` (calldata and value).

Crucially, there is no whitelist check (like `_whitelisted.hasRole`) for the `callees[i]` addresses in `performSimpleSwap`, unlike in `performSwap` and `performBuy` which validate the `route.exchange` against a whitelist.

This lack of validation allows an attacker to direct `AugustusSwapper` to call any contract, including the `fromToken` contract itself, and execute any function on it. Specifically, after the `fromToken` amount is transferred from `msg.sender` to `AugustusSwapper` via `_tokenTransferProxy.transferFrom`, the `AugustusSwapper` contract holds the `fromToken`. A malicious actor can then force `AugustusSwapper` to transfer these tokens to an arbitrary address.

---

## 2. Theoretical Exploit Scenario
1.  **Initiate Swap:** An attacker calls either `simplBuy` or `simpleSwap`, supplying a `fromToken` and `fromAmount`.
2.  **Token Transfer:** The contract executes `_tokenTransferProxy.transferFrom(address(fromToken), msg.sender, address(this), fromAmount);`. This transfers the `fromAmount` of `fromToken` from the attacker to the `AugustusSwapper` contract.
3.  **Malicious Callee Injection:** The attacker crafts the `callees` array such that one of the elements, say `callees[k]`, is the address of the `fromToken` contract itself.
4.  **Arbitrary Function Execution:** The attacker crafts `exchangeData`, `startIndexes`, and `values` such that when `externalCall` is executed for `callees[k]`, it results in a call to `IERC20(address(fromToken)).transfer(attackerAddress, amountToSteal)`. The `amountToSteal` can be the entire `fromAmount` now held by `AugustusSwapper`.
5.  **Token Drain:** The `externalCall` executes the crafted `transfer` call from the context of `AugustusSwapper`, causing `AugustusSwapper` to transfer its `fromToken` balance (which was intended for the swap) to the `attackerAddress`.
6.  **Transaction Reversion (Post-Theft):** The subsequent `require(receivedAmount >= toAmount, ...)` check will likely fail, causing the transaction to revert. However, by this point, the `fromToken` has already been transferred out of `AugustusSwapper` into the attacker's control, completing the theft.

---

## 3. Remediation
Implement a whitelist check for `callees[i]` in the `performSimpleSwap` function, similar to how `route.exchange` is checked in `performSwap` and `performBuy`. Only allow calls to whitelisted exchange contracts.

```diff
diff --git a/original_contracts/AugustusSwapper.sol b/original_contracts/AugustusSwapper.sol
index d0e02c5..19d690a 100644
--- a/original_contracts/AugustusSwapper.sol
+++ b/original_contracts/AugustusSwapper.sol
@@ -321,6 +321,11 @@
                 "Can not call TokenTransferProxy Contract"
             );
 
+            require(
+                _whitelisted.hasRole(_whitelisted.WHITELISTED_ROLE(), callees[i]),
+                "AugustusSwapper: Callee not whitelisted"
+            );
+
             bool result = externalCall(
                 callees[i], //destination
                 values[i], //value to send
```
