# Vulnerability Report: Fee On Transfer Strategy Lock

**Vulnerability Category:** Fee On Transfer Strategy Lock Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
Handling of Fee-on-Transfer Tokens Leads to Funds Stuck in Strategy

The `BaseStrategy` contract, specifically in its `harvest()` and `withdraw(uint _amount)` functions, calculates fee distributions based on the token balance *before* initiating `safeTransfer` calls. This design is vulnerable to issues when interacting with "fee-on-transfer" ERC20 tokens, which deduct a percentage or fixed amount from the transferred value.

If either `reward` (in `harvest()`) or `want` (in `withdraw(uint)`) is a fee-on-transfer token, the actual amount received by the `strategist` and the `_vault` will be less than the amount calculated. This discrepancy results in residual funds (the accumulated transfer fees) being left behind in the strategy contract. These funds are not accounted for in subsequent operations and can accumulate over time, becoming permanently stuck and unrecoverable within the strategy. This flaw violates the expectation that all transferable funds are correctly distributed or returned.

---

## 2. Theoretical Exploit Scenario
1.  A `StrategyCurve3Pool` (or any strategy inheriting `BaseStrategy`) is initialized or updated to use a `want` or `reward` token that applies a fee on transfer (e.g., a tax token).
2.  During a `harvest()` operation, `_claimReward()` brings `reward` tokens into the strategy. The `harvest()` function then calculates `_fee` for the `strategist` based on the strategy's current balance of `reward` tokens.
3.  `IERC20(reward).safeTransfer(strategist, _fee)` is executed. If `reward` is a fee-on-transfer token, the `strategist` receives less than `_fee`, and the difference remains in the strategy.
4.  Subsequently, `IERC20(reward).safeTransfer(_vault, _balance.sub(_fee))` is executed for the remaining balance. Again, the `_vault` receives less than `_balance.sub(_fee)` due to transfer fees, leaving more residual funds in the strategy.
5.  A similar scenario occurs during a `withdraw(uint _amount)` call, where the `managementFee` in `want` tokens is transferred to the `strategist`, and the remainder to the `_vault`. If `want` is a fee-on-transfer token, residual funds accumulate.
6.  Over time, these accumulated residual funds become stuck in the `BaseStrategy` contract, as there is no mechanism to sweep or recover them.

---

## 3. Remediation
To properly handle fee-on-transfer tokens and prevent funds from getting stuck, the contract should measure the token balance of `address(this)` *after* each external transfer to determine the *actual* amount remaining, rather than relying solely on the pre-transfer calculated values.

**Proposed changes for `BaseStrategy.sol`:**

```diff
--- a/contracts/farm/strategies/BaseStrategy.sol
+++ b/contracts/farm/strategies/BaseStrategy.sol
@@ -140,16 +140,24 @@ abstract contract BaseStrategy {
     function harvest() external {
         _claimReward();
 
-        uint _balance = IERC20(reward).balanceOf(address(this));
-        require(_balance > 0, "!_balance");
-        uint256 _fee = _balance.mul(performanceFee).div(max);
-        IERC20(reward).safeTransfer(strategist, _fee);
+        uint256 _preTransferBalance = IERC20(reward).balanceOf(address(this));
+        require(_preTransferBalance > 0, "!_preTransferBalance");
+
+        // Calculate the intended performance fee for the strategist
+        uint256 _intendedStrategistFee = _preTransferBalance.mul(performanceFee).div(max);
+        
+        // Transfer the intended fee to the strategist.
+        // If 'reward' token is fee-on-transfer, the strategist might receive less.
+        IERC20(reward).safeTransfer(strategist, _intendedStrategistFee);
+        
+        // The remaining balance in the strategy, after the strategist's transfer (and any fees),
+        // is transferred to the vault to ensure no funds are stuck.
+        uint256 _remainingBalance = IERC20(reward).balanceOf(address(this));
 
         address _vault = IController(controller).vaults(address(this));
         require(_vault != address(0), "!vault"); // additional protection so we don't burn the funds
-        IERC20(reward).safeTransfer(_vault, _balance.sub(_fee));
+        IERC20(reward).safeTransfer(_vault, _remainingBalance);
     }
 
     // Controller only function for creating additional rewards from dust
@@ -165,13 +173,21 @@ abstract contract BaseStrategy {
             _amount = _amount.add(_balance);
         }
 
-        uint256 _fee = _amount.mul(managementFee).div(max);
-        IERC20(want).safeTransfer(strategist, _fee);
+        // Calculate the intended management fee for the strategist
+        uint256 _intendedStrategistFee = _amount.mul(managementFee).div(max);
+        
+        // Transfer the intended fee to the strategist.
+        // If 'want' token is fee-on-transfer, the strategist might receive less.
+        IERC20(want).safeTransfer(strategist, _intendedStrategistFee);
+        
+        // The remaining balance in the strategy, after the strategist's transfer (and any fees),
+        // is transferred to the vault to ensure no funds are stuck.
+        uint256 _remainingBalance = IERC20(want).balanceOf(address(this));
 
         address _vault = IController(controller).vaults(address(this));
         require(_vault != address(0), "!vault"); // additional protection so we don't burn the funds
-        IERC20(want).safeTransfer(_vault, _amount.sub(_fee));
+        IERC20(want).safeTransfer(_vault, _remainingBalance);
     }
 
     // Withdraw all funds, normally used when migrating strategies
```
