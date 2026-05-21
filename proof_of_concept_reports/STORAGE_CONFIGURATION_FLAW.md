# Vulnerability Report: Storage Configuration Flaw

**Vulnerability Category:** Storage Configuration Flaw Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
The `CurveStableSwapNG` contract contains a critical logic flaw related to the handling of rebasing tokens when they are misconfigured during pool initialization. The `__init__` constructor sets the `pool_contains_rebasing_tokens` immutable variable based on whether `2` (Rebasing asset type) is present in the `_asset_types` array.

If a token that is *actually* a rebasing token (e.g., stETH) is included in the pool's `_coins` list, but its corresponding `asset_type` is *incorrectly* set to something other than `2` (e.g., `0` for a standard ERC20), the `pool_contains_rebasing_tokens` flag will be `False`.

This misconfiguration leads to several critical issues:
1.  **Incorrect Balance Accounting**: The `_balances()` internal view function, which is fundamental for all AMM calculations (e.g., `get_D`, `get_y`, `calc_withdraw_one_coin`), will use `self.stored_balances[i]` for the misconfigured rebasing token. `self.stored_balances` is only updated via explicit `_transfer_in` and `_transfer_out` calls and does not automatically reflect rebases. Consequently, any positive rebases (token balance increases) will not be registered by the pool's internal state.
2.  **Rebases Can Be Stolen**: The actual `ERC20(coins[i]).balanceOf(self)` for the misconfigured rebasing token will grow due to rebases, while `self.stored_balances[i]` remains stale. This creates a discrepancy where the pool holds more physical tokens than its internal accounting indicates. This surplus (the rebase gains) effectively becomes "stuck" or "stolen" within the pool. An attacker can exploit this discrepancy to withdraw more than their proportional share, or the funds could be implicitly redistributed to other users in an unfair manner, or even effectively locked. The contract's own internal documentation explicitly warns about this: "If pool contains rebasing token and `asset_types` does not contain 2 (Rebasing) then this is an incorrect implementation and rebases can be stolen."

This is a high-severity logic flaw because, while it requires an initial administrative misconfiguration, the flaw itself leads to an unprivileged attacker (or any LP) being able to extract value that doesn't belong to them, or for value to be lost.

---

## 2. Theoretical Exploit Scenario
1.  **Pool Creation with Misconfiguration**: An admin deploys `CurveStableSwapNG`, including a rebasing token (e.g., stETH) in the `_coins` array. However, they mistakenly set the corresponding `asset_type` in the `_asset_types` array to `0` (Standard ERC20) instead of `2` (Rebasing). As a result, the `pool_contains_rebasing_tokens` immutable flag is `False`.
2.  **User Deposits Liquidity**: User A adds liquidity to the pool, including the misconfigured rebasing token. The `_transfer_in` function updates `self.stored_balances[rebasing_token_idx]` to reflect User A's deposit.
3.  **Rebase Occurs**: Over time, the balance of the rebasing token held by the `CurveStableSwapNG` contract increases due to positive rebases (e.g., stETH's underlying ETH value grows). For example, if 100 stETH was deposited, it might now internally represent 101 stETH in the actual ERC20 balance.
4.  **Internal State Remains Stale**: Because `pool_contains_rebasing_tokens` is `False`, the `_balances()` function will continue to use `self.stored_balances[rebasing_token_idx]` (which is still 100), ignoring the actual 101 stETH balance in the token contract.
5.  **Exploitation by Disproportionate Withdrawal/Swap**:
    *   **Scenario A (Withdrawal)**: An attacker (or User A, or any LP) performs a `remove_liquidity` or `remove_liquidity_imbalance` operation. The calculation of `_amounts` to be withdrawn (or `burn_amount`) relies on the `_balances()` function. Since `_balances()` underreports the actual rebasing token quantity, the attacker's proportional share of the *actual* physical tokens in the pool is higher than what the pool's internal state (based on `stored_balances`) suggests. By carefully crafting a withdrawal (e.g., removing all other tokens and a small amount of the rebasing token, or removing all LP tokens), the attacker can effectively claim a larger portion of the *actual* rebasing token balance than their `_burn_amount` would normally entitle them to if `_balances()` were accurate. The rebasing gains accumulated while `stored_balances` was static can be siphoned off.
    *   **Scenario B (Swap)**: If the `exchange_received` function is disabled for rebasing tokens (as per the contract's own internal warning), then the standard `exchange` function will be used. While `_transfer_in` for `exchange` still updates `stored_balances`, the underlying `_balances()` function used for `xp` and `D` calculations will be stale. This could lead to unfavorable pricing for swaps or allow an attacker to exploit the delta between reported and actual balances, gaining extra tokens or causing losses to others.

The core of the exploit is that the rebase gains accrue in the contract but are not reflected in its internal accounting, allowing anyone to potentially "claim" these gains by interacting with the pool in a way that benefits from this discrepancy.

---

## 3. Remediation
The most robust solution is to consistently apply the logic for handling rebasing tokens to all assets, regardless of their `asset_type` configuration. This involves always "gulping" balances (reading `ERC20(coins[i]).balanceOf(self)` directly) and updating `stored_balances` based on observed differences. This makes the contract resilient to `asset_type` misconfigurations.

**Specific Code Recommendations:**

1.  **Modify `_balances()` function**:
    Change the logic to always read the current `balanceOf` from the token contract for all coins, ensuring that rebases are always accounted for.

    ```vyper
        @view
        @internal
        def _balances() -> DynArray[uint256, MAX_COINS]:
            result: DynArray[uint256, MAX_COINS] = empty(DynArray[uint256, MAX_COINS])
            balances_i: uint256 = 0

            for i in range(N_COINS_128, bound=MAX_COINS_128):
                # Always read balances from the token contract to account for rebases
                # and ensure consistency, regardless of `pool_contains_rebasing_tokens` flag.
                balances_i = ERC20(coins[i]).balanceOf(self) - self.admin_balances[i]
                result.append(balances_i)

            return result
    ```

2.  **Modify `_transfer_out()` function**:
    Ensure that `stored_balances` are always updated based on the actual observed change in the contract's balance before and after an ERC20 transfer, rather than relying on a flag. This handles fees-on-transfer and rebases consistently.

    ```vyper
        @internal
        def _transfer_out(_coin_idx: int128, _amount: uint256, receiver: address):
            assert receiver != empty(address)  # dev: do not send tokens to zero_address

            # Always cache balances pre and post to account for fee on transfers, rebases, etc.
            # This makes the logic consistent for all tokens and robust against misconfiguration.
            coin_balance_before: uint256 = ERC20(coins[_coin_idx]).balanceOf(self)
            assert ERC20(coins[_coin_idx]).transfer(
                receiver, _amount, default_return_value=True
            )
            # Update stored_balances based on actual change observed, including any rebases
            # that might have occurred or any fees on transfer.
            self.stored_balances[_coin_idx] = coin_balance_before - ERC20(coins[_coin_idx]).balanceOf(self)
    ```

These changes effectively make the `pool_contains_rebasing_tokens` variable redundant for the core accounting logic, as all balances would be "gulped" directly from the ERC20 contract, providing robust handling regardless of the `asset_type` configuration.
