# Vulnerability Report: Core Amm Div Zero Dos

**Vulnerability Category:** Core Amm Div Zero Dos Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
**Denial of Service (DoS) via Division-by-Zero in Core AMM Math**

The `CurveStableSwapNG` contract's core mathematical functions, `get_y` and `get_D`, are susceptible to a division-by-zero vulnerability. These functions are critical for calculating output amounts, invariant `D`, and ultimately, the pool's functionality (swaps, liquidity additions/removals).

The `get_y` and `get_D` functions iterate over the virtual balances `_xp` (which are derived from the actual token balances `_balances` and `_stored_rates`). If the balance of any underlying asset `coins[i]` in the pool is drained to zero (or near zero) by an attacker, the corresponding `_xp[i]` value will also become zero. Subsequently, when these `_xp[i]` values are used as divisors in calculations within `get_y` and `get_D` (e.g., `D_P = D_P * D / x` in `get_D`, or `c = c * D / (_x * N_COINS)` in `get_y`), the transaction will revert due to a division-by-zero error.

This effectively bricks the pool, preventing legitimate users from performing essential operations such as adding or removing liquidity, or executing swaps, leading to a Denial of Service.

---

## 2. Theoretical Exploit Scenario
1.  **Asset Draining:** An attacker initiates a series of `exchange` operations (or a single large swap) to significantly deplete the reserves of one of the `coins[i]` within the `CurveStableSwapNG` pool.
2.  **Zero Virtual Balance (`xp[i]`):** As the actual `coins[i]` balance approaches zero, the calculated `_balances()[i]` (actual balance less admin fees) will also become zero. Consequently, the corresponding virtual balance `_xp_mem()[i]` (calculated as `_rates[i] * _balances[i] / PRECISION`) will also become zero.
3.  **Trigger DoS:** A subsequent attempt by any user (including the attacker) to perform an operation that relies on the `get_y` or `get_D` functions—such as `add_liquidity`, `remove_liquidity_imbalance`, `_exchange`, `remove_liquidity_one_coin`, `get_dx`, `get_dy`, `get_p`, or `get_virtual_price`—will call `get_y` or `get_D`.
4.  **Division-by-Zero Revert:** Within `get_y` or `get_D`, when the loop attempts to use the zero `_x` (or `x` from `_xp`) as a divisor, the transaction will revert with a division-by-zero error.
5.  **Pool Inoperability:** This renders the pool unusable for these critical operations, causing a Denial of Service for all users and for any protocols that integrate with or rely on the pool's functionality and price oracles.

---

## 3. Remediation
Implement explicit checks to ensure that no `xp` (virtual balance) value is zero before it is used as a divisor in the `get_y` and `get_D` functions. The safest approach is to revert with an informative error message if a `xp` value is found to be zero, as operating with a zero asset balance can lead to incorrect or undefined mathematical behavior in an AMM.

**Suggested Code Changes:**

**In `get_D` function:**
```vyper
@pure
@internal
def get_D(_xp: DynArray[uint256, MAX_COINS], _amp: uint256) -> uint256:
    S: uint256 = 0
    for x_val in _xp: # Renamed loop variable to x_val to avoid conflict if any.
        assert x_val > 0, "AMM: Virtual balance (xp) cannot be zero for D calculation" # ADD THIS ASSERTION
        S += x_val
    if S == 0:
        return 0

    D: uint256 = S
    Ann: uint256 = _amp * N_COINS

    for i in range(255):

        D_P: uint256 = D
        for x_val_inner in _xp: # Renamed loop variable to x_val_inner
            # assert x_val_inner > 0, "AMM: Virtual balance (xp) cannot be zero for D_P calculation" # This assertion is already covered above but can be repeated for clarity.
            D_P = D_P * D / x_val_inner
        D_P /= pow_mod256(N_COINS, N_COINS)
        Dprev: uint256 = D

        D = (
            (unsafe_div(Ann * S, A_PRECISION) + D_P * N_COINS) * D
            /
            (
                unsafe_div((Ann - A_PRECISION) * D, A_PRECISION) +
                unsafe_add(N_COINS, 1) * D_P
            )
        )

        if D > Dprev:
            if D - Dprev <= 1:
                return D
        else:
            if Dprev - D <= 1:
                return D
    raise
```

**In `get_y` function:**
```vyper
@view
@internal
def get_y(
    i: int128,
    j: int128,
    x: uint256,
    xp: DynArray[uint256, MAX_COINS],
    _amp: uint256,
    _D: uint256
) -> uint256:
    # ... (existing code)
    S_: uint256 = 0
    _x_curr: uint256 = 0 # Renamed local var to avoid shadowing
    y_prev: uint256 = 0
    c: uint256 = D
    Ann: uint256 = amp * N_COINS

    for _i in range(MAX_COINS_128):

        if _i == N_COINS_128:
            break

        if _i == i:
            _x_curr = x
        elif _i != j:
            _x_curr = xp[_i]
        else:
            continue

        S_ += _x_curr
        assert _x_curr > 0, "AMM: Virtual balance (xp) cannot be zero for c calculation" # ADD THIS ASSERTION
        c = c * D / (_x_curr * N_COINS)

    c = c * D * A_PRECISION / (Ann * N_COINS)
    b: uint256 = S_ + D * A_PRECISION / Ann  # - D
    y: uint256 = D
    # ... (rest of the function)
```
