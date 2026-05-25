# Vulnerability Report: Harvest Zero Slippage Mev

**Vulnerability Category:** Harvest Zero Slippage Mev Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
The `harvest()` function performs multiple token swaps through Curve (LUSD pool) and Uniswap V3 (Router) with no slippage protection. Specifically, the calls to `ICurveFi_4(...).exchange_underlying(...)` use `_min_to_amount: 0`, and the calls to `ISwapRouter(...).exactInput(...)` use `amountOutMinimum: 0`. This design allows an attacker to execute a sandwich attack by front-running and back-running the `harvest()` transaction.

An attacker can:
1.  **Front-run**: Artificially manipulate the price of the trading pair on the AMM (Curve or Uniswap V3) by executing a swap that pushes the price against the strategy's upcoming trade.
2.  **Execute `harvest()`**: The strategy's `harvest()` function then executes its swap at this manipulated, unfavorable price, receiving significantly fewer output tokens than it should. Since `_min_to_amount` or `amountOutMinimum` is zero, the transaction will not revert, even if the slippage is extreme.
3.  **Back-run**: The attacker then executes another swap to move the price back to its original state, profiting from the price difference created by the strategy's trade.

This results in a direct loss of accumulated yield for the protocol and its users during each `harvest()` operation, which can be significant and consistently drained by MEV bots.

---

## 2. Theoretical Exploit Scenario
1.  An attacker monitors the mempool for `StrategyLqty.harvest()` transactions.
2.  When a `harvest()` transaction is detected, the attacker prepares two transactions:
    *   **Transaction A (Front-run)**: Swaps a large amount of a token (e.g., LUSD or USDC) on the relevant AMM (Curve or Uniswap V3) to significantly move the price away from the strategy's expected trade direction.
    *   **Transaction B (Back-run)**: Swaps the token back to its original state, profiting from the price movement caused by the strategy's trade.
3.  The attacker sends Transaction A with a higher gas price than the `harvest()` transaction, and Transaction B with a slightly lower gas price than Transaction A but higher than the `harvest()` transaction. This ensures the order: Attacker A -> `harvest()` -> Attacker B.
4.  The `harvest()` function will execute its swaps at the manipulated, unfavorable prices (e.g., selling LUSD for far less USDC, selling USDC for far less WETH, or selling WETH for far less LQTY). Due to `amountOutMinimum: 0`, these unfavorable trades will not revert.
5.  The attacker profits from the price difference, effectively draining a portion of the harvested yield from the strategy.

---

## 3. Remediation
Implement robust slippage protection for all external swap calls within the `harvest()` function.
For each swap, calculate a reasonable `min_to_amount` or `amountOutMinimum` based on the expected amount out and an acceptable slippage percentage (e.g., 0.5% - 2%). This amount should be derived from a fresh price quote (e.g., directly from the router `getAmountsOut` or a robust oracle if available) immediately before the swap.

Example for Uniswap V3 `exactInput`:
Before:
```solidity
ISwapRouter(univ3Router).exactInput(
    ISwapRouter.ExactInputParams({
        path: abi.encodePacked(usdc, uint24(500), weth),
        recipient: address(this),
        deadline: block.timestamp + 300,
        amountIn: _usdc,
        amountOutMinimum: 0 // VULNERABLE
    })
);
```
Remediation:
```solidity
// Example: Assuming a helper function to get expected amount out and apply slippage
uint256 expectedWethOut = ISwapRouter(univ3Router).getAmountsOut(
    _usdc,
    abi.encodePacked(usdc, uint24(500), weth)
); // (hypothetical function or manual calculation)
uint256 amountOutMin = expectedWethOut.mul(9950).div(10000); // 0.5% slippage

ISwapRouter(univ3Router).exactInput(
    ISwapRouter.ExactInputParams({
        path: abi.encodePacked(usdc, uint24(500), weth),
        recipient: address(this),
        deadline: block.timestamp + 300,
        amountIn: _usdc,
        amountOutMinimum: amountOutMin // REMEDIATED
    })
);
```

Similarly, for the Curve `exchange_underlying` call:
Before:
```solidity
ICurveFi_4(lusd_pool).exchange_underlying(0, 2, _lusd, 0); // VULNERABLE
```
Remediation:
```solidity
// Calculate expected USDC out from Curve and apply slippage.
// This might involve calling a view function on the Curve pool to estimate output.
uint256 expectedUsdcOut = ICurveFi_4(lusd_pool).get_dy_underlying(0, 2, _lusd); // (hypothetical function)
uint256 minUsdcOut = expectedUsdcOut.mul(9950).div(10000); // 0.5% slippage

ICurveFi_4(lusd_pool).exchange_underlying(0, 2, _lusd, minUsdcOut); // REMEDIATED
```
