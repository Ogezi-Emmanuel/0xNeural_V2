# Vulnerability Report: Uniswap V4 Hook Reentrancy

**Vulnerability Category:** Uniswap V4 Hook Reentrancy Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
The `NFTStrategyHook` contract is vulnerable to a reentrancy attack due to an unprotected external call to a user-controlled contract within the `_afterSwap` hook.

The `NFTStrategyHook` contract inherits `ReentrancyGuard`, but its `internal override` hook functions (such as `_afterSwap`) do not apply the `nonReentrant` modifier. The `external` `afterSwap` function in `BaseHook` (which `NFTStrategyHook`'s `_afterSwap` implements) also does not use `nonReentrant`.

The `_afterSwap` function, after collecting fees from the Uniswap V4 PoolManager using `manager.take`, proceeds to call the `_processFees` internal function. Within `_processFees`, an external call is made to `INFTStrategy(collection).addFees{value: depositAmount}()`. The `collection` address is derived from `key.currency1`, which can be controlled by a user who sets up a Uniswap V4 pool using this hook.

If `INFTStrategy(collection)` is a malicious contract, it can implement a re-entrant `addFees` function. This allows the malicious contract to call back into `NFTStrategyHook` (or potentially the `PoolManager` to initiate another swap) while the original `_afterSwap` execution context is still active. Since no reentrancy guard is active, the attacker can repeatedly drain the ETH fees accumulated in the `NFTStrategyHook` contract's balance (from the `manager.take` call) before they are properly distributed to the `punkstrAmount` and `ownerAmount` recipients.

---

## 2. Theoretical Exploit Scenario
1.  **Setup Malicious Contract**: An attacker deploys a malicious smart contract, `MaliciousNFTStrategy`, that implements the `INFTStrategy` interface and has a re-entrant `addFees()` function. This `addFees()` function will attempt to re-enter the `NFTStrategyHook` contract or trigger another swap in the `PoolManager`.
2.  **Pool Creation**: The attacker creates a Uniswap V4 pool using the `NFTStrategyHook`, ensuring that `key.currency1` (which determines the `collection` address for fee distribution) points to their `MaliciousNFTStrategy` contract. This is a standard interaction as the hook is designed to work with `INFTStrategy` contracts.
3.  **Initiate Swap**: The attacker initiates a swap on this newly created pool. The swap parameters are chosen such that `key.currency1` is the `feeCurrency`, ensuring that ETH fees are collected and routed to the `MaliciousNFTStrategy`. This triggers the `NFTStrategyHook._afterSwap` function via the `PoolManager`.
4.  **Fee Collection by Hook**: Inside `_afterSwap`, the `manager.take(feeCurrency, address(this), feeAmount);` call successfully transfers the calculated swap fees (in ETH) from the `PoolManager` to the `NFTStrategyHook` contract's address. At this point, the `NFTStrategyHook` contract holds the collected fees.
5.  **Reentrancy**: The `_afterSwap` function then calls `_processFees`, which in turn calls `MaliciousNFTStrategy(collection).addFees{value: depositAmount}()`.
6.  **Drainage**: Upon receiving the ETH via `addFees()`, `MaliciousNFTStrategy` immediately executes its re-entrant logic. It can call back into the `NFTStrategyHook` contract to trigger another `_afterSwap` or exploit other logic, or interact with the `PoolManager` to initiate another swap. Since the `NFTStrategyHook`'s call to `MaliciousNFTStrategy.addFees()` is not protected by a `nonReentrant` modifier, the re-entrant call succeeds. The attacker can repeatedly drain the ETH held by `NFTStrategyHook` (which was just collected from `manager.take`) before the contract finishes its current fee distribution logic.

---

## 3. Remediation
The `nonReentrant` modifier from `ReentrancyGuard` should be applied to the `external` functions in `BaseHook` that delegate to the `_internal virtual` hook implementations and make external calls. Specifically, the `afterSwap` external function in `BaseHook` must be protected.

Modify `BaseHook.sol` as follows:

```solidity
// File: lib/v4-periphery/src/utils/BaseHook.sol
// ... (imports and other code) ...

abstract contract BaseHook is IHooks, ImmutableState {
    error HookNotImplemented();

    constructor(IPoolManager _manager) ImmutableState(_manager) {
        validateHookAddress(this);
    }

    // ... (getHookPermissions, validateHookAddress, and other _beforeX, _afterX stubs) ...

    /// @inheritdoc IHooks
    function afterSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata params,
        BalanceDelta delta,
        bytes calldata hookData
    ) external onlyPoolManager nonReentrant /* ADD THIS MODIFIER */ returns (bytes4, int128) {
        return _afterSwap(sender, key, params, delta, hookData);
    }

    function _afterSwap(address, PoolKey calldata, SwapParams calldata, BalanceDelta, bytes calldata)
        internal
        virtual
        returns (bytes4, int128)
    {
        revert HookNotImplemented();
    }

    // ... (rest of the contract) ...
}
```
