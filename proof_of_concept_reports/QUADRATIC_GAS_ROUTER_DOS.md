# Vulnerability Report: Quadratic Gas Router Dos

**Vulnerability Category:** Quadratic Gas Router Dos Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
The `LombardBtcDecoderAndSanitizer` contract, through its inherited `UniswapV3DecoderAndSanitizer`, `BalancerV2DecoderAndSanitizer`, `PendleRouterDecoderAndSanitizer`, `MerklDecoderAndSanitizer`, `EigenLayerLSTStakingDecoderAndSanitizer`, and `CCIPDecoderAndSanitizer` (among others), contains functions that iterate over user-supplied `calldata` arrays and repeatedly use `abi.encodePacked` to build a dynamic `bytes memory` variable. This pattern results in a quadratic increase in gas consumption relative to the input array's length.

Specifically, in functions like `UniswapV3DecoderAndSanitizer.exactInput`, the `params.path` length (a user-controlled calldata input) directly dictates the number of iterations and the size of the `addressesFound` variable being built. Each `abi.encodePacked` operation on a growing dynamic array `addressesFound` involves memory reallocations and data copying, leading to a computational complexity of O(N^2), where N is the number of addresses or elements being packed.

An attacker can exploit this by providing a large `calldata` array, causing the function to consume an excessive amount of gas, thereby leading to a denial of service (DoS). This can either exhaust the block gas limit, causing the transaction to revert, or make the transaction prohibitively expensive, preventing legitimate users or automated systems from processing inputs via this decoder. Since this decoder is designed to process transaction data for various protocols, a successful DoS against it could impact critical downstream operations.

---

## 2. Theoretical Exploit Scenario
1.  An attacker prepares a malicious transaction targeting a function in the `LombardBtcDecoderAndSanitizer` contract, for instance, the `exactInput` function (inherited from `UniswapV3DecoderAndSanitizer`).
2.  The attacker crafts the `params.path` parameter to contain an extremely long sequence of token addresses and fees (e.g., thousands of address-fee pairs).
3.  When this transaction is processed by the `exactInput` function, the internal loop that iterates over `params.path` and concatenates addresses using `abi.encodePacked` will trigger excessive gas consumption due to its quadratic complexity.
4.  The transaction will either revert (if it hits the block gas limit) or consume a very high amount of gas, making the operation economically unfeasible or causing the system that relies on this decoder to fail.
5.  This effectively denies service to any entity attempting to use this decoder with legitimate or even other (non-maliciously oversized) inputs, as the processing becomes unreliable or too expensive.

This attack vector can be replicated across multiple inherited decoder functions exhibiting the same pattern, including but not limited to:
*   `UniswapV3DecoderAndSanitizer.exactInput`: `params.path`
*   `BalancerV2DecoderAndSanitizer.flashLoan`: `tokens` array
*   `BalancerV2DecoderAndSanitizer.joinPool` / `exitPool`: `req.assets` array
*   `PendleRouterDecoderAndSanitizer.redeemDueInterestAndRewards`: `sys`, `yts`, `markets` arrays
*   `PendleRouterDecoderAndSanitizer.fill`: `params` array (and nested `normalFills`, `flashFills` in `_sanitizeLimitOrderData`)
*   `MerklDecoderAndSanitizer.claim`: `users`, `tokens` arrays
*   `EigenLayerLSTStakingDecoderAndSanitizer.queueWithdrawals`: `queuedWithdrawalParams` array and nested `strategies`
*   `EigenLayerLSTStakingDecoderAndSanitizer.completeQueuedWithdrawals`: `withdrawals` array and nested `strategies`, `tokens`
*   `CCIPDecoderAndSanitizer.ccipSend`: `message.tokenAmounts` array

---

## 3. Remediation
To mitigate this Denial of Service vulnerability, it is crucial to implement explicit upper bounds on the lengths of all user-controlled calldata arrays that are processed in loops involving dynamic memory allocations (like `abi.encodePacked`).

For each vulnerable function, add a `require` statement at the beginning of the function to check the length of the input array against a carefully chosen maximum limit. This limit should be determined based on acceptable gas costs and the practical requirements of the protocols being decoded.

Example for `UniswapV3DecoderAndSanitizer.exactInput`:

```solidity
// File: src/base/DecodersAndSanitizers/Protocols/UniswapV3DecoderAndSanitizer.sol
// ...
contract UniswapV3DecoderAndSanitizer {
    // ...
    // Define a reasonable maximum number of addresses to prevent DoS.
    // Assuming a chunk size of 23 bytes (20 for address, 3 for fee) and 1 address at the start,
    // a path of 20 addresses would be 20 * 23 + 20 (for the last address) = 480 bytes.
    // A path of 100 addresses would be 100 * 23 + 20 = 2320 bytes.
    // Choose MAX_PATH_ADDRESSES based on acceptable gas limits.
    uint256 internal constant MAX_PATH_ADDRESSES = 20; // Example, adjust as needed

    function exactInput(DecoderCustomTypes.ExactInputParams calldata params)
        external
        pure
        virtual
        returns (bytes memory addressesFound)
    {
        uint256 chunkSize = 23; 
        uint256 pathLength = params.path.length;
        if (pathLength % chunkSize != 20) revert UniswapV3DecoderAndSanitizer__BadPathFormat();
        
        uint256 pathAddressCount = 1 + (pathLength / chunkSize);

        // Remediation: Add a length check for the input path
        require(pathAddressCount <= MAX_PATH_ADDRESSES, "UniswapV3DecoderAndSanitizer: Path too long");

        uint256 pathIndex;
        for (uint256 i; i < pathAddressCount; ++i) {
            addressesFound = abi.encodePacked(addressesFound, params.path[pathIndex:pathIndex + 20]);
            pathIndex += chunkSize;
        }
        addressesFound = abi.encodePacked(addressesFound, params.recipient);
    }
    // ...
}
```

Apply similar `MAX_ARRAY_LENGTH` checks to all other identified functions that iterate over unbounded calldata arrays and perform gas-intensive operations like `abi.encodePacked` within those loops. The `MAX_ARRAY_LENGTH` value should be a constant that fits the business logic constraints and ensures transaction execution remains within acceptable gas limits.
