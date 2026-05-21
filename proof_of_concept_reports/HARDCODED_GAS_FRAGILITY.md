# Vulnerability Report: Hardcoded Gas Fragility

**Vulnerability Category:** Hardcoded Gas Fragility Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
**Hardcoded and Immutable Gas Cost (`RECEIVE_COST`) leads to potential Cross-Chain Messaging Denial of Service (DoS) and incorrect estimations.**

The `WormholeAdapter` contract defines `RECEIVE_COST = 70_000` as a `uint256 public constant`. This constant is intended to cover the gas consumed by the `receiveWormholeMessages()` function on the destination chain, *excluding* the gas used by the `entrypoint.handle()` call. This `RECEIVE_COST` is critically added to the `gasLimit` parameter when:
1.  Estimating the cost of sending a message via `estimate()`: `relayer.quoteEVMDeliveryPrice(destination.wormholeId, 0, gasLimit + RECEIVE_COST)`
2.  Sending the actual payload via `send()`: `relayer.sendPayloadToEvm{value: msg.value}(..., gasLimit + RECEIVE_COST, ...)`

The core logic flaw is that EVM opcode gas costs are not static; they can and do change over time due to network upgrades (e.g., EIP-1559, Istanbul, London, Berlin). If the actual gas cost of executing the `receiveWormholeMessages()` function's internal logic (the part `RECEIVE_COST` is supposed to cover) increases, the hardcoded `RECEIVE_COST` will become insufficient. Since `RECEIVE_COST` is a `constant`, it cannot be updated without redeploying the contract, making the system highly fragile.

This vulnerability can lead to:
*   **Critical Denial of Service (DoS):** If the `RECEIVE_COST` becomes too low, all incoming cross-chain messages will fail due to out-of-gas errors on the destination chain, effectively halting the bridge's core functionality.
*   **Economic Loss:** If the `RECEIVE_COST` becomes too high, users will consistently overpay for message delivery, leading to unnecessary transaction costs.

---

## 2. Theoretical Exploit Scenario
1.  A future Ethereum (or any EVM-compatible chain where this adapter is deployed) network upgrade alters the gas costs of opcodes used within the `WormholeAdapter.receiveWormholeMessages()` function's logic that executes prior to calling `entrypoint.handle()`. Examples include `sload`, `mload`, `mstore`, `calldataload`, `require` checks, or `abi.decode` operations.
2.  The actual gas required for this segment of code surpasses the hardcoded `RECEIVE_COST` of 70,000 gas.
3.  When the `entrypoint` contract (or any entity using the `send` function) attempts to send a cross-chain message, the `gasLimit` provided to the `relayer.sendPayloadToEvm` will include the now-insufficient `RECEIVE_COST`.
4.  On the destination chain, the Wormhole Relayer attempts to execute `WormholeAdapter.receiveWormholeMessages()`. However, the transaction runs out of gas during the adapter's initial processing (e.g., `require` checks, `CastLib` conversions, or `sources` mapping lookups) before reaching `entrypoint.handle()`.
5.  All cross-chain message deliveries through this adapter will consequently revert, leading to a complete Denial of Service for the bridge. This would prevent the system from processing any incoming cross-chain commands, potentially leading to frozen assets or state inconsistencies across chains.

---

## 3. Remediation
1.  **Make `RECEIVE_COST` configurable:** Change `RECEIVE_COST` from a `public constant` to a `public` state variable. Implement an `auth` protected function (e.g., `setReceiveCost(uint256 newCost)`) to allow the authorized administrator to update this value as needed. This enables the contract to adapt to future changes in EVM gas costs without requiring a full redeployment (assuming the contract is upgradeable or can be replaced).
2.  **Add robust monitoring:** Implement off-chain monitoring systems to continuously track the actual gas consumption of the `receiveWormholeMessages` function (specifically the part covered by `RECEIVE_COST`). This would alert administrators if the configured `RECEIVE_COST` deviates significantly from the actual required gas, enabling timely adjustments.
3.  **Consider dynamic gas estimation:** Explore if the `Wormhole Relayer` provides any mechanisms to dynamically estimate the gas cost for the *receiving* adapter's logic, rather than relying on a hardcoded value.
