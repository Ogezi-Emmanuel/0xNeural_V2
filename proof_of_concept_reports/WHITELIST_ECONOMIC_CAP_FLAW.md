# Vulnerability Report: Whitelist Economic Cap Flaw

**Vulnerability Category:** Whitelist Economic Cap Flaw Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
The `MoreVaultsLib._setDepositWhitelist` function contains a logical error in how it updates the `availableToDeposit` for existing users when their `initialDepositCapPerUser` is changed (either increased or decreased). This flaw can allow users to bypass their intended deposit limits, leading to an economic vulnerability where they can deposit more assets than permitted.

The logic in question is:
```solidity
            // If the user already existed (initialDepositCapPerUser was set previously)
            if (previousInitialCap > 0) {
                // Preserve the current availableToDeposit value, but cap it to the new initialDepositCapPerUser
                // if it exceeds the new limit
                uint256 currentAvailableToDeposit = ds.availableToDeposit[depositors[i]];
                if (currentAvailableToDeposit > underlyingAssetCaps[i]) {
                    ds.availableToDeposit[depositors[i]] = underlyingAssetCaps[i]; // Flawed
                } else if (underlyingAssetCaps[i] > previousInitialCap) {
                    ds.availableToDeposit[depositors[i]] += underlyingAssetCaps[i] - previousInitialCap; // Flawed
                }
            } else {
                // If the user is new, set both values to be equal
                ds.availableToDeposit[depositors[i]] = underlyingAssetCaps[i];
            }
```
The `initialDepositCapPerUser` defines a user's total allowed deposit. The `availableToDeposit` tracks how much *more* a user can deposit. The amount a user has *already deposited* is `previousInitialCap - currentAvailableToDeposit`.

When the `underlyingAssetCaps[i]` (new total cap) is less than `previousInitialCap` (old total cap):
The code sets `ds.availableToDeposit[depositors[i]] = underlyingAssetCaps[i];`. This is incorrect. If a user had already deposited some amount, the `availableToDeposit` should be `newCap - alreadyDepositedAmount`. By setting `availableToDeposit` directly to `newCap`, it allows the user to deposit `newCap` more, effectively enabling `alreadyDepositedAmount + newCap` total deposits, which exceeds `newCap`.

When the `underlyingAssetCaps[i]` (new total cap) is greater than `previousInitialCap` (old total cap):
The code adds `underlyingAssetCaps[i] - previousInitialCap` to `availableToDeposit`. This logic correctly calculates the *increase* in available deposit capacity if `availableToDeposit` implicitly tracks the remaining capacity. For example, if a user had deposited 20 out of 100 (leaving 80 available), and the cap is increased to 200, the available should become 180 (200 - 20). The calculation `80 + (200 - 100) = 80 + 100 = 180` is correct here. However, the first `if` branch for reduced caps is still problematic.

The flaw lies in the `currentAvailableToDeposit > underlyingAssetCaps[i]` branch, where it should be `newCap - already_deposited_amount`.

---

## 2. Theoretical Exploit Scenario
1.  An owner sets `initialDepositCapPerUser[Attacker] = 100` and `availableToDeposit[Attacker] = 100`.
2.  Attacker deposits `20` tokens. `availableToDeposit[Attacker]` becomes `80`.
3.  Owner, for some reason, decides to reduce the attacker's total cap to `50` via `_setDepositWhitelist([Attacker], [50])`.
4.  Inside `_setDepositWhitelist`:
    *   `previousInitialCap = 100`.
    *   `currentAvailableToDeposit = 80`.
    *   `underlyingAssetCaps[i] = 50`.
    *   The condition `currentAvailableToDeposit (80) > underlyingAssetCaps[i] (50)` is true.
    *   The code executes `ds.availableToDeposit[depositors[i]] = underlyingAssetCaps[i];`.
    *   So, `availableToDeposit[Attacker]` becomes `50`.
5.  Attacker can now deposit `50` more tokens.
6.  Total deposited by Attacker: `20` (initial) + `50` (new deposit) = `70`.
7.  The new cap was `50`. The attacker has deposited `70`, exceeding the cap by `20`.

---

## 3. Remediation
The logic for updating `availableToDeposit` should consistently reflect the remaining capacity relative to the *new* `initialDepositCapPerUser` (total cap), taking into account the amount already deposited.

The `_setDepositWhitelist` function should be modified as follows:

```solidity
    function _setDepositWhitelist(address[] calldata depositors, uint256[] calldata underlyingAssetCaps) internal {
        MoreVaultsStorage storage ds = moreVaultsStorage();
        for (uint256 i; i < depositors.length;) {
            uint256 newCap = underlyingAssetCaps[i];
            uint256 previousInitialCap = ds.initialDepositCapPerUser[depositors[i]];
            uint256 depositedAmount = 0;

            if (previousInitialCap > 0) {
                // Calculate actual amount deposited by the user based on previous cap
                depositedAmount = previousInitialCap - ds.availableToDeposit[depositors[i]];
            }

            // Update initialDepositCapPerUser to the new value
            ds.initialDepositCapPerUser[depositors[i]] = newCap;

            // Calculate the new availableToDeposit based on the new cap and already deposited amount
            if (newCap >= depositedAmount) {
                ds.availableToDeposit[depositors[i]] = newCap - depositedAmount;
            } else {
                // If newCap < depositedAmount, it means the user has deposited more than the new cap allows.
                // This scenario might imply a different error or a design choice to allow over-deposits
                // to remain but prevent further deposits. For now, set available to 0.
                ds.availableToDeposit[depositors[i]] = 0;
            }

            unchecked {
                ++i;
            }
        }
    }
```

---

[VULNERABILITY]: The `MoreVaultsLib.removeFunction` internal function, which is called by `diamondCut` to remove selectors and potentially facets, contains a critical logical flaw that prevents any facet from being removed from the diamond.
The problematic line is:
```solidity
        if (_facetAddress != address(0)) {
            revert ZeroAddress();
        }
```
This check is intended to catch `address(0)` as a facet address, but the condition `_facetAddress != address(0)` means that if `_facetAddress` is *any valid non-zero address* (which it always will be when attempting to remove a legitimate facet), the function will revert with `ZeroAddress()`. This makes it impossible to remove any existing facet or its functions, effectively causing a permanent denial of service for diamond upgrades and maintenance.

[EXPLOIT PATH]:
1.  An owner attempts to upgrade the `MoreVaultsDiamond` by removing an old facet or certain functions from a facet using `diamondCut`.
2.  The `diamondCut` function calls `MoreVaultsLib.removeFunctions` internally.
3.  `MoreVaultsLib.removeFunctions` iterates through the provided selectors and calls `removeFunction` for each, passing the `_facetAddress` associated with the selector.
4.  Inside `removeFunction`, the check `if (_facetAddress != address(0)) { revert ZeroAddress(); }` is encountered.
5.  Since `_facetAddress` is a valid, non-zero address (e.g., `0x...deadbeef`), the condition `_facetAddress != address(0)` evaluates to `true`.
6.  The transaction reverts with `ZeroAddress()`, preventing the facet or its functions from being removed. This permanently blocks the ability to remove functions or entire facets from the diamond, hindering future upgrades, bug fixes, or functionality removal.

[REMEDIATION]:
The erroneous conditional check in `MoreVaultsLib.removeFunction` must be inverted to correctly identify and reject `address(0)` while allowing valid facet addresses:

```solidity
    function removeFunction(MoreVaultsStorage storage ds, address _facetAddress, bytes4 _selector, bool _isReplacing)
        internal
    {
        // Corrected logic: Revert if _facetAddress IS address(0)
        if (_facetAddress == address(0)) {
            revert ZeroAddress();
        }
        // ... rest of the function remains the same ...
    }
```
Alternatively, since the `_facetAddress` is derived from `ds.selectorToFacetAndPosition[_selector].facetAddress` which should never be `address(0)` for an existing selector, this check might even be redundant if the `FunctionDoesNotExist()` error (for `_facetAddress == address(0)`) is expected to cover this case. However, a specific check for `address(0)` as a facet being explicitly passed is generally good practice. Given `_facetAddress` is sourced from storage, if a selector points to `address(0)`, `FunctionDoesNotExist()` will already be triggered earlier. If `_facetAddress` were an input parameter, the check would be more appropriate. For clarity, inverting the check is the most direct fix to the current code logic.

---

[VULNERABILITY]: The `VaultsFactory.pauseFacet` function is susceptible to a denial of service (DoS) attack due to an unbounded loop. This function allows the owner to pause all vaults that are currently linked to a specific facet.
The implementation fetches all linked vaults for a given facet using `_linkedVaults[_facet].values()`, which returns an array of all vault addresses. It then iterates through this array, performing an external call to `IVaultFacet(vaults[i]).pause()` for each vault.

If a popular or foundational facet is linked to a very large number of vaults, the `vaults` array can grow arbitrarily large. Iterating over such an array and making external calls for each element will consume a proportional amount of gas. Eventually, the transaction cost will exceed the block gas limit, making it impossible to call `pauseFacet` for that specific facet. This prevents a critical emergency function from being executed, which could be necessary to halt operations if a vulnerability is discovered in the linked facet, leading to a broader system-wide DoS.

[EXPLOIT PATH]:
1.  A malicious actor (or even many legitimate users over time) links an excessive number of `MoreVaultsDiamond` instances (vaults) to a specific facet by deploying many vaults that include this facet or by directly calling the `VaultsFactory.link` function from their deployed vaults.
2.  The number of linked vaults to this facet grows to a point where `_linkedVaults[_facet].values().length` becomes very large (e.g., thousands or tens of thousands).
3.  If an emergency situation arises requiring the owner to pause all vaults using this facet (e.g., a vulnerability is found in the facet code), the owner calls `VaultsFactory.pauseFacet(_facet)`.
4.  The transaction attempts to iterate through the `vaults` array and call `pause()` on each, consuming a large amount of gas.
5.  Due to the excessive number of iterations and external calls, the transaction runs out of gas, or hits the block gas limit, and reverts.
6.  The owner is unable to pause the vulnerable facet, leaving all linked vaults exposed and vulnerable to exploitation, thereby causing a denial of service to the system's emergency response mechanism.

[REMEDIATION]:
To mitigate the unbounded loop DoS in `pauseFacet`, consider the following strategies:

1.  **Batching Mechanism:** Implement a batching mechanism that allows the owner to pause vaults in smaller, manageable chunks. Instead of pausing all vaults in a single transaction, provide a function that takes an array of vault addresses or a starting/ending index to process a subset of vaults. This shifts the gas cost to multiple transactions, making the operation callable.
    ```solidity
    // Example Batching Function
    function pauseFacetsInBatch(address _facet, address[] calldata _vaultsToPause) external onlyOwner {
        _setFacetRestricted(_facet, true); // Set restricted once
        for (uint256 i = 0; i < _vaultsToPause.length;) {
            try IVaultFacet(_vaultsToPause[i]).pause() {}
            catch (bytes memory) {
                emit VaultFailedToPause(_vaultsToPause[i]);
            }
            unchecked {
                ++i;
            }
        }
        // Emit an event to indicate progress or completion
        emit FacetsPausedInBatch(_facet, _vaultsToPause);
    }
    ```
    This would require the owner to query `getLinkedVaults(_facet)` off-chain, split the list, and call the batch function multiple times.

2.  **Event-Driven Off-chain Worker:** Instead of on-chain iteration, the `_setFacetRestricted` function could emit an event (e.g., `FacetRestricted(address facet, bool isRestricted)`). An off-chain worker would listen for this event, fetch all linked vaults, and then send individual transactions to pause each vault. This decentralizes the execution and avoids on-chain gas limits for a single call. This requires a trusted off-chain component.

3.  **Refactor `_linkedVaults`:** If the primary use case of `_linkedVaults` is for `pauseFacet`, consider if a direct `AddressSet` is the most efficient storage. However, given the current diamond design where individual vaults link themselves, it's hard to avoid a list of linked vaults without a full re-architecture. The batching solution is generally preferred in such cases.

The current implementation implicitly assumes that `_linkedVaults[_facet].values().length` will always be small enough to fit within a single transaction's gas limit. This is a dangerous assumption for a factory that deploys potentially many vaults.
