# Vulnerability Report: Reentrancy Callback Bypass

**Vulnerability Category:** Reentrancy Callback Bypass Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
The `Registrar.transferRegistrars` function suffers from a reentrancy vulnerability due to an external call being made before the contract's internal state is fully updated. Specifically, the line `Registrar(registrar).acceptRegistrarTransfer(_hash, h.deed, h.registrationDate);` makes an external call to a potentially untrusted `newRegistrar` contract. The `_entries[_hash].deed` state, which represents the Deed contract associated with the name hash, is only cleared *after* this external call returns.

---

## 2. Theoretical Exploit Scenario
1. A legitimate owner of a name (`msg.sender`) calls `transferRegistrars(bytes32 _hash)` to transfer their name to a new `Registrar` contract (let's call it `MaliciousRegistrar`).
2. The `Registrar` contract performs its initial checks, calls `h.deed.setRegistrar(MaliciousRegistrar)`, and then executes the external call `MaliciousRegistrar.acceptRegistrarTransfer(_hash, h.deed, h.registrationDate)`.
3. The `MaliciousRegistrar` contract's `acceptRegistrarTransfer` function is designed to be malicious. Instead of simply accepting the transfer, it re-enters the `Registrar.transferRegistrars` function with the *same* `_hash`.
4. Upon re-entry, the `onlyOwner(_hash)` modifier in `Registrar.transferRegistrars` still passes, because `_entries[_hash].deed` has not yet been cleared by the initial call. `h.deed.owner()` still refers to the original `msg.sender` (the owner who initiated the transfer).
5. This leads to a recursive execution of `transferRegistrars`, where `MaliciousRegistrar.acceptRegistrarTransfer` is called repeatedly. Each recursive call consumes gas.
6. The recursive calls will quickly exhaust the transaction's gas limit, causing an out-of-gas error and reverting the entire transaction. This effectively creates a Denial of Service (DoS) for any name transfer initiated to the `MaliciousRegistrar`, preventing legitimate users from moving their names.

---

## 3. Remediation
Adhere to the Checks-Effects-Interactions (CEI) pattern. The internal state (`_entries[_hash]`) should be updated (e.g., by clearing `h.deed` or marking the transfer as pending/complete) *before* making any external calls.

```solidity
function transferRegistrars(bytes32 _hash) onlyOwner(_hash) {
    var registrar = ens.owner(rootNode);
    if(registrar == address(this))
        throw;

    entry h = _entries[_hash];
    
    // EFFECT: Update state BEFORE external call
    h.deed.setRegistrar(registrar); // This is an external call to the Deed contract, but controlled by Registrar.
                                    // It modifies the Deed's internal 'registrar' variable.
    // Clear the local entry BEFORE the call to the new registrar
    Deed tempDeed = h.deed; // Store deed reference for the call
    uint tempRegistrationDate = h.registrationDate;

    h.deed = Deed(0);
    h.registrationDate = 0;
    h.value = 0;
    h.highestBid = 0;

    // INTERACTION: Make the external call
    Registrar(registrar).acceptRegistrarTransfer(_hash, tempDeed, tempRegistrationDate);
}
```

---

[VULNERABILITY]: The `Deed.closeDeed` function, specifically the calculation `((1000 - refundRatio) * this.balance)/1000`, is vulnerable to an integer overflow. Given that the contract uses Solidity `^0.4.0`, arithmetic operations do not automatically revert on overflow; instead, they wrap around silently. If `this.balance` is sufficiently large, the intermediate multiplication `(1000 - refundRatio) * this.balance` can exceed `type(uint256).max`, causing it to wrap around to a much smaller value.

[EXPLOIT PATH]:
1. An attacker (or any user) bids on a name, funding the `Deed` contract with a large amount of Ether (e.g., `X` Wei) such that `1000 * X` (when `refundRatio` is near 0) would cause a `uint256` overflow.
2. When `Registrar.closeDeed(uint refundRatio)` is called (e.g., by the `Registrar` in a scenario like `unsealBid` or `cancelBid`), the calculation `(1000 - refundRatio) * this.balance` overflows and wraps around to a small `Y` value.
3. Consequently, `burn.send(Y)` sends only this small `Y` amount to the burn address, instead of the intended large amount.
4. Immediately after, `destroyDeed()` is called, which checks `if(owner.send(this.balance))`. Since only `Y` was sent to `burn`, the `this.balance` still contains nearly the original `X` amount.
5. The `owner.send(this.balance)` then sends the full, original `X` amount (or a very large portion of it) to the `Deed`'s owner (which can be the attacker). This results in a critical fund misdirection: funds intended to be burned are instead returned to the owner of the Deed.

[REMEDIATION]:
1.  **Upgrade Solidity Version**: Migrate the contract to Solidity `^0.8.0` or higher, where arithmetic operations revert on overflow/underflow by default.
2.  **Implement SafeMath**: For Solidity `0.4.0`, integrate and use a SafeMath library for all arithmetic operations to prevent silent overflows and underflows. For the specific calculation, ensure that `this.balance` is checked against `type(uint256).max / (1000 - refundRatio)` before multiplication.

```solidity
// Example with SafeMath (assuming SafeMath.mul and SafeMath.div are available)
import "openzeppelin-solidity/contracts/math/SafeMath.sol"; // If using OpenZeppelin or similar

contract Deed {
    using SafeMath for uint; // Or use it explicitly like SafeMath.mul(a,b)

    // ... existing code ...

    function closeDeed(uint refundRatio) onlyRegistrar onlyActive {
        active = false;
        // Ensure (1000 - refundRatio) * this.balance does not overflow
        // And then ensure division is safe.
        // If refundRatio is 0, the intended amount to burn is this.balance.
        // If refundRatio is 1000, the intended amount to burn is 0.
        uint amountToBurn = (1000).sub(refundRatio).mul(this.balance).div(1000);
        
        if (! burn.send(amountToBurn)) throw;
        DeedClosed();
        destroyDeed();
    }

    // ... existing code ...
}
```
