# Vulnerability Report: Implicit Access Control Redeem Dos

**Vulnerability Category:** Implicit Access Control Redeem Dos Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
Unrestricted Parameter Modification Leading to Denial of Service (DoS) and Fund Lock
The `AlephVaultRedeem` contract exposes several `external` functions (`queueNoticePeriod`, `queueLockInPeriod`, `queueMinRedeemAmount`, `setNoticePeriod`, `setLockInPeriod`, `setMinRedeemAmount`) that allow *any* external caller to queue and subsequently set critical redemption-related parameters for any `classId`. These parameters directly control user redemption conditions: `noticePeriod` (delay before redemption), `lockInPeriod` (period during which redemptions are disallowed), and `minRedeemAmount` (minimum amount required for a redemption request).

Crucially, there are no access control mechanisms (e.g., `onlyOwner`, `onlyManager`, or role-based access control) applied to these functions within the `AlephVaultRedeem` contract or its `AlephVaultBase` parent. This means an unprivileged external attacker can call these functions.

This vulnerability allows an attacker to manipulate the vault's redemption policies to extreme values, effectively denying legitimate users the ability to redeem their funds or forcing them into highly unfavorable conditions, leading to a denial-of-service or fund lock.

---

## 2. Theoretical Exploit Scenario
An unprivileged attacker can execute the following steps to lock users' funds:
1.  **Queue Malicious Parameters:** The attacker calls `queueMinRedeemAmount(classId, type(uint256).max)` for a target `classId`. This queues a change to set the minimum redeemable amount to the maximum possible `uint256` value, effectively making it impossible for any legitimate user to meet this threshold.
2.  **Wait for Timelock:** The attacker waits for the `MIN_REDEEM_AMOUNT_TIMELOCK` period (defined in the constructor) to expire. This is a fixed, publicly known duration.
3.  **Activate Malicious Parameters:** Once the timelock expires, the attacker calls `setMinRedeemAmount(classId)`. This activates the queued change, updating `_sd.shareClasses[classId].shareClassParams.minRedeemAmount` to `type(uint256).max`.
4.  **Fund Lock / Denial of Service:** From this point forward, any user attempting to call `requestRedeem` or `syncRedeem` for that `classId` will find that their `_redeemRequestParams.estAmountToRedeem` is less than `_shareClassParams.minRedeemAmount` (unless they literally hold `type(uint256).max` assets, which is impossible). The transaction will revert with `RedeemLessThanMinRedeemAmount`, effectively preventing all redemptions for that class and locking user funds indefinitely.

Similar attacks can be performed using `queueLockInPeriod` to set an astronomically long lock-in period, or `queueNoticePeriod` to impose an indefinite notice period, causing a soft lock of funds by delaying redemptions beyond any practical timeframe.

---

## 3. Remediation
Implement robust access control for all sensitive `external` functions (`queueNoticePeriod`, `queueLockInPeriod`, `queueMinRedeemAmount`, `setNoticePeriod`, `setLockInPeriod`, `setMinRedeemAmount`). These functions should only be callable by a designated privileged role (e.g., `MANAGER`, `OPERATIONS_MULTISIG`) which itself is protected by appropriate governance mechanisms and multisig. This access control should be enforced either directly in the `AlephVaultRedeem` contract using a modifier (e.g., `onlyManager`) or in the central `AlephVault` contract that delegates calls to this module.

Example of proposed code change (assuming an `onlyManager` modifier from an `Ownable` or `AccessControl` pattern in `AlephVaultBase` or a higher-level vault contract):

```solidity
contract AlephVaultRedeem is IAlephVaultRedeem, AlephVaultBase {
    // ... existing code ...

    // Assume an 'onlyManager' modifier is available and properly restricts access
    // This modifier would need to be defined in AlephVaultBase or imported.

    function queueNoticePeriod(uint8 _classId, uint48 _noticePeriod) external onlyManager { // ADD onlyManager
        _queueNoticePeriod(_getStorage(), _classId, _noticePeriod);
    }

    function queueLockInPeriod(uint8 _classId, uint48 _lockInPeriod) external onlyManager { // ADD onlyManager
        _queueLockInPeriod(_getStorage(), _classId, _lockInPeriod);
    }

    function queueMinRedeemAmount(uint8 _classId, uint256 _minRedeemAmount) external onlyManager { // ADD onlyManager
        // ... existing _minRedeemAmount == 0 check ...
        _queueMinRedeemAmount(_getStorage(), _classId, _minRedeemAmount);
    }

    function setNoticePeriod(uint8 _classId) external onlyManager { // ADD onlyManager
        _setNoticePeriod(_getStorage(), _classId);
    }

    function setLockInPeriod(uint8 _classId) external onlyManager { // ADD onlyManager
        _setLockInPeriod(_getStorage(), _classId);
    }

    function setMinRedeemAmount(uint8 _classId) external onlyManager { // ADD onlyManager
        _setMinRedeemAmount(_getStorage(), _classId);
    }
}
```
