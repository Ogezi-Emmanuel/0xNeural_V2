# Vulnerability Report: Vesting Integer Truncation

**Vulnerability Category:** Vesting Integer Truncation Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
Permanent Loss of Vested Funds due to Integer Division Truncation
The `HundredVesting.getClaimableVest` function calculates the claimable amount using integer division, which can lead to a permanent loss of a portion of the vested tokens for the beneficiary. The calculation involves the term `user.totalAmount / numberOfEpochs`. If `user.totalAmount` is not perfectly divisible by `numberOfEpochs`, the remainder is truncated and effectively never accounted for in the vesting schedule.

This occurs in the line:
`uint256 amount = (block.timestamp - user.timestamp) / epochLength * user.totalAmount / numberOfEpochs;`

The specific issue lies in `user.totalAmount / numberOfEpochs`. This operation performs integer division, discarding any fractional part. For example, if `user.totalAmount` is 105 tokens and `numberOfEpochs` is 10, `user.totalAmount / numberOfEpochs` evaluates to 10 (due to integer division). The 5 remaining tokens (105 % 10) are effectively "lost" for the user, as the vesting schedule will only ever account for 10 tokens per epoch, summing up to 100 tokens over 10 epochs. These lost tokens remain locked in the `HundredVesting` contract and are unclaimable by the beneficiary. This constitutes a direct economic loss for the users.

---

## 2. Theoretical Exploit Scenario
No active exploit is required by an attacker. This is a passive loss of funds that affects any beneficiary whose `totalAmount` of vested tokens is not perfectly divisible by the `numberOfEpochs` defined for the vesting schedule. The user will simply find that they cannot claim the full amount they deposited for vesting, as a portion of their tokens will be permanently trapped in the contract.

Consider a scenario:
1. A user migrates PCT tokens via `PCTtoHundredMigrator`, which results in 105 HUNDRED tokens being transferred to `HundredVesting.beginVesting` for them.
2. The `HundredVesting` contract is configured such that its `numberOfEpochs` variable is 10 (e.g., `_epochLength = 1 day`, `totalVestingTime = 10 days`).
3. When the user calls `claimVested()`, the `getClaimableVest` function is invoked.
4. Inside `getClaimableVest`, the term `user.totalAmount / numberOfEpochs` evaluates to `105 / 10 = 10` (integer division).
5. Over the entire 10-epoch vesting period, the maximum claimable amount will be calculated as `10 * 10 = 100` HUNDRED tokens.
6. The remaining 5 HUNDRED tokens (`105 - 100`) from the original `user.totalAmount` are permanently locked in the `HundredVesting` contract, leading to a direct and irrecoverable economic loss for the user.

---

## 3. Remediation
The calculation for `amount` in `getClaimableVest` should be rewritten to preserve precision and avoid premature truncation. Instead of performing multiple divisions, calculate the total vested amount proportionally by multiplying before performing a single division by the total vesting duration.

Modify the `getClaimableVest` function in `contracts/HundredVesting.sol` as follows:

```solidity
function getClaimableVest(address beneficiary) public view returns(uint) {
    UserInfo memory user = addresses[beneficiary];
    require(user.timestamp != 0, "Invalid address");
    
    // Calculate the elapsed time since vesting began
    uint256 elapsedTime = block.timestamp - user.timestamp;
    
    // Calculate the total duration of the vesting period.
    // In the constructor, numberOfEpochs is derived from totalVestingTime / _epochLength.
    // Thus, totalVestingDuration = numberOfEpochs * epochLength.
    uint256 totalVestingDuration = numberOfEpochs * epochLength;

    // Prevent division by zero if totalVestingDuration is zero,
    // though ideally constructor parameters should prevent this.
    if (totalVestingDuration == 0) {
        return 0; 
    }

    // Calculate the claimable amount proportionally, multiplying before dividing to maintain precision.
    // This ensures the full user.totalAmount is accounted for over the entire vesting duration.
    uint256 claimableProportionally = user.totalAmount * elapsedTime / totalVestingDuration;
    
    return claimableProportionally < user.claimedAmount ? 0 : claimableProportionally - user.claimedAmount;
}
```
This revised calculation `user.totalAmount * elapsedTime / totalVestingDuration` ensures that the full `user.totalAmount` is distributed proportionally over the `totalVestingDuration`, preventing the loss of remainders due to multiple integer divisions.
