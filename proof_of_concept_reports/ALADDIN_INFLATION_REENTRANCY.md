# Vulnerability Report: Aladdin Inflation Reentrancy

**Vulnerability Category:** Aladdin Inflation Reentrancy Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
The `distribute()` function is vulnerable to an economic reentrancy attack, allowing an approved `staking` contract to mint exponentially increasing rewards.

The `distribute()` function calculates the `_reward` amount based on `IERC20(ald).totalSupply()` *before* making an external call to `ITreasury(treasury).mintRewards(staking, _reward)`. The `staking` address is the same as `msg.sender` (the caller of `distribute()`).

If the `staking` address is a smart contract, it can be designed to reenter the `distribute()` function. Upon receiving the ALD tokens from the `treasury` via `mintRewards`, the `staking` contract's fallback, receive, or a token-receiving hook (e.g., `onERC20Received`) could be triggered. If this triggered function then calls `distribute()` again:
1. The first `distribute()` call calculates `_reward_1` based on the initial `ald.totalSupply()`.
2. It calls `ITreasury(treasury).mintRewards(staking, _reward_1)`.
3. The `treasury` mints `_reward_1` ALD tokens to `staking`, which increases the global `ald.totalSupply()`.
4. The `staking` contract immediately reenters `distribute()`.
5. The second `distribute()` call calculates `_reward_2`. Since `ald.totalSupply()` has already increased by `_reward_1`, `_reward_2` will be greater than `_reward_1`.
6. This process can be repeated, leading to an exponential increase in minted ALD rewards for the `staking` contract.

While the `staking` address is `immutable` and set in the constructor (implying a trusted partner), any contract interaction where an external call modifies a state variable that is subsequently read in the same transaction context, and the caller can reenter, is a reentrancy vulnerability. It assumes the `staking` contract is not only trusted but also free from any reentrancy vulnerabilities itself or malicious intent, which is a dangerous assumption in smart contract design. The `Distributor` contract itself does not enforce the Checks-Effects-Interactions pattern for this function.

---

## 2. Theoretical Exploit Scenario
1.  An attacker deploys a malicious `Staking` contract. This contract must have a fallback/receive function or a token-receiving hook that, when called by the `ITreasury` (upon receiving ALD tokens), immediately calls `distributor.distribute()` again.
2.  (Prerequisite, not part of the exploit by an unprivileged attacker): The `Distributor` contract must have been deployed with the malicious `Staking` contract address as its `immutable staking` parameter. If this is not the case, this specific exploit requires compromising the `staking` contract first. Assuming the `staking` contract is *potentially* exploitable by an unprivileged attacker to reenter, or was deployed maliciously, the vulnerability exists in `Distributor`.
3.  The malicious `Staking` contract calls `distributor.distribute()`.
4.  `distribute()` calculates `_reward_1 = IERC20(ald).totalSupply().mul(rewardRate).div(PRECISION)`.
5.  `distribute()` calls `ITreasury(treasury).mintRewards(staking, _reward_1)`.
6.  The `ITreasury` contract mints `_reward_1` ALD to the malicious `Staking` contract. This increases `ald.totalSupply()`.
7.  The malicious `Staking` contract's reentrant logic is triggered (e.g., via its fallback function receiving the ALD tokens).
8.  The malicious `Staking` contract immediately calls `distributor.distribute()` again within the same transaction.
9.  The second call to `distribute()` calculates `_reward_2 = IERC20(ald).totalSupply().mul(rewardRate).div(PRECISION)`. Since `ald.totalSupply()` now includes `_reward_1`, `_reward_2` will be greater than `_reward_1`.
10. This loop continues, allowing the malicious `Staking` contract to receive an exponentially increasing amount of ALD rewards, potentially draining the `treasury` or inflating the token supply to a critical degree.

---

## 3. Remediation
Implement a reentrancy guard for the `distribute()` function. The simplest way is to use OpenZeppelin's `ReentrancyGuard` by inheriting it and adding the `nonReentrant` modifier to the `distribute` function.

```solidity
// Add this import
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

// Modify contract declaration
contract Distributor is Ownable, IDistributor, ReentrancyGuard {
    // ... existing code ...

    /// @dev distribute ALD reward to Aladdin Staking contract.
    function distribute() external override nonReentrant { // Add nonReentrant modifier
        require(msg.sender == staking, "Distributor: not approved");

        uint256 _reward = nextRewardAt(rewardRate);
        ITreasury(treasury).mintRewards(staking, _reward);
    }

    // ... existing code ...
}
```
