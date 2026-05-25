# Vulnerability Report: Delegatecall Approval Drain

**Vulnerability Category:** Delegatecall Approval Drain Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
**Arbitrary Token Drain via Malicious vlFeeDistributor in `depositRewards`**

The `depositRewards` function in `RouterModuleVLSDT` allows an attacker to drain arbitrary ERC20 tokens from the router contract's balance. This function is intended to facilitate depositing rewards into `vlFeeDistributors` by first transferring tokens to the router (via a preceding `transferFromPermit2` call in a composed transaction) and then having the router approve and deposit them.

The vulnerability arises because:
1.  The `vlFeeDistributors` array is passed directly from `calldata`, meaning an attacker can supply the address of a malicious contract.
2.  The `REWARD_TOKEN()` address for approval is dynamically fetched by calling `IVlFeeDistributor(vlFeeDistributors[i]).REWARD_TOKEN()`. A malicious contract at `vlFeeDistributors[i]` can implement `REWARD_TOKEN()` to return the address of *any* ERC20 token (e.g., WETH, USDC, SDT) that the router might hold.
3.  The router (acting as `address(this)` due to the `onlyDelegateCall` modifier) then calls `token.approve(vlFeeDistributors[i], amounts[i])` for this arbitrary token to the malicious `vlFeeDistributor` address.
4.  Immediately after, `IVlFeeDistributor(vlFeeDistributors[i]).deposit(amounts[i])` is called. The malicious contract's `deposit` function can then execute `IERC20(REWARD_TOKEN_ADDRESS).transferFrom(ROUTER_ADDRESS, ATTACKER_ADDRESS, amounts[i])`, effectively stealing the approved tokens from the router.

This leads to a critical state manipulation vulnerability, as the router's temporary token balances (intended for legitimate operations) can be hijacked.

---

## 2. Theoretical Exploit Scenario
1.  An attacker prepares a malicious `AttackFeeDistributor` contract. This contract implements `REWARD_TOKEN()` to return the address of a valuable ERC20 token (e.g., USDC, WETH) that the router is expected to hold during a composed transaction. It also implements `deposit(uint256 amount)` to call `IERC20(REWARD_TOKEN_ADDRESS).transferFrom(msg.sender, ATTACKER_ADDRESS, amount)`.
2.  The attacker initiates a composed transaction via the main router contract that `delegatecall`s `RouterModuleVLSDT`.
3.  The composed transaction first transfers a valuable token (e.g., 100 USDC) to the router using a module like `RouterModuleERC20Manager.transferFromPermit2`.
4.  In the same composed transaction, the attacker then calls `RouterModuleVLSDT.depositRewards` with `vlFeeDistributors = [ADDRESS_OF_ATTACK_FEES_DISTRIBUTOR]` and `amounts = [100]` (or any amount up to the router's balance of that token).
5.  Inside `RouterModuleVLSDT.depositRewards`:
    *   `AttackFeeDistributor.REWARD_TOKEN()` is called, which returns `USDC_ADDRESS`.
    *   The router's USDC contract then calls `USDC.approve(ADDRESS_OF_ATTACK_FEES_DISTRIBUTOR, 100)`.
    *   `AttackFeeDistributor.deposit(100)` is called by the router.
    *   Inside `AttackFeeDistributor.deposit`, it executes `USDC.transferFrom(ROUTER_ADDRESS, ATTACKER_ADDRESS, 100)`.
6.  The 100 USDC is transferred from the router to the attacker's address.

---

## 3. Remediation
The `vlFeeDistributors` parameter should be strictly validated against a whitelist of trusted addresses, or the `REWARD_TOKEN()` call should be replaced with a mechanism that does not rely on an untrusted external call to determine the token for approval.

Possible solutions:
1.  **Whitelist `vlFeeDistributors`:** Implement a mapping or a list of trusted `IVlFeeDistributor` addresses. All `vlFeeDistributors` provided in `calldata` must be present in this whitelist.
2.  **Trusted `REWARD_TOKEN` Registry:** If the `REWARD_TOKEN` for a specific `vlFeeDistributor` is known and fixed, store this mapping in a trusted, immutable (or carefully governed) registry within the router or a linked configuration contract. Fetch the `REWARD_TOKEN` address from this registry instead of calling the user-supplied `vlFeeDistributor` address.
3.  **Explicit `rewardTokens` parameter (less ideal):** The function could take an additional `IERC20[] calldata rewardTokens` parameter, alongside `vlFeeDistributors` and `amounts`, mapping each distributor to its specific reward token. This would put the burden of trust on the caller to provide correct token addresses, but it removes the dynamic fetching from an untrusted contract for the approval. This should still be combined with whitelisting `vlFeeDistributors` to prevent other potential attacks on malicious fee distributors.
