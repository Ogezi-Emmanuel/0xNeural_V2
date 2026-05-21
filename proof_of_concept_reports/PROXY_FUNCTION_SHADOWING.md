# Vulnerability Report: Proxy Function Shadowing

**Vulnerability Category:** Proxy Function Shadowing Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
The `Proxy` contract implements a custom `proxyCallIfNotAdmin` modifier that dictates how functions defined within the proxy contract (e.g., `upgradeTo`, `changeAdmin`, `admin`, `implementation`) are handled based on `msg.sender`.
Specifically, if `msg.sender` is not the contract's admin (or `address(0)`), the modifier forces a `delegatecall` to the current implementation contract using the original `msg.data`.

This design deviates from standard transparent proxy patterns and introduces a critical access control vulnerability:
1.  **Admin Function Shadowing:** Functions like `upgradeTo` and `changeAdmin` are intended to be sensitive admin functions of the proxy itself. By forcing a `delegatecall` for non-admin callers, the proxy's own administrative interface is effectively "shadowed" by the implementation.
2.  **Implementation Vulnerability Exposure:** If the current implementation contract (the target of the `delegatecall`) contains a `public` or `external` function that shares the same function selector as one of the proxy's admin functions (e.g., `upgradeTo(address)` or `changeAdmin(address)`) and *lacks proper access control checks* (e.g., `onlyOwner`/`onlyAdmin`), an unprivileged external attacker can exploit this. The attacker can call the proxy's `upgradeTo` (or `changeAdmin`) function, which will then `delegatecall` to the vulnerable, unprotected function in the implementation. Since `delegatecall` preserves `msg.sender`, the implementation's function would execute with the attacker's address as `msg.sender` and no internal check would prevent the action.

This allows any unprivileged user to potentially change the proxy's implementation or admin, leading to a complete compromise of the proxy and any logic that relies on its upgradeability.

---

## 2. Theoretical Exploit Scenario
1.  An attacker identifies that the `Proxy` contract is in use and observes the `proxyCallIfNotAdmin` modifier.
2.  The attacker determines the address of the current `_implementation` contract.
3.  The attacker inspects the `_implementation` contract's code (or bytecode) and discovers a `public` or `external` function, for example, `function upgradeTo(address newImplementation)` or `function changeAdmin(address newAdmin)`, which does *not* contain an `onlyOwner` or `onlyAdmin` modifier or any other check against `msg.sender`.
4.  The attacker constructs a transaction to call the `Proxy` contract's `upgradeTo(maliciousImplementationAddress)` function (or `changeAdmin(maliciousAdminAddress)`).
5.  Since the attacker's `msg.sender` is not the proxy's admin, the `proxyCallIfNotAdmin` modifier executes its `else` branch, leading to a `delegatecall` to the `_implementation` contract with the attacker's calldata (i.e., `upgradeTo(maliciousImplementationAddress)`).
6.  The `_implementation` contract's unprotected `upgradeTo` function is executed in the context of the `Proxy` contract. It successfully updates the `Proxy`'s internal `_implementation` storage slot (EIP-1967 slot `PROXY_IMPLEMENTATION_ADDRESS`) to the `maliciousImplementationAddress`.
7.  The attacker now controls the proxy's logic, effectively rug-pulling funds or taking over associated contracts.

---

## 3. Remediation
The `proxyCallIfNotAdmin` modifier should be removed or refactored to align with standard transparent proxy security practices. Admin functions of the `Proxy` contract (e.g., `upgradeTo`, `upgradeToAndCall`, `changeAdmin`, `admin`, `implementation`) must be exclusively callable by the `_admin` address directly. Calls by non-admin users to these specific functions should revert, rather than being delegatecalled.

A recommended fix is to:
1.  Introduce a standard `onlyAdmin` modifier:
    ```solidity
    modifier onlyAdmin() {
        require(msg.sender == _getAdmin(), "Proxy: not admin");
        _;
    }
    ```
2.  Apply this `onlyAdmin` modifier to all administrative functions within the `Proxy` contract:
    ```solidity
    function upgradeTo(address _implementation) public virtual onlyAdmin {
        _setImplementation(_implementation);
    }

    function upgradeToAndCall(
        address _implementation,
        bytes calldata _data
    )
        public
        payable
        virtual
        onlyAdmin // Change proxyCallIfNotAdmin to onlyAdmin
        returns (bytes memory)
    {
        _setImplementation(_implementation);
        (bool success, bytes memory returndata) = _implementation.delegatecall(_data);
        require(success, "Proxy: delegatecall to new implementation contract failed");
        return returndata;
    }

    function changeAdmin(address _admin) public virtual onlyAdmin { // Change proxyCallIfNotAdmin to onlyAdmin
        _changeAdmin(_admin);
    }

    function admin() public virtual onlyAdmin returns (address) { // Change proxyCallIfNotAdmin to onlyAdmin
        return _getAdmin();
    }

    function implementation() public virtual onlyAdmin returns (address) { // Change proxyCallIfNotAdmin to onlyAdmin
        return _getImplementation();
    }
    ```
3.  Ensure the `receive()` and `fallback()` functions continue to use `_doProxyCall()` for all non-admin-function calls, adhering to the transparent proxy model.
4.  Remove the `address(0)` check from `onlyAdmin` as it is typically for off-chain simulation and should not affect on-chain access control. If `address(0)` simulation for admin functions is strictly required, it should be handled with a separate, explicit check for such simulations, distinct from the primary access control mechanism.
