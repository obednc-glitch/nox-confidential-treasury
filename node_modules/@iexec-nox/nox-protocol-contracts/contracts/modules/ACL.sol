// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.35;

import {HandleUtils} from "../utils/HandleUtils.sol";
import {INoxCompute} from "../interfaces/INoxCompute.sol";
import {Common} from "./Common.sol";

/**
 * @title ACL
 * @notice Access control for encrypted handles. Supports persistent and transient access,
 * plus viewer and public-decryption roles.
 */
abstract contract ACL is Common {
    modifier notZeroAddress(address account) {
        require(account != address(0), InvalidZeroAddress());
        _;
    }

    /**
     * Ensures the sender is allowed to access the handle
     * @param handle The handle to check access for
     */
    modifier onlyAllowed(bytes32 handle) {
        require(_isAllowed(handle, msg.sender), UnauthorizedSender(msg.sender));
        _;
    }

    /**
     * Prevents ACL mutations on public handles.
     * Applied before onlyAllowed to avoid unnecessary storage reads.
     * @param handle The handle to check
     */
    modifier notPublicHandle(bytes32 handle) {
        require(!HandleUtils.isPublicHandle(handle), PublicHandleACLForbidden());
        _;
    }

    /// @inheritdoc INoxCompute
    function isAllowed(bytes32 handle, address account) external view override returns (bool) {
        return _isAllowed(handle, account);
    }

    /// @inheritdoc INoxCompute
    function validateAllowedForAll(
        address account,
        bytes32[] calldata handles
    ) external view override {
        _validateAllowedForAll(account, handles);
    }

    /// @inheritdoc INoxCompute
    function allow(
        bytes32 handle,
        address account
    ) external override notZeroAddress(account) notPublicHandle(handle) onlyAllowed(handle) {
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        $.admins[handle][account] = true;
        emit Allowed(msg.sender, account, handle);
    }

    /**
     * @inheritdoc INoxCompute
     * @dev To grant transient access, the caller must already have permission on `handle`.
     *      Transient access only lasts for the current transaction. It is the responsibility
     *      of the application contract to convert this into persistent access via `allow()`
     *      if needed.
     */
    function allowTransient(
        bytes32 handle,
        address account
    ) external override notZeroAddress(account) notPublicHandle(handle) onlyAllowed(handle) {
        _allowTransient(handle, account);
    }

    /// @inheritdoc INoxCompute
    function disallowTransient(
        bytes32 handle,
        address account
    ) external override notZeroAddress(account) notPublicHandle(handle) onlyAllowed(handle) {
        bytes32 key = keccak256(abi.encodePacked(handle, account));
        assembly {
            tstore(key, 0)
        }
    }

    /// @inheritdoc INoxCompute
    function addViewer(
        bytes32 handle,
        address viewer
    ) external override notZeroAddress(viewer) notPublicHandle(handle) onlyAllowed(handle) {
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        $.viewers[handle][viewer] = true;
        emit ViewerAdded(msg.sender, viewer, handle);
    }

    /// @inheritdoc INoxCompute
    function isViewer(bytes32 handle, address viewer) external view override returns (bool) {
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        return
            HandleUtils.isPublicHandle(handle) ||
            $.isPubliclyDecryptable[handle] ||
            $.viewers[handle][viewer] ||
            $.admins[handle][viewer];
    }

    /// @inheritdoc INoxCompute
    function allowPublicDecryption(
        bytes32 handle
    ) external override notPublicHandle(handle) onlyAllowed(handle) {
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        $.isPubliclyDecryptable[handle] = true;
        emit MarkedAsPubliclyDecryptable(msg.sender, handle);
    }

    /// @inheritdoc INoxCompute
    function isPubliclyDecryptable(bytes32 handle) external view override returns (bool) {
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        return HandleUtils.isPublicHandle(handle) || $.isPubliclyDecryptable[handle];
    }

    /**
     * Grants transient access to a handle for an account. This function does not do any
     * checks and should be used with caution.
     * This function is used in two scenarios:
     *   - For handles generated off-chain by the Handle Gateway, once the proof has been verified
     *   - For handles resulting from on-chain operations, where the caller naturally inherits
     *     rights on the output handle
     * @param handle Handle identifier
     * @param account Address of the account
     */
    function _allowTransient(bytes32 handle, address account) internal override {
        // Public handles don't need ACL; skip silently to save gas.
        if (HandleUtils.isPublicHandle(handle)) {
            return;
        }
        bytes32 key = keccak256(abi.encodePacked(handle, account));
        assembly {
            tstore(key, 1)
        }
    }

    /**
     * Reverts if account lacks access to any handle in the array.
     */
    function _validateAllowedForAll(
        address account,
        bytes32[] memory handles
    ) internal view override {
        for (uint256 i = 0; i < handles.length; i++) {
            if (!_isAllowed(handles[i], account)) {
                revert NotAllowed(handles[i], account);
            }
        }
    }

    /**
     * Checks if the handle is public, or if account has transient or persistent
     * access to the handle.
     */
    function _isAllowed(bytes32 handle, address account) private view returns (bool) {
        return
            HandleUtils.isPublicHandle(handle) ||
            _isAllowedTransient(handle, account) ||
            _isAllowedPersistent(handle, account);
    }

    /**
     * Check if an address has transient access to handle.
     * @param handle Handle.
     * @param account Address of the account.
     * @return Returns `true` if the address has transient access to a handle and `false` otherwise.
     */
    function _isAllowedTransient(bytes32 handle, address account) private view returns (bool) {
        bool isAllowedTransient_;
        bytes32 key = keccak256(abi.encodePacked(handle, account));
        assembly {
            isAllowedTransient_ := tload(key)
        }
        return isAllowedTransient_;
    }

    /**
     * Check if an address has persistent access to handle.
     * @param handle Handle.
     * @param account Address of the account.
     * @return Returns `true` if the address has persistent access to a handle and `false` otherwise.
     */
    function _isAllowedPersistent(bytes32 handle, address account) private view returns (bool) {
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        return $.admins[handle][account];
    }
}
