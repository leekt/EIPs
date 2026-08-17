// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @notice Minimal canonical paymaster for EIP-8141-style frame transactions.
/// @dev The PAY/VERIFY frame must carry empty calldata and exactly one
///      frame-scoped signature reference. Local signature index 0 must resolve
///      to a protocol-validated SECP256K1 signature with empty msg and signer
///      equal to owner. The protocol validates the raw signature before frame
///      execution, so this contract checks only frame-local signature metadata.
contract CanonicalPaymaster {
    uint256 public constant WITHDRAWAL_DELAY = 12 hours;
    uint256 private constant SECP256K1_SCHEME = 0x01;

    // Stored in contract storage instead of immutable so the deployed runtime code
    // is identical across all instances and can be recognized canonically by code match.
    address public owner;

    address payable public pendingWithdrawalTo;
    uint256 public pendingWithdrawalAmount;
    uint256 public pendingWithdrawalReadyAt;

    error NotOwner();
    error ZeroAddress();
    error InvalidSignatureReference();
    error NoPendingWithdrawal();
    error WithdrawalNotReady();
    error TransferFailed();

    event WithdrawalRequested(address indexed to, uint256 amount, uint256 readyAt);
    event WithdrawalExecuted(address indexed to, uint256 amount);

    constructor(address owner_) payable {
        if (owner_ == address(0)) revert ZeroAddress();
        owner = owner_;
    }

    receive() external payable {}

    /// @dev Raw paymaster validation entrypoint. Use as the target of the PAY/VERIFY frame.
    fallback() external payable {
        if (msg.data.length != 0) revert InvalidSignatureReference();
        if (_signatureRefCount() != 1) revert InvalidSignatureReference();

        uint256 localSignatureIndex = 0;
        if (_signatureScheme(localSignatureIndex) != SECP256K1_SCHEME) {
            revert InvalidSignatureReference();
        }
        if (_signatureSigner(localSignatureIndex) != owner) {
            revert InvalidSignatureReference();
        }
        if (_signatureMessage(localSignatureIndex) != bytes32(0)) {
            revert InvalidSignatureReference();
        }
        if (_signatureLength(localSignatureIndex) != 65) {
            revert InvalidSignatureReference();
        }

        _approvePayer();
    }

    function requestWithdrawal(address payable to, uint256 amount) external {
        if (msg.sender != owner) revert NotOwner();
        if (to == address(0)) revert ZeroAddress();

        pendingWithdrawalTo = to;
        pendingWithdrawalAmount = amount;
        pendingWithdrawalReadyAt = block.timestamp + WITHDRAWAL_DELAY;

        emit WithdrawalRequested(to, amount, pendingWithdrawalReadyAt);
    }

    function executeWithdrawal() external {
        if (msg.sender != owner) revert NotOwner();

        address payable to = pendingWithdrawalTo;
        uint256 amount = pendingWithdrawalAmount;
        uint256 readyAt = pendingWithdrawalReadyAt;

        if (readyAt == 0) revert NoPendingWithdrawal();
        if (block.timestamp < readyAt) revert WithdrawalNotReady();

        delete pendingWithdrawalTo;
        delete pendingWithdrawalAmount;
        delete pendingWithdrawalReadyAt;

        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit WithdrawalExecuted(to, amount);
    }

    function _signatureRefCount() internal returns (uint256 count) {
        uint256 frameIndex;
        assembly {
            // TXPARAM(0x0a) -> current frame index
            frameIndex := verbatim_0i_1o(hex"600ab0")
            // FRAMEPARAM(param=0x0c, frameIndex) -> len(signature_refs)
            count := verbatim_1i_1o(hex"600c90b3", frameIndex)
        }
    }

    function _signatureSigner(uint256 localSignatureIndex) internal returns (address signer) {
        uint256 value;
        assembly {
            // SIGPARAM(param=0, localSignatureIndex)
            value := verbatim_1i_1o(hex"600090b4", localSignatureIndex)
        }
        signer = address(uint160(value));
    }

    function _signatureScheme(uint256 localSignatureIndex) internal returns (uint256 scheme) {
        assembly {
            // SIGPARAM(param=1, localSignatureIndex)
            scheme := verbatim_1i_1o(hex"600190b4", localSignatureIndex)
        }
    }

    function _signatureMessage(uint256 localSignatureIndex) internal returns (bytes32 message) {
        assembly {
            // SIGPARAM(param=2, localSignatureIndex); zero represents empty msg.
            message := verbatim_1i_1o(hex"600290b4", localSignatureIndex)
        }
    }

    function _signatureLength(uint256 localSignatureIndex) internal returns (uint256 length) {
        assembly {
            // SIGPARAM(param=3, localSignatureIndex)
            length := verbatim_1i_1o(hex"600390b4", localSignatureIndex)
        }
    }

    function _approvePayer() internal {
        assembly {
            // APPROVE(scope=0x1, length=0, offset=0)
            // Push order: scope, length, offset
            verbatim_0i_0o(hex"600160006000aa")
        }
    }
}
