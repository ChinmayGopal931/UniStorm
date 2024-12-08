// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {BeforeSwapDelta, toBeforeSwapDelta} from "v4-core/types/BeforeSwapDelta.sol";
import {CurrencySettler} from "@uniswap/v4-core/test/utils/CurrencySettler.sol";

import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";

import {Currency, CurrencyLibrary} from "v4-core/types/Currency.sol";
import {StateLibrary} from "v4-core/libraries/StateLibrary.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {TickMath} from "v4-core/libraries/TickMath.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";

import {FixedPointMathLib} from "solmate/src/utils/FixedPointMathLib.sol";

import "./Tornado.sol";
import {TokenETHSwapper} from "./WETH.sol";

contract UniStorm is BaseHook, ERC1155, Tornado {
    using StateLibrary for IPoolManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using FixedPointMathLib for uint256;
    using CurrencySettler for Currency;

    // Errors
    error InvalidOrder();
    error NothingToClaim();
    error NotEnoughToClaim();
    error AddLiquidityThroughHook();
    error SwapFailed();

    // Events for tracking ETH flow
    event ETHReceived(uint256 amount);
    event TokenDeposited(Currency token, uint256 amount, uint256 ethReceived);

    TokenETHSwapper public immutable swapper;

    struct Deposits {
        uint256 amount;
        bytes32 commitment;
        bool isDeposited;
        Currency token;
        uint256 timestamp;
    }

    struct CallbackData {
        uint256 amountEach;
        Currency currency0;
        Currency currency1;
        address sender;
    }

    struct SwapState {
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
        bytes32 root;
        bytes32 nullifierHash;
        address recipient;
        address relayer;
        uint256 amountInOutPositive;
    }

    // Mapping to store deposits by their commitment hash
    mapping(Currency => mapping(bytes32 => Deposits)) public deposits;

    // Constructor
    constructor(
        IPoolManager _manager,
        string memory _uri,
        IVerifier _verifier,
        IHasher _hasher,
        uint256 _denomination,
        uint32 _merkleTreeHeight,
        TokenETHSwapper _swapper
    ) BaseHook(_manager) ERC1155(_uri) Tornado(_verifier, _hasher, _denomination, _merkleTreeHeight) {
        swapper = _swapper;
    }

    // BaseHook Functions
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: true, // Don't allow adding liquidity normally
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true, // Override how swaps are done
            afterSwap: false,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: true, // Allow beforeSwap to return a custom delta
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // Disable adding liquidity through the PM
    function beforeAddLiquidity(address, PoolKey calldata, IPoolManager.ModifyLiquidityParams calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        revert AddLiquidityThroughHook();
    }

    // Custom add liquidity function
    function addLiquidity(PoolKey calldata key, uint256 amountEach) external {
        poolManager.unlock(abi.encode(CallbackData(amountEach, key.currency0, key.currency1, msg.sender)));
    }

    function _processWithdraw(address _recipient, address _relayer, uint256 _fee, uint256 _refund) internal override {
        require(msg.value == 0, "Message value is supposed to be zero for ETH instance");
        require(_refund == 0, "Refund value is supposed to be zero for ETH instance");

        // If recipient is this contract, skip the transfer since we already have the ETH
        if (_recipient != address(this)) {
            (bool success,) = _recipient.call{value: denomination - _fee}("");
            require(success, "payment to _recipient did not go thru");
        }

        if (_fee > 0 && _relayer != address(0)) {
            (bool success,) = _relayer.call{value: _fee}("");
            require(success, "payment to _relayer did not go thru");
        }
    }

    function _processDeposit() internal override {
        require(msg.value == denomination, "Please send `mixDenomination` ETH along with transaction");
    }

    // External deposit function that takes both token and commitment
    // Modified deposit function to handle both ETH and token0 deposits
    function deposit(Currency token, uint256 amount, bytes32 commitment) external payable nonReentrant {
        require(!commitments[commitment], "The commitment has been submitted");
        require(!deposits[token][commitment].isDeposited, "Token commitment already exists");

        // Get the leaf index from merkle tree insertion
        uint32 insertedIndex = _insert(commitment);
        commitments[commitment] = true;

        // Handle ETH deposits
        if (Currency.unwrap(token) == address(0)) {
            require(msg.value == denomination, "Invalid ETH amount");
            require(amount == denomination, "Amount must match denomination for ETH");
            _processDeposit();
        }
        // Handle token0 deposits
        else {
            require(msg.value == 0, "ETH not accepted for token deposits");

            // Transfer tokens from user to this contract
            IERC20(Currency.unwrap(token)).transferFrom(msg.sender, address(this), amount);

            // Approve swapper to spend our tokens
            IERC20(Currency.unwrap(token)).approve(address(swapper), amount);

            // Swap tokens for ETH
            try swapper.swapTokenForETH(amount) {
                require(address(this).balance >= denomination, "Insufficient ETH after swap");
            } catch {
                revert SwapFailed();
            }
        }

        // Store deposit information
        deposits[token][commitment] = Deposits({
            amount: amount,
            commitment: commitment,
            isDeposited: true,
            token: token,
            timestamp: block.timestamp
        });

        // Emit deposit event
        Tornado._emit_deposit(commitment, insertedIndex);
    }

    // Handle private swap (withdrawal) with zero-knowledge proof
    function verifyProofAndNullifier(SwapState memory state) internal view returns (bool) {
        require(!nullifierHashes[state.nullifierHash], "Note has been spent");
        require(isKnownRoot(state.root), "Invalid root");

        return verifier.verifyProof(
            state.pA,
            state.pB,
            state.pC,
            [
                uint256(state.root),
                uint256(state.nullifierHash),
                uint256(uint160(state.recipient)),
                uint256(uint160(state.relayer)),
                0,
                0
            ]
        );
    }

    // Move swap execution to a separate function
    function executeSwap(SwapState memory state, PoolKey calldata key, IPoolManager.SwapParams calldata params)
        internal
        returns (BeforeSwapDelta)
    {
        console.log("in executeSwap");
        uint256 amount = state.amountInOutPositive;
        console.log("Contract ETH balance:", address(this).balance);

        if (params.zeroForOne) {
            key.currency0.take(poolManager, address(this), state.amountInOutPositive, true);

            key.currency1.settle(poolManager, address(this), state.amountInOutPositive, true);
        } else {
            key.currency0.settle(poolManager, address(this), state.amountInOutPositive, true);
            key.currency1.take(poolManager, address(this), state.amountInOutPositive, true);
        }

        return toBeforeSwapDelta(int128(-params.amountSpecified), int128(params.amountSpecified));
    }

    function handlePrivateSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata proofData
    ) internal returns (bytes4, BeforeSwapDelta, uint24) {
        SwapState memory state;

        // Decode proof data
        (state.pA, state.pB, state.pC, state.root, state.nullifierHash, state.recipient, state.relayer) =
            abi.decode(proofData, (uint256[2], uint256[2][2], uint256[2], bytes32, bytes32, address, address));

        console.log("beofre invalid, before bal", address(this).balance);
        // Verify proof
        require(verifyProofAndNullifier(state), "Invalid proof");

        // Mark nullifier as spent
        nullifierHashes[state.nullifierHash] = true;

        // Process ETH withdrawal
        _processWithdraw(address(this), address(0), 0, 0);

        console.log(
            "bal before token0 eth",
            IERC20(Currency.unwrap(key.currency0)).balanceOf(address((this))),
            address(this).balance
        );

        // Perform the token0 to ETH swap
        swapper.swapETHForToken{value: denomination}();

        console.log(
            "bal before token0 eth",
            IERC20(Currency.unwrap(key.currency0)).balanceOf(address(this)),
            address(this).balance
        );
        console.log("after _processWithdraw", address(this).balance);

        // Calculate swap amount
        state.amountInOutPositive =
            params.amountSpecified > 0 ? uint256(params.amountSpecified) : uint256(-params.amountSpecified);

        // Execute swap
        BeforeSwapDelta delta = executeSwap(state, key, params);

        // Emit withdrawal event
        emit Withdrawal(state.recipient, state.nullifierHash, address(this), 0);

        return (this.beforeSwap.selector, delta, 0);
    }

    function _unlockCallback(bytes calldata data) internal override returns (bytes memory) {
        CallbackData memory callbackData = abi.decode(data, (CallbackData));

        // Settle `amountEach` of each currency from the sender
        // i.e. Create a debit of `amountEach` of each currency with the Pool Manager
        callbackData.currency0.settle(
            poolManager,
            callbackData.sender,
            callbackData.amountEach,
            false // `burn` = `false` i.e. we're actually transferring tokens, not burning ERC-6909 Claim Tokens
        );
        callbackData.currency1.settle(poolManager, callbackData.sender, callbackData.amountEach, false);

        callbackData.currency0.take(
            poolManager,
            address(this),
            callbackData.amountEach,
            true // true = mint claim tokens for the hook, equivalent to money we just deposited to the PM
        );
        callbackData.currency1.take(poolManager, address(this), callbackData.amountEach, true);

        return "";
    }

    // Modified beforeSwap to handle private withdrawals
    function beforeSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata data
    ) external override returns (bytes4, BeforeSwapDelta, uint24) {
        if (data.length >= 10) {
            console.log("efmofmoe");
            // This is a withdrawal/private swap
            return handlePrivateSwap(sender, key, params, data);
        }

        // Regular swap logic here if needed
        revert("Regular swaps not supported");
    }

    // Simple receive function to accept ETH payments
    receive() external payable {
        emit ETHReceived(msg.value);
    }

    // Explicit fallback function to handle ETH transfers with data
    fallback() external payable {
        emit ETHReceived(msg.value);
    }
}
