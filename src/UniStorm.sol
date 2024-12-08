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
import {WETH} from "./WETH.sol";

contract UniStorm is BaseHook, ERC1155, Tornado {
    using StateLibrary for IPoolManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using FixedPointMathLib for uint256;
    using CurrencySettler for Currency;

    // Errors
    error AddLiquidityThroughHook();
    error SwapFailed();

    // Events for tracking ETH flow
    event ETHReceived(uint256 amount);
    event TokenDeposited(Currency token, uint256 amount, uint256 ethReceived);

    WETH public immutable weth;

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
        WETH _weth
    ) BaseHook(_manager) ERC1155(_uri) Tornado(_verifier, _hasher, _denomination, _merkleTreeHeight) {
        weth = _weth;
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

    /*
     * Prevents direct liquidity addition through the pool manager
     * Forces all liquidity operations to go through our privacy-preserving logic
     * @param key Pool identifier
     * @param params Liquidity parameters
     * @return bytes4 Function selector
     */
    function beforeAddLiquidity(address, PoolKey calldata, IPoolManager.ModifyLiquidityParams calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        revert AddLiquidityThroughHook();
    }

    /*
     * Custom liquidity addition function that preserves privacy
     * Handles token transfers and pool updates while maintaining anonymity
     * @param key Pool identifier
     * @param amountEach Amount of each token to add as liquidity
     */
    function addLiquidity(PoolKey calldata key, uint256 amountEach) external {
        poolManager.unlock(abi.encode(CallbackData(amountEach, key.currency0, key.currency1, msg.sender)));
    }

    /*
     * Internal function to process withdrawals in the privacy system
     * Handles ETH transfers to recipients and relayers while maintaining privacy
     * @param _recipient Address to receive withdrawn funds
     * @param _relayer Optional relayer address for gas compensation
     * @param _fee Fee paid to relayer
     * @param _refund Additional refund amount
     */
    function _processWithdraw(address _recipient, address _relayer, uint256 _fee, uint256 _refund) internal override {
        // Ensure no ETH is sent with withdrawal processing
        require(msg.value == 0, "Message value is supposed to be zero for ETH instance");
        require(_refund == 0, "Refund value is supposed to be zero for ETH instance");

        // Skip transfer if recipient is this contract (internal operation)
        if (_recipient != address(this)) {
            (bool success,) = _recipient.call{value: denomination - _fee}("");
            require(success, "payment to _recipient did not go thru");
        }

        // Process relayer fee if applicable
        if (_fee > 0 && _relayer != address(0)) {
            (bool success,) = _relayer.call{value: _fee}("");
            require(success, "payment to _relayer did not go thru");
        }
    }

    /*
     * Internal function to process deposits into the privacy system
     * Ensures correct ETH amount is provided with deposit
     */
    function _processDeposit() internal override {
        require(msg.value == denomination, "Please send `mixDenomination` ETH along with transaction");
    }

    /*
     * Main deposit function handling both ETH and token deposits
     * Converts token deposits to ETH and stores commitment information
     * @param token Currency being deposited
     * @param amount Amount of currency to deposit
     * @param commitment Zero-knowledge commitment for privacy preservation
     */
    function deposit(Currency token, uint256 amount, bytes32 commitment) external payable nonReentrant {
        // Verify commitment hasn't been used
        require(!commitments[commitment], "The commitment has been submitted");
        require(!deposits[token][commitment].isDeposited, "Token commitment already exists");

        // Add commitment to Merkle tree
        uint32 insertedIndex = _insert(commitment);
        commitments[commitment] = true;

        // Handle ETH deposits
        if (Currency.unwrap(token) == address(0)) {
            require(msg.value == denomination, "Invalid ETH amount");
            require(amount == denomination, "Amount must match denomination for ETH");
            _processDeposit();
        }
        // Handle token deposits
        else {
            require(msg.value == 0, "ETH not accepted for token deposits");

            // Transfer and swap tokens to ETH
            IERC20(Currency.unwrap(token)).transferFrom(msg.sender, address(this), amount);
            IERC20(Currency.unwrap(token)).approve(address(weth), amount);

            try weth.swapTokenForETH(amount) {
                require(address(this).balance >= denomination, "Insufficient ETH after swap");
            } catch {
                revert SwapFailed();
            }
        }

        // Record deposit details
        deposits[token][commitment] = Deposits({
            amount: amount,
            commitment: commitment,
            isDeposited: true,
            token: token,
            timestamp: block.timestamp
        });

        // Emit deposit event for indexing
        Tornado._emit_deposit(commitment, insertedIndex);
    }

    /*
     * Verifies zero-knowledge proof and checks nullifier status
     * Prevents double-spending and ensures transaction privacy
     * @param state Current swap state containing proof components
     * @return bool Indicates if proof is valid
     */
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

    /*
     * Executes the actual token swap after privacy verification
     * Handles currency settlement and updates pool state
     * @param state Current swap state
     * @param key Pool identifier
     * @param params Swap parameters
     * @return BeforeSwapDelta Computed swap amounts
     */
    function executeSwap(SwapState memory state, PoolKey calldata key, IPoolManager.SwapParams calldata params)
        internal
        returns (BeforeSwapDelta)
    {
        uint256 amount = state.amountInOutPositive;

        // Handle token transfers based on swap direction
        if (params.zeroForOne) {
            key.currency0.take(poolManager, address(this), state.amountInOutPositive, true);
            key.currency1.settle(poolManager, address(this), state.amountInOutPositive, true);
        } else {
            key.currency0.settle(poolManager, address(this), state.amountInOutPositive, true);
            key.currency1.take(poolManager, address(this), state.amountInOutPositive, true);
        }

        return toBeforeSwapDelta(int128(-params.amountSpecified), int128(params.amountSpecified));
    }

    /*
     * Processes private swaps with zero-knowledge proof verification
     * Coordinates the entire private swap flow including proof verification,
     * token swapping, and state updates
     * @param sender Transaction initiator
     * @param key Pool identifier
     * @param params Swap parameters
     * @param proofData Zero-knowledge proof components
     * @return Function selector and swap amounts
     */
    function handlePrivateSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata proofData
    ) internal returns (bytes4, BeforeSwapDelta, uint24) {
        SwapState memory state;

        // Decode proof components
        (state.pA, state.pB, state.pC, state.root, state.nullifierHash, state.recipient, state.relayer) =
            abi.decode(proofData, (uint256[2], uint256[2][2], uint256[2], bytes32, bytes32, address, address));

        // Verify proof validity
        require(verifyProofAndNullifier(state), "Invalid proof");

        // Mark nullifier as spent to prevent reuse
        nullifierHashes[state.nullifierHash] = true;

        // Process the withdrawal
        _processWithdraw(address(this), address(0), 0, 0);

        // Convert ETH to tokens
        weth.swapETHForToken{value: denomination}();

        // Calculate and execute swap
        state.amountInOutPositive =
            params.amountSpecified > 0 ? uint256(params.amountSpecified) : uint256(-params.amountSpecified);

        BeforeSwapDelta delta = executeSwap(state, key, params);

        // Emit withdrawal event
        emit Withdrawal(state.recipient, state.nullifierHash, address(this), 0);

        return (this.beforeSwap.selector, delta, 0);
    }

    /*
     * Callback handler for unlocked pool operations
     * Processes token settlements during liquidity operations
     * @param data Encoded callback parameters
     * @return Empty bytes for interface compliance
     */
    function _unlockCallback(bytes calldata data) internal override returns (bytes memory) {
        CallbackData memory callbackData = abi.decode(data, (CallbackData));

        // Settle tokens from sender
        callbackData.currency0.settle(poolManager, callbackData.sender, callbackData.amountEach, false);
        callbackData.currency1.settle(poolManager, callbackData.sender, callbackData.amountEach, false);

        // Take tokens for the hook
        callbackData.currency0.take(poolManager, address(this), callbackData.amountEach, true);
        callbackData.currency1.take(poolManager, address(this), callbackData.amountEach, true);

        return "";
    }

    /*
     * Pre-swap hook handler
     * Routes transactions to either private or public swap logic
     * @param sender Transaction initiator
     * @param key Pool identifier
     * @param params Swap parameters
     * @param data Additional swap data (includes proof for private swaps)
     * @return Function selector and swap amounts
     */
    function beforeSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata data
    ) external override returns (bytes4, BeforeSwapDelta, uint24) {
        if (data.length >= 10) {
            // Handle private swap with proof verification
            return handlePrivateSwap(sender, key, params, data);
        }

        // Handle regular swaps
        uint256 amountIn =
            params.amountSpecified > 0 ? uint256(params.amountSpecified) : uint256(-params.amountSpecified);

        uint256 amountInOutPositive =
            params.amountSpecified > 0 ? uint256(params.amountSpecified) : uint256(-params.amountSpecified);

        BeforeSwapDelta beforeSwapDelta =
            toBeforeSwapDelta(int128(-params.amountSpecified), int128(params.amountSpecified));

        if (params.zeroForOne) {
            key.currency0.take(poolManager, address(this), amountInOutPositive, true);

            key.currency1.settle(poolManager, address(this), amountInOutPositive, true);
        } else {
            key.currency0.settle(poolManager, address(this), amountInOutPositive, true);
            key.currency1.take(poolManager, address(this), amountInOutPositive, true);
        }

        return (this.beforeSwap.selector, beforeSwapDelta, 0);
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
