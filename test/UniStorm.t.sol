pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "forge-std/Test.sol";

import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {PoolSwapTest} from "v4-core/test/PoolSwapTest.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";

import {PoolManager} from "v4-core/PoolManager.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";

import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {Currency, CurrencyLibrary} from "v4-core/types/Currency.sol";
import {StateLibrary} from "v4-core/libraries/StateLibrary.sol";

import {Hooks} from "v4-core/libraries/Hooks.sol";
import {TickMath} from "v4-core/libraries/TickMath.sol";
import {IERC20Minimal} from "v4-core/interfaces/external/IERC20Minimal.sol";

import {UniStorm} from "../src/UniStorm.sol";
import {WETH} from "../src/WETH.sol";

import {Groth16Verifier} from "src/Verifier.sol";
import {IVerifier, IHasher} from "src/Tornado.sol";

/* 
 * Test contract for UniStorm - a privacy-preserving liquidity pool built on Uniswap v4
 * This contract tests the core functionality including:
 * - Private deposits and withdrawals
 * - Token-ETH swaps
 * - Zero-knowledge proof verification
 * - Liquidity management
 */
contract UniStormTest is Test, Deployers {
    // Library usage declarations for Pool management
    using StateLibrary for IPoolManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;

    // Core protocol contracts
    IVerifier public verifier; // Handles verification of zero-knowledge proofs

    // Test configuration constants
    address public recipient = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address public relayer = address(0); // Zero address indicates no relayer
    uint256 public fee = 0; // No fees for testing
    uint256 public refund = 0; // No refunds for testing

    // Pool currencies (tokens)
    Currency token0; // First token in the pool
    Currency token1; // Second token in the pool

    // Core contracts
    UniStorm hook; // Our privacy-preserving hook
    WETH public weth; // Handles token-ETH conversions

    /*
     * Test setup: Deploys all necessary contracts and initializes the testing environment
     * 1. Deploys the MiMC hasher for zero-knowledge proofs
     * 2. Sets up the Groth16 verifier
     * 3. Initializes the Tornado Cash mixer
     * 4. Deploys Uniswap v4 contracts
     * 5. Sets up test tokens and the ETH swapper
     * 6. Configures the UniStorm hook with proper permissions
     */
    function setUp() public {
        // Deploy MimcSponge hasher using node.js script through FFI
        string[] memory inputs = new string[](3);
        inputs[0] = "node";
        inputs[1] = "forge-ffi-scripts/deployMimcsponge.js";

        bytes memory mimcspongeBytecode = vm.ffi(inputs);

        address mimcHasher;
        assembly {
            mimcHasher := create(0, add(mimcspongeBytecode, 0x20), mload(mimcspongeBytecode))
            if iszero(mimcHasher) { revert(0, 0) }
        }

        // Initialize verifier for zero-knowledge proofs
        verifier = IVerifier(address(new Groth16Verifier()));

        // Set up Uniswap v4 core infrastructure
        deployFreshManagerAndRouters();
        (token0, token1) = deployMintAndApprove2Currencies();

        // Initialize token-ETH swapper and fund it
        weth = new WETH(Currency.unwrap(token0));
        vm.deal(address(weth), 100 ether);
        MockERC20(Currency.unwrap(token0)).mint(address(weth), 100 ether);

        // Configure hook permissions - only allow specific operations
        uint160 flags =
            uint160(Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG);
        address payable hookAddress = payable(address(flags));

        // Deploy UniStorm hook with all necessary parameters
        deployCodeTo(
            "UniStorm.sol", abi.encode(manager, "", verifier, IHasher(mimcHasher), 1 ether, 20, weth, 1e18), hookAddress
        );

        hook = UniStorm(hookAddress);

        // Initialize pool and store key
        PoolKey memory poolKey;
        PoolId poolId;
        (poolKey, poolId) = initPool(token0, token1, hook, 3000, SQRT_PRICE_1_1);
        key = poolKey;

        // Set up token approvals for the hook
        MockERC20(Currency.unwrap(token0)).approve(address(hook), type(uint256).max);
        MockERC20(Currency.unwrap(token1)).approve(address(hook), type(uint256).max);

        // Add initial liquidity to the pool
        hook.addLiquidity(key, 1000e18);
    }

    /*
     * Helper function to deploy MimcSponge hasher contract
     * Used for zero-knowledge proof generation
     */
    function deployMimcSponge(bytes memory bytecode) public returns (address) {
        address deployedAddress;
        assembly {
            deployedAddress := create(0, add(bytecode, 0x20), mload(bytecode))
            if iszero(deployedAddress) { revert(0, 0) }
        }
        return deployedAddress;
    }

    /*
     * Generates commitment data for private transactions
     * Returns tuple of (commitment, nullifier, secret)
     * Uses external Node.js script through FFI
     */
    function _getCommitment() internal returns (bytes32 commitment, bytes32 nullifier, bytes32 secret) {
        string[] memory inputs = new string[](2);
        inputs[0] = "node";
        inputs[1] = "forge-ffi-scripts/generateCommitment.js";

        bytes memory result = vm.ffi(inputs);
        return abi.decode(result, (bytes32, bytes32, bytes32));
    }

    /*
     * Generates witness and proof data for private transactions
     * Uses external Node.js script through FFI
     * Returns zero-knowledge proof components and transaction details
     */
    function _getWitnessAndProof(
        bytes32 _nullifier,
        bytes32 _secret,
        address _recipient,
        address _relayer,
        bytes32[] memory leaves
    ) internal returns (uint256[2] memory, uint256[2][2] memory, uint256[2] memory, bytes32, bytes32) {
        string[] memory inputs = new string[](8 + leaves.length);
        inputs[0] = "node";
        inputs[1] = "forge-ffi-scripts/generateWitness.js";
        inputs[2] = vm.toString(_nullifier);
        inputs[3] = vm.toString(_secret);
        inputs[4] = vm.toString(_recipient);
        inputs[5] = vm.toString(_relayer);
        inputs[6] = "0";
        inputs[7] = "0";

        for (uint256 i = 0; i < leaves.length; i++) {
            inputs[8 + i] = vm.toString(leaves[i]);
        }

        bytes memory result = vm.ffi(inputs);
        return abi.decode(result, (uint256[2], uint256[2][2], uint256[2], bytes32, bytes32));
    }

    /*
     * Tests that direct liquidity modification is blocked
     * All liquidity changes must go through the hook
     */
    function test_cannotModifyLiquidity() public {
        vm.expectRevert();
        modifyLiquidityRouter.modifyLiquidity(
            key,
            IPoolManager.ModifyLiquidityParams({tickLower: -60, tickUpper: 60, liquidityDelta: 1e18, salt: bytes32(0)}),
            ZERO_BYTES
        );
    }

    /*
     * Tests ETH deposit functionality
     * Verifies:
     * - Deposit amount is correct
     * - Commitment is properly stored
     * - Deposit state is properly tracked
     * - Timestamp is recorded
     */
    function test_eth_deposit() public {
        uint256 depositAmount = 1 ether;
        (bytes32 commitment, bytes32 nullifier, bytes32 secret) = _getCommitment();

        hook.deposit{value: 1 ether}(Currency.wrap(address(0)), 1 ether, commitment);

        (uint256 amount, bytes32 storedCommitment, bool isDeposited, Currency token, uint256 timestamp) =
            hook.deposits(Currency.wrap(address(0)), commitment);

        assertEq(amount, depositAmount, "Incorrect deposit amount");
        assertEq(storedCommitment, commitment, "Incorrect commitment stored");
        assertTrue(isDeposited, "Deposit not marked as deposited");
        assertEq(Currency.unwrap(token), address(0), "Incorrect token stored");
        assertEq(timestamp, block.timestamp, "Incorrect timestamp");
    }

    /*
     * Tests complete private ETH swap flow
     * Steps:
     * 1. Generate commitment and make deposit
     * 2. Generate proof for withdrawal
     * 3. Execute private swap
     * 4. Verify balances and state changes
     */
    function test_private_eth_swap_flow() public {
        // Generate commitment and deposit ETH
        (bytes32 commitment, bytes32 nullifier, bytes32 secret) = _getCommitment();
        hook.deposit{value: 1 ether}(Currency.wrap(address(0)), 1 ether, commitment);

        // Generate proof for withdrawal
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = commitment;

        (uint256[2] memory pA, uint256[2][2] memory pB, uint256[2] memory pC, bytes32 root, bytes32 nullifierHash) =
            _getWitnessAndProof(nullifier, secret, recipient, relayer, leaves);

        // Prepare swap parameters
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: -1e18,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });

        // Encode proof data
        bytes memory proofData = abi.encode(pA, pB, pC, root, nullifierHash, recipient, relayer);

        // Record initial balances
        uint256 balanceBefore0 = MockERC20(Currency.unwrap(key.currency0)).balanceOf(address((this)));
        uint256 balanceBefore1 = MockERC20(Currency.unwrap(key.currency1)).balanceOf(address((this)));

        // Verify initial states
        assertEq(recipient.balance, 0);
        assertEq(address(hook).balance, 1 ether);

        // Execute private swap
        swapRouter.swap(key, params, PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false}), proofData);

        // Verify final balances and states
        uint256 balanceAfter0 = MockERC20(Currency.unwrap(key.currency0)).balanceOf(address((this)));
        uint256 balanceAfter1 = MockERC20(Currency.unwrap(key.currency1)).balanceOf(address((this)));

        assertEq(recipient.balance, 0);
        assertEq(1e18, balanceBefore0 - balanceAfter0);

        assertTrue(hook.isSpent(nullifierHash));
    }

    /*
     * Tests token deposit functionality
     * Verifies:
     * - Token transfer works correctly
     * - ETH conversion is handled properly
     * - Commitment is stored
     * - Balances are updated correctly
     */
    function test_token_deposit() public {
        (bytes32 commitment, bytes32 nullifier, bytes32 secret) = _getCommitment();

        // Setup test tokens
        MockERC20(Currency.unwrap(token0)).mint(address(this), 10e18);
        MockERC20(Currency.unwrap(token0)).approve(address(hook), 10e18);

        // Record initial balances
        uint256 hookETHBefore = address(hook).balance;
        uint256 userTokensBefore = MockERC20(Currency.unwrap(token0)).balanceOf(address(this));

        // Make token deposit
        hook.deposit(token0, 1e18, commitment);

        // Verify deposit state
        assertTrue(hook.commitments(commitment));

        // Verify balance changes
        assertEq(address(hook).balance - hookETHBefore, 1 ether);
        assertEq(userTokensBefore - MockERC20(Currency.unwrap(token0)).balanceOf(address(this)), 1e18);
    }

    /*
     * Tests regular non zk CSMM swap functionality
     */
    function test_regular_csmm_swap() public {
        PoolSwapTest.TestSettings memory settings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        // Swap exact output 100 Token A
        uint256 balanceOfTokenABefore = key.currency0.balanceOfSelf();
        uint256 balanceOfTokenBBefore = key.currency1.balanceOfSelf();
        swapRouter.swap(
            key,
            IPoolManager.SwapParams({
                zeroForOne: true,
                amountSpecified: 100e18,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            }),
            settings,
            ZERO_BYTES
        );
        uint256 balanceOfTokenAAfter = key.currency0.balanceOfSelf();
        uint256 balanceOfTokenBAfter = key.currency1.balanceOfSelf();

        assertEq(balanceOfTokenBAfter - balanceOfTokenBBefore, 100e18);
        assertEq(balanceOfTokenABefore - balanceOfTokenAAfter, 100e18);
    }
}
