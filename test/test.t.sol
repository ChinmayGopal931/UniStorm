// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// Foundry libraries
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

// Our contracts
import {UniStorm} from "../src/UniStorm.sol";
import {TokenETHSwapper} from "../src/WETH.sol";

import {Groth16Verifier} from "src/Verifier.sol";
import {ETHTornado, IVerifier, IHasher} from "src/ETHTornado.sol";

contract UniStormTest is Test, Deployers {
    // Use the libraries
    using StateLibrary for IPoolManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;

    IVerifier public verifier;
    ETHTornado public mixer;

    // Test vars
    address public recipient = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address public relayer = address(0);
    uint256 public fee = 0;
    uint256 public refund = 0;

    // The two currencies (tokens) from the pool
    Currency token0;
    Currency token1;

    UniStorm hook;

    TokenETHSwapper public swapper;

    function setUp() public {
        // Deploy MimcSponge hasher contract.
        string[] memory inputs = new string[](3);
        inputs[0] = "node";
        inputs[1] = "forge-ffi-scripts/deployMimcsponge.js";

        bytes memory mimcspongeBytecode = vm.ffi(inputs);

        address mimcHasher;
        assembly {
            mimcHasher := create(0, add(mimcspongeBytecode, 0x20), mload(mimcspongeBytecode))
            if iszero(mimcHasher) { revert(0, 0) }
        }

        // Deploy Groth16 verifier contract.
        verifier = IVerifier(address(new Groth16Verifier()));

        /**
         * Deploy Tornado Cash mixer
         *
         * - verifier: Groth16 verifier
         * - hasher: MiMC hasher
         * - denomination: 1 ETH
         * - merkleTreeHeight: 20
         */
        mixer = new ETHTornado(verifier, IHasher(mimcHasher), 1 ether, 20);

        // Deploy v4 core contracts
        deployFreshManagerAndRouters();

        // Deploy two test tokens
        (token0, token1) = deployMintAndApprove2Currencies();

        // Deploy the swapper after tokens are deployed
        swapper = new TokenETHSwapper(Currency.unwrap(token0));

        // Fund swapper with ETH for testing
        vm.deal(address(swapper), 100 ether);

        // Mint and approve tokens for swapper
        MockERC20(Currency.unwrap(token0)).mint(address(swapper), 100 ether);

        // Deploy our hook
        uint160 flags =
            uint160(Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG);

        // Explicitly mark the address as payable
        address payable hookAddress = payable(address(flags));

        deployCodeTo(
            "UniStorm.sol",
            abi.encode(manager, "", verifier, IHasher(mimcHasher), 1 ether, 20, swapper, 1e18), // Added token denomination
            hookAddress
        );

        hook = UniStorm(hookAddress);

        // Initialize a pool with these two tokens, properly capturing both return values
        PoolKey memory poolKey;
        PoolId poolId;
        (poolKey, poolId) = initPool(token0, token1, hook, 3000, SQRT_PRICE_1_1);
        key = poolKey; // Store the pool key in our test contract's state variable

        // Approve our hook address to spend these tokens as well
        MockERC20(Currency.unwrap(token0)).approve(address(hook), type(uint256).max);
        MockERC20(Currency.unwrap(token1)).approve(address(hook), type(uint256).max);

        hook.addLiquidity(key, 1000e18);
    }

    function deployMimcSponge(bytes memory bytecode) public returns (address) {
        address deployedAddress;
        assembly {
            deployedAddress := create(0, add(bytecode, 0x20), mload(bytecode))
            if iszero(deployedAddress) { revert(0, 0) }
        }
        return deployedAddress;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    function _getCommitment() internal returns (bytes32 commitment, bytes32 nullifier, bytes32 secret) {
        string[] memory inputs = new string[](2);
        inputs[0] = "node";
        inputs[1] = "forge-ffi-scripts/generateCommitment.js";

        bytes memory result = vm.ffi(inputs);
        (commitment, nullifier, secret) = abi.decode(result, (bytes32, bytes32, bytes32));

        return (commitment, nullifier, secret);
    }

    function _toHexString(bytes32 value) public pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(66);
        str[0] = "0";
        str[1] = "x";

        for (uint256 i = 0; i < 32; i++) {
            str[2 + i * 2] = alphabet[uint8(value[i] >> 4)];
            str[3 + i * 2] = alphabet[uint8(value[i] & 0x0f)];
        }

        return string(str);
    }

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
        (uint256[2] memory pA, uint256[2][2] memory pB, uint256[2] memory pC, bytes32 root, bytes32 nullifierHash) =
            abi.decode(result, (uint256[2], uint256[2][2], uint256[2], bytes32, bytes32));

        return (pA, pB, pC, root, nullifierHash);
    }

    function test_cannotModifyLiquidity() public {
        vm.expectRevert();
        modifyLiquidityRouter.modifyLiquidity(
            key,
            IPoolManager.ModifyLiquidityParams({tickLower: -60, tickUpper: 60, liquidityDelta: 1e18, salt: bytes32(0)}),
            ZERO_BYTES
        );
    }

    function test_eth_deposit() public {
        // Prepare test data
        uint256 depositAmount = 1 ether;
        (bytes32 commitment, bytes32 nullifier, bytes32 secret) = _getCommitment();

        // Make ETH deposit
        hook.deposit{value: 1 ether}(Currency.wrap(address(0)), 1 ether, commitment);

        // Verify deposit state - Note we're using Currency.wrap(address(0)) to check ETH deposits
        (uint256 amount, bytes32 storedCommitment, bool isDeposited, Currency token, uint256 timestamp) =
            hook.deposits(Currency.wrap(address(0)), commitment);

        assertEq(amount, depositAmount, "Incorrect deposit amount");
        assertEq(storedCommitment, commitment, "Incorrect commitment stored");
        assertTrue(isDeposited, "Deposit not marked as deposited");
        assertEq(Currency.unwrap(token), address(0), "Incorrect token stored"); // Should be address(0) for ETH
        assertEq(timestamp, block.timestamp, "Incorrect timestamp");
    }

    function test_private_eth_swap_flow() public {
        // 1. Generate commitment for deposit
        (bytes32 commitment, bytes32 nullifier, bytes32 secret) = _getCommitment();

        // hook.deposit{value: 1 ether}(token0, 1e18, commitment);
        hook.deposit{value: 1 ether}(Currency.wrap(address(0)), 1 ether, commitment);

        // 3. Generate proof for withdrawal
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = commitment;

        (uint256[2] memory pA, uint256[2][2] memory pB, uint256[2] memory pC, bytes32 root, bytes32 nullifierHash) =
            _getWitnessAndProof(nullifier, secret, recipient, relayer, leaves);

        PoolSwapTest.TestSettings memory settings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        // 4. Prepare swap parameters
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: -1e18,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });

        // 5. Encode proof data
        bytes memory proofData = abi.encode(pA, pB, pC, root, nullifierHash, recipient, relayer);

        uint256 balanceBefore0 = MockERC20(Currency.unwrap(key.currency0)).balanceOf(address((this)));
        uint256 balanceBefore1 = MockERC20(Currency.unwrap(key.currency1)).balanceOf(address((this)));

        assertEq(recipient.balance, 0);
        assertEq(address(hook).balance, 1 ether);
        // 6. Execute private swap
        swapRouter.swap(key, params, PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false}), proofData);

        uint256 balanceAfter0 = MockERC20(Currency.unwrap(key.currency0)).balanceOf(address((this)));
        uint256 balanceAfter1 = MockERC20(Currency.unwrap(key.currency1)).balanceOf(address((this)));

        assertEq(recipient.balance, 0);
        assertEq(1e18, balanceBefore0 - balanceAfter0);
        assertEq(address(mixer).balance, 0);

        assertTrue(hook.isSpent(nullifierHash)); // Nullifier should be marked as spent
    }

    function test_token_deposit() public {
        // Generate commitment
        (bytes32 commitment, bytes32 nullifier, bytes32 secret) = _getCommitment();

        // Mint some tokens to the test contract
        MockERC20(Currency.unwrap(token0)).mint(address(this), 10e18);

        // Approve tokens
        MockERC20(Currency.unwrap(token0)).approve(address(hook), 10e18);

        // Record balances before deposit
        uint256 hookETHBefore = address(hook).balance;
        uint256 userTokensBefore = MockERC20(Currency.unwrap(token0)).balanceOf(address(this));

        // Make deposit
        hook.deposit(token0, 1e18, commitment);

        // Verify deposit succeeded
        assertTrue(hook.commitments(commitment));

        // Verify balances changed correctly
        assertEq(address(hook).balance - hookETHBefore, 1 ether);
        assertEq(userTokensBefore - MockERC20(Currency.unwrap(token0)).balanceOf(address(this)), 1e18);
    }
}
