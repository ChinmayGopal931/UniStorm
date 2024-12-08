// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract TokenETHSwapper {
    // The ERC20 token that will be swapped with ETH
    IERC20 public immutable token0;

    // Event to track swaps
    event SwapTokenForETH(address indexed user, uint256 amount);
    event SwapETHForToken(address indexed user, uint256 amount);

    constructor(address _token0) {
        token0 = IERC20(_token0);
    }

    // Function to swap tokens for ETH
    function swapTokenForETH(uint256 amount) external {
        // Transfer tokens from user to this contract
        require(token0.transferFrom(msg.sender, address(this), amount), "Token transfer failed");

        // Send ETH to user
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "ETH transfer failed");

        emit SwapTokenForETH(msg.sender, amount);
    }

    // Function to swap ETH for tokens
    function swapETHForToken() external payable {
        uint256 amount = msg.value;

        // Transfer tokens to user
        require(token0.transfer(msg.sender, amount), "Token transfer failed");

        emit SwapETHForToken(msg.sender, amount);
    }

    // Allow contract to receive ETH
    receive() external payable {}
}
