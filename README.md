# UniStorm: Privacy-Preserving Swaps on Uniswap v4

![DALL·E 2024-12-08 08 17 39 - A modern, vectorized logo blending Uniswap's iconic unicorn emblem with the swirling tornado design of Tornado Cash  The unicorn emerges dynamically f-min 2](https://github.com/user-attachments/assets/b3febd84-30b2-4bb8-9f41-d4910dad01e5)




Deck: https://gamma.app/docs/UniStorm-t4964wzmw9vl1hp

---

## Project Overview  

**UniStorm** is a privacy-preserving protocol built on **Uniswap V4** that combines the power of zero-knowledge proofs inspired by **Tornado Cash**. It enables private token swaps while maintaining the security and efficiency of Uniswap's liquidity pools.

---

## Overview  

UniStorm extends Tornado Cash's privacy mechanism to work with Uniswap V4's hook system, creating a hybrid protocol that allows users to perform **private token swaps**. The protocol uses **zero-knowledge proofs (ZKPs)** to break the on-chain link between deposit and withdrawal addresses while leveraging Uniswap V4's liquidity pools for token exchanges.

---

## Technical Architecture  

### Core Components  

1. **Privacy Mechanism**  
   - Implements **Tornado Cash's commitment-nullifier scheme**  
   - Uses a **Merkle tree** to store deposit commitments  
   - Employs **zero-knowledge proofs** for private withdrawals  
   - Maintains **denomination pools** for standardized amounts  

2. **Uniswap V4 Integration**  
   - Implements **BaseHook** for custom swap logic  
   - Manages liquidity through **hook-controlled deposits**  
   - Handles **currency settlement** and pool state updates  
   - Provides both **private** and **public swap paths**  

---

### Key Data Structures  

```solidity
struct Deposits {
    uint256 amount;
    bytes32 commitment;
    bool isDeposited;
    Currency token;
    uint256 timestamp;
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
```

### Technical Flow

Protocol Flow
1. Deposit Process
- User generates random nullifier and secret values.
- Creates a commitment (hash of nullifier and secret).
- Deposits tokens along with the commitment.
- Protocol converts tokens to ETH if necessary.
- Commitment is stored in the Merkle tree.
- Deposit details are recorded with a timestamp.

2. Private Swap Process
- User generates a zero-knowledge proof of deposit ownership.
- Submits proof along with desired swap parameters.
- Protocol verifies:
    - Proof validity
    - Nullifier hasn't been spent
    - Merkle root is valid

- If verification succeeds:
    - Marks nullifier as spent
    - Converts ETH back to tokens
    - Executes swap through Uniswap V4
    - Updates pool state
    - Settles currencies


Security Features
Zero-Knowledge Privacy

- Breaks on-chain links between deposits and withdrawals
     - Uses Groth16 proof system
        Implements nullifier tracking to prevent double-spending
        Pool Security

    -   Enforces hook-controlled liquidity additions
        Maintains standardized denomination amounts
        Implements reentrancy protection
        Verifies all proofs before execution
        Economic Security




#Key Functions
 - `deposit(Currency token, uint256 amount, bytes32 commitment)`

        Handles initial token deposits
        Converts tokens to ETH if necessary
        Stores commitment in Merkle tree

- `beforeSwap(address sender, PoolKey key, IPoolManager.SwapParams params, bytes data)`

    Routes between private and public swaps
    Handles proof verification for private swaps
    Manages currency settlements

- `verifyProofAndNullifier(SwapState memory state)`
    
    Validates zero-knowledge proofs
    Checks nullifier status
    Verifies Merkle root



## Installation & Setup  

### Clone the Repository  
```bash
git clone https://github.com/ChinmayGopal931/UniStorm.git

## Installation

Clone this repository

```bash
git clone https://github.com/ChinmayGopal931/UniStorm.git
```

Install dependencies:

```bash
forge install
```

```bashs
yarn
```

## Usage

### Compiling circom circuits

The main workflow of this repo is:

1. Compile circuits to generate circuit artifacts
2. Perform a powers of tau ceremony
3. Generate proving and verification keys `/circuit_artifacts` and `src/Verifier.sol`

These three steps are written as bash commands in the [makefile](https://github.com/chinmaygopal931/UniStorm/blob/main/makefile). Run the following to perform these steps:

```bash
make all
```

This will create a `/circuit_artifacts` folder that contains everything needed to run tests.

### Running tests


Run the following command to run tests (_after_ you have generated circuit artifacts):

```bash
forge test
```
<img width="591" alt="Screenshot 2024-12-08 at 8 47 29 AM" src="https://github.com/user-attachments/assets/7b5905a7-d811-4601-84ac-be30c29aa998">


## Credits

Tornado Cash rebuilt by https://github.com/nkrishang here https://github.com/nkrishang/tornado-cash-rebuilt/

