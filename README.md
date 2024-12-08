# UniStorm: Privacy-Preserving Swaps on Uniswap v4

## Project Overview  
**UniStorm** enables private token swaps by combining Uniswap v4's hook system with zero-knowledge proofs. Built on the privacy foundations of Tornado Cash, it allows users to trade tokens without revealing their identity or trading patterns.

---


## Core Benefits  

### Privacy  
- Ensures **complete trading anonymity** by breaking the on-chain link between deposits and swaps using zero-knowledge proofs.

### Security  
- Built on **Uniswap v4's battle-tested smart contracts** and enhanced with Tornado Cash's proven privacy technology.  
- Provides institutional-grade security for private trading.

### Permissionless & Composable  
- Any token tradable on Uniswap v4 can be privately swapped through UniStorm.  
- No gatekeepers or restrictions.

---


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
3. Generate zkey and verifier Solidity smart contract

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

