# UniStorm

Tornado Cash is a non-custodial Ethereum and ERC20 privacy solution based on zkSNARKs.

The Original Tornado Cash repository (https://github.com/tornadocash/tornado-core) 

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

## Credits

Tornado Cash rebuilt by https://github.com/nkrishang here https://github.com/nkrishang/tornado-cash-rebuilt/

