# Balancer V3 Angstrom Router and Hook

A specialized router and hook system for Balancer V3 that implements node-based access control and block-level unlocking mechanisms for Angstrom pools.

## Overview

The Angstrom Router is a combination of a batch router and hook that provides controlled access to Angstrom pools within the Balancer V3 ecosystem. It ensures that only registered nodes can perform swaps and unbalanced liquidity operations before the network is unlocked for a given block, maintaining price consistency with off-chain computations.

## Key Features

### 🔐 Node-Based Access Control

- Only registered Angstrom nodes can perform the first swap and/or liquidity transaction (before network unlock)
- Node registration is managed through permissioned `registerNode` and `deregisterNode` functions
- Prevents unauthorized access to locked pools

### 🔓 Block-Level Unlocking

- The network can only be unlocked once per block
- Unlocking is global - once unlocked, all pools accept operations from any router

### 🔄 Dual Operation Modes

- **Router Mode**: Direct swaps against pools, as a registered node (no signature required)
- **Hook Mode**: Operations through any router with cryptographic signature verification (node registration is still required)

### 📊 Comprehensive Swap Support

- Exact amount in swaps (`swapExactIn`)
- Exact amount out swaps (`swapExactOut`)
- Query functions for both swap types
- Support for multi-hop routing through multiple pools

### 🏊 Liquidity Hooks for pools

- Proportional liquidity operations (no unlock required)
- Unbalanced liquidity operations (requires network unlock)
- Hook-based validation for all liquidity operations

## Requirements

- Node.js v18.x (we recommend using nvm to install it)
- Yarn v4.x
- Foundry v1.0.0

## Installation

If it's the first time running the project, run `sh ./scripts/install-fresh.sh` to install the dependencies and build the project. It will download and compile the V3 monorepo, creating node_modules folders in the library. (These folders will be needed to use the monorepo as a submodule of the angstrom project.)

## Testing

After installing the dependencies, run `yarn test:forge` to run forge tests. Also, run `yarn coverage` to generate a coverage report.

## Contributing

This project is part of the Balancer ecosystem. Please refer to the main Balancer repository for contribution guidelines.
