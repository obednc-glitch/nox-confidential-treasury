# Nox · nox-protocol-contracts

[![License](https://img.shields.io/badge/license-BUSL--1.1-blue)](./LICENSE)
[![Docs](https://img.shields.io/badge/docs-nox--protocol-purple)](https://docs.iex.ec)
[![Discord](https://img.shields.io/badge/chat-Discord-5865F2)](https://discord.com/invite/5TewNUnJHN)
[![Tag](https://img.shields.io/github/v/tag/iExec-Nox/nox-protocol-contracts?label=tag)](https://github.com/iExec-Nox/nox-protocol-contracts/releases)
[![npm](https://img.shields.io/npm/v/@iexec-nox/nox-protocol-contracts?label=npm)](https://www.npmjs.com/package/@iexec-nox/nox-protocol-contracts)
[![codecov](https://codecov.io/gh/iExec-Nox/nox-protocol-contracts/graph/badge.svg?token=8uANxipzVv)](https://codecov.io/gh/iExec-Nox/nox-protocol-contracts)

> Solidity contracts for the Nox protocol: manage encrypted handles, validate proofs, and trigger confidential computations.

## Table of Contents

- [Nox · nox-protocol-contracts](#nox--nox-protocol-contracts)
    - [Table of Contents](#table-of-contents)
    - [Overview](#overview)
    - [Prerequisites](#prerequisites)
    - [Getting Started](#getting-started)
    - [Environment Variables](#environment-variables)
    - [Testing](#testing)
    - [Deployment](#deployment)
    - [Verification](#verification)
    - [Configuration notes](#configuration-notes)
    - [Related Repositories](#related-repositories)
    - [Contributing](#contributing)
        - [Code style](#code-style)
    - [License](#license)

## Overview

**nox-protocol-contracts** is the Solidity layer of the Nox protocol. It provides:

- **NoxCompute**: the main UUPS-upgradeable contract that manages the Access Control List (ACL) for encrypted handles, validates handle proofs issued by a trusted gateway, facilitates plaintext-to-encrypted conversions, and triggers off-chain TEE computations through event emissions.
- **INoxCompute**: the public interface consumed by application contracts and off-chain services.
- **Nox SDK library** (`contracts/sdk/Nox.sol`): a convenience wrapper that resolves the NoxCompute proxy address per chain and exposes typed helper functions for application contracts.

## Prerequisites

- Node.js >= 24 (see `.nvmrc`)
- pnpm >= 10 (see `packageManager` in `package.json`)
- Hardhat >= 3

## Getting Started

```bash
git clone https://github.com/iExec-Nox/nox-protocol-contracts.git
cd nox-protocol-contracts

# Use the correct Node version
nvm install && nvm use

# Install dependencies
pnpm install

# Build contracts
pnpm run build
```

## Environment Variables

| Variable            | Description                                    | Required          | Default |
| ------------------- | ---------------------------------------------- | ----------------- | ------- |
| `RPC_URL`           | JSON-RPC endpoint for the target network       | For remote deploy | -       |
| `PRIVATE_KEY`       | Deployer private key                           | For remote deploy | -       |
| `ETHERSCAN_API_KEY` | API key for contract verification on Etherscan | For verification  | -       |

## Testing

```bash
# Run all tests (unit + integration)
pnpm run test

# Run tests with gas stats
pnpm run test:gas

# Run coverage
pnpm run coverage
```

## Deployment

The default network is a local EDR simulation. For external networks, set `RPC_URL` and `PRIVATE_KEY`:

```bash
# Local deploy
pnpm run deploy

# Production deploy (optimizer + viaIR)
pnpm run deploy:production

# Upgrade an existing proxy
pnpm run upgrade
```

## Verification

Verify deployed contracts on Etherscan. Requires `ETHERSCAN_API_KEY`:

```bash
pnpm run verify arbitrumSepolia --network arbitrumSepolia
```

## Configuration notes

- CREATE2 salt is defined in [`config/config.ts`](config/config.ts).
- Default owner addresses and KMS public keys per network are also defined in [`config/config.ts`](config/config.ts).
- The SDK constants in [`contracts/sdk/Nox.sol`](contracts/sdk/Nox.sol) must match the deployed proxy addresses.
- OpenZeppelin manifest files in `.openzeppelin/` track proxy deployments.

## Related Repositories

| Repository                                                                      | Description                                         |
| ------------------------------------------------------------------------------- | --------------------------------------------------- |
| [nox-handle-sdk](https://github.com/iExec-Nox/nox-handle-sdk)                   | TypeScript SDK for handle encryption/decryption     |
| [nox-offchain-deployment](https://github.com/iExec-Nox/nox-offchain-deployment) | Off-chain services (gateway, KMS, runner, ingestor) |

## Contributing

Contributions are welcome. Please open an issue first to discuss your proposed changes.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

### Code style

```bash
# Format all files
pnpm run format

# Check formatting
pnpm run format:check
```

## License

The Nox Protocol source code is released under the [Business Source License 1.1 (BUSL-1.1)](./LICENSE).

The license will automatically convert to the MIT License under the conditions described in the LICENSE file.

The full text of the MIT License is provided in the [LICENSE-MIT](./LICENSE-MIT) file.

Some files are dual-licensed under MIT:

- All files in `contracts/interfaces/`, `contracts/utils/`, `contracts/sdk/` may also be licensed under MIT (as indicated in their SPDX headers).
