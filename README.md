# Multi-Chain Wallet

A secure, non-custodial desktop application for managing Ethereum (ETH), Bitcoin (BTC), Solana (SOL), Polygon, and Avalanche wallets, built with Python and PyQt5. Supports wallet creation, balance checks, transactions, token swaps, portfolio tracking, and QR code generation.

## Features

- **Non-Custodial**: Users control private keys, encrypted with a strong password.
- **Multi-Chain Support**: Manage ETH (Mainnet/Sepolia), Polygon, Avalanche, SOL (Devnet), BTC (Mainnet/Testnet).
- **Wallet Creation**: Generates a 12-word BIP-39 mnemonic for all chains.
- **Secure Storage**: Encrypts wallet data with AES-256, PBKDF2, and random salt.
- **Blockchain Interaction**: Uses Infura (ETH/Polygon/Avalanche), `solana-py` (Solana), and `bitcoinlib` (BTC).
- **GUI**: PyQt5 interface with tabs for wallet, sending, swapping, history, and portfolio.
- **Security**:
  - Password strength validation (≥8 characters, letters, numbers, symbols).
  - Random salt encryption.
  - Two-word mnemonic confirmation.
  - Input validation for addresses and amounts.
- **Usability**:
  - Copy wallet address to clipboard.
  - Real-time ETH/BTC/SOL/Polygon prices in USD (via CoinGecko).
  - Transaction history with Etherscan/Polygonscan/Blockchain.com links or RPC fallback.
  - Customizable QR code colors (requires `qrcode>=7.0`).
  - Portfolio tracking across chains (requires Bitquery API key).
  - Token swapping (stubbed, requires 1inch/Orca integration).
- **Logging**: Debug/error logs in `~/.wallet/wallet.log`.
- **EXE Conversion**: Package as Windows/macOS/Linux binaries with PyInstaller.

## Prerequisites

- **Python**: 3.8 or higher
- **Dependencies**:
  ```bash
  pip install pyqt5 web3 mnemonic cryptography qrcode>=7.0 pillow requests bitcoinlib solana
  ```
- **API Keys**:
  - **Infura**: Sign up at [infura.io](https://infura.io) for ETH/Polygon/Avalanche.
  - **Etherscan/Polygonscan**: Optional, for ETH/Polygon transaction history ([etherscan.io](https://etherscan.io), [polygonscan.com](https://polygonscan.com)).
  - **Bitquery**: Optional, for portfolio tracking ([bitquery.io](https://bitquery.io)).
  - **1inch**: Optional, for token swaps ([1inch.io](https://1inch.io)).
- **Testnet Funds**:
  - ETH: [faucetlink.to/sepolia](https://faucetlink.to/sepolia)
  - BTC: [testnet-faucet.com](https://testnet-faucet.com)
  - SOL: [solfaucet.com](https://solfaucet.com)
  - Polygon: [faucet.polygon.technology](https://faucet.polygon.technology)
- **For EXE Conversion**:
  ```bash
  pip install pyinstaller pyarmor
  ```

## Installation

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd multi-chain-wallet
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   Or:
   ```bash
   pip install pyqt5 web3 mnemonic cryptography qrcode>=7.0 pillow requests bitcoinlib solana
   ```

3. **Set API Keys**:
   ```bash
   # Linux/macOS
   export INFURA_API_KEY=your_infura_key_here
   export BITQUERY_API_KEY=your_bitquery_key_here
   export ONEINCH_API_KEY=your_1inch_key_here
   # Windows
   set INFURA_API_KEY=your_infura_key_here
   set BITQUERY_API_KEY=your_bitquery_key_here
   set ONEINCH_API_KEY=your_1inch_key_here
   ```
   - Update `YourApiKeyToken` in `TRANSACTION_HISTORY_API` in `wallet_v1.4.py` for Etherscan/Polygonscan.

## Usage

1. **Run the Application**:
   ```bash
   python wallet_v1.4.py
   ```

2. **Create a Wallet**:
   - Enter a strong password (min 8 chars, letters, numbers, symbols).
   - Save the 12-word mnemonic securely and confirm two random words.
   - View addresses, balances, and QR codes for all chains.

3. **Load a Wallet**:
   - Enter the password to load addresses and balances.

4. **Send Transactions**:
   - Select a network (ETH-Sepolia, ETH-Mainnet, Polygon, Avalanche, SOL-Devnet, BTC-Testnet, BTC-Mainnet).
   - Enter recipient address and amount, then send.
   - View transactions on explorers (Etherscan, Polygonscan, Blockchain.com).

5. **Swap Tokens**:
   - Use the “Swap” tab (requires 1inch/Orca setup).
   - Enter from/to tokens and amount (stubbed).

6. **View Transaction History**:
   - Check the “History” tab (Etherscan/Polygonscan API or RPC for ETH/Polygon; `bitcoinlib` for BTC).

7. **View Portfolio**:
   - Check the “Portfolio” tab for cross-chain balances (requires Bitquery API key).

8. **Switch Networks**:
   - Use the dropdown to switch networks. Test on testnets/Devnet before Mainnet.

9. **Debugging**:
   - Check `~/.wallet/wallet.log` for logs.

## Converting to a Standalone Binary

1. **Install PyInstaller and PyArmor**:
   ```bash
   pip install pyinstaller pyarmor
   ```

2. **Obfuscate Code** (optional):
   ```bash
   pyarmor obfuscate wallet_v1.4.py
   ```

3. **Create Binary**:
   - **Windows**:
     ```bash
     pyinstaller --onefile --windowed wallet_v1.4.py
     ```
   - **macOS/Linux**: Run on respective OS:
     ```bash
     pyinstaller --onefile --windowed wallet_v1.4.py
     ```

4. **Run Binary**:
   ```bash
   set INFURA_API_KEY=your_infura_key_here
   dist\wallet_v1.4
   ```

## Security Considerations

- **Mnemonic Phrase**: Store offline securely. Loss results in permanent fund loss.
- **Password**: Use a strong password. If lost, mnemonic is required for recovery.
- **Testnets First**: Test on Sepolia/Devnet/BTC-Testnet before Mainnet.
- **Auditing**: Audit code for production use (e.g., by OpenZeppelin).
- **API Keys**: Keep all API keys secret.
- **Obfuscation**: Use PyArmor for binary distribution.

## Testing

1. **Set Up**:
   - Set `INFURA_API_KEY`, `BITQUERY_API_KEY`, `ONEINCH_API_KEY`, and Etherscan/Polygonscan keys.
   - Get test funds for ETH, BTC, SOL, Polygon.

2. **Test Features**:
   - Create/load wallet, verify addresses.
   - Check balances, prices, and portfolio.
   - Send transactions and verify history.
   - Test network switching, QR code customization, and address copying.
   - Verify logs in `~/.wallet/wallet.log`.

3. **Test Binaries**:
   - Build and test on Windows, macOS, Linux.

## Limitations and Future Improvements

- **API Keys**: Etherscan/Polygonscan for transaction history; Bitquery for portfolio; 1inch/Orca for swaps.
- **Solana Transactions**: Implement transaction sending and history.
- **Multisig Wallets**: Deploy and integrate multisig smart contract.
- **Bitcoin Nodes**: `bitcoinlib` may require reliable nodes.
- **Features**: Add DeFi/NFT support, more chains (e.g., Binance Smart Chain).

## Contributing

Submit pull requests or issues to the repository. Ensure changes maintain security and compatibility.

## License

MIT License. See the `LICENSE` file.

## Disclaimer

Use at your own risk. Test thoroughly on testnets before using with real funds. Developers are not responsible for fund loss.
