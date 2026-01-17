import sys
import os
import json
import qrcode
import random
import time
import logging
from PyQt5 import QtWidgets, QtCore, QtGui
from mnemonic import Mnemonic
from web3 import Web3
from eth_account import Account
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import requests
from datetime import datetime
from threading import Thread
from bitcoinlib.wallets import Wallet
from bitcoinlib.services.services import Service
from solana.rpc.api import Client as SolanaClient
from solana.keypair import Keypair
from solana.publickey import PublicKey

# --- Configuration ---
INFURA_API_KEY = os.getenv("INFURA_API_KEY", "c1813e31464648bf9b78c90b6a6c406b")
BITQUERY_API_KEY = os.getenv("BITQUERY_API_KEY", None)  # Optional, for portfolio tracking
ONEINCH_API_KEY = os.getenv("ONEINCH_API_KEY", None)  # Optional, for token swaps

NETWORKS = {
    "ETH-Sepolia": {"url": f"https://sepolia.infura.io/v3/{INFURA_API_KEY}", "chain_id": 11155111, "type": "EVM"},
    "ETH-Mainnet": {"url": f"https://mainnet.infura.io/v3/{INFURA_API_KEY}", "chain_id": 1, "type": "EVM"},
    "Polygon-Mainnet": {"url": "https://polygon-rpc.com", "chain_id": 137, "type": "EVM"},
    "Avalanche-C-Chain": {"url": "https://api.avax.network/ext/bc/C/rpc", "chain_id": 43114, "type": "EVM"},
    "SOL-Devnet": {"url": "https://api.devnet.solana.com", "type": "Solana"},
    "BTC-Testnet": {"nodes": ["testnet-seed.bitcoin.jonasschnelli.ch", "seed.tbtc.petertodd.org"], "type": "Bitcoin"},
    "BTC-Mainnet": {"nodes": ["seed.bitcoin.sipa.be", "dnsseed.bluematt.me"], "type": "Bitcoin"}
}
WALLET_FILE = os.path.expanduser("~/.wallet/wallet.dat")
WALLET_LOG = os.path.expanduser("~/.wallet/wallet.log")
PRICE_API = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum,bitcoin,solana,polygon&vs_currencies=usd"
TRANSACTION_HISTORY_API = {
    "ETH-Sepolia": "https://api-sepolia.etherscan.io/api?module=account&action=txlist&address={}&startblock=0&endblock=99999999&sort=asc&apikey=YourApiKeyToken",
    "ETH-Mainnet": "https://api-etherscan.io/api?module=account&action=txlist&address={}&startblock=0&endblock=99999999&sort=asc&apikey=YourApiKeyToken",
    "Polygon-Mainnet": "https://api.polygonscan.com/api?module=account&action=txlist&address={}&startblock=0&endblock=99999999&sort=asc&apikey=YourApiKeyToken",
    "Avalanche-C-Chain": None  # No direct API; use RPC
}
BITQUERY_PORTFOLIO_QUERY = """
query($addresses: [String!]) {
  EVM(network: [eth, polygon, avalanche], addresses: $addresses) {
    address {
      address
      balances {
        currency { symbol }
        value
      }
    }
  }
  Solana(network: solana) {
    address(addresses: $addresses) {
      address
      balance
    }
  }
  Bitcoin(network: bitcoin) {
    address(addresses: $addresses) {
      address
      balance
    }
  }
}
"""
ONEINCH_SWAP_API = "https://api.1inch.io/v5.0/{chain_id}/swap"

# Create directory for log file
os.makedirs(os.path.dirname(WALLET_LOG), exist_ok=True)

# --- Logging Setup ---
logging.basicConfig(
    filename=WALLET_LOG,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logging.info("Logging initialized")

# Enable HD wallet features for Ethereum
Account.enable_unaudited_hdwallet_features()

# --- Multi-chain Wallet Class ---
class MultiChainWallet:
    def __init__(self):
        self.w3 = None
        self.btc_service = None
        self.solana_client = None
        self.wallet_data = {}
        self.active_chain = "ETH-Sepolia"  # Default network
        self.account = None
        self.fernet = None
        self.connect(self.active_chain)
        logging.info("Initialized MultiChainWallet with default network: ETH-Sepolia")

    def connect(self, network_name):
        self.active_chain = network_name
        chain_type = NETWORKS[network_name]["type"]
        logging.info(f"Connecting to network: {network_name}")
        
        if chain_type == "EVM":
            self.w3 = Web3(Web3.HTTPProvider(NETWORKS[network_name]["url"]))
            if not self.w3.is_connected():
                logging.error(f"Failed to connect to {network_name} node.")
                raise ConnectionError(f"Failed to connect to {network_name} node.")
            self.btc_service = None
            self.solana_client = None
            self.account = self.wallet_data.get(network_name.split('-')[0], {}).get('address')
        elif chain_type == "Solana":
            self.solana_client = SolanaClient(NETWORKS[network_name]["url"])
            self.w3 = None
            self.btc_service = None
            self.account = self.wallet_data.get('SOL', {}).get('address')
        elif chain_type == "Bitcoin":
            self.btc_service = Service(network=NETWORKS[network_name]["nodes"][0])
            for node in NETWORKS[network_name]["nodes"]:
                try:
                    self.btc_service = Service(network=NETWORKS[network_name]["nodes"][0])
                    break
                except Exception as e:
                    logging.warning(f"Failed to connect to Bitcoin node {node}: {str(e)}")
                    continue
            if not self.btc_service:
                logging.error(f"Failed to connect to any Bitcoin node for {network_name}.")
                raise ConnectionError(f"Failed to connect to any Bitcoin node for {network_name}.")
            self.w3 = None
            self.solana_client = None
            self.account = self.wallet_data.get('BTC', {}).get('address')
        logging.info(f"Connected to {network_name} successfully.")

    def generate_new_wallet(self, password):
        logging.info("Generating new wallet")
        mnemo = Mnemonic("english")
        mnemonic_phrase = mnemo.generate(strength=128)
        
        # Derive Ethereum/Polygon/Avalanche accounts
        eth_account = Account.from_mnemonic(mnemonic_phrase)
        
        # Derive Bitcoin wallet
        btc_network = 'testnet' if self.active_chain.startswith('BTC-Testnet') else 'bitcoin'
        btc_wallet_name = f"wallet_{mnemonic_phrase.replace(' ', '_')[:10]}"
        btc_wallet = Wallet.create(btc_wallet_name, keys=mnemonic_phrase, network=btc_network)
        btc_address = btc_wallet.get_key().address
        btc_private_key = btc_wallet.get_key().key_private
        btc_private_key_str = btc_private_key.hex() if isinstance(btc_private_key, bytes) else btc_private_key
        
        # Derive Solana account
        solana_keypair = Keypair.from_seed(mnemo.to_seed(mnemonic_phrase)[:32])
        solana_address = str(solana_keypair.public_key)
        
        self.wallet_data = {
            "mnemonic": mnemonic_phrase,
            "ETH": {"address": eth_account.address, "private_key": eth_account.key.hex()},
            "Polygon": {"address": eth_account.address, "private_key": eth_account.key.hex()},
            "Avalanche": {"address": eth_account.address, "private_key": eth_account.key.hex()},
            "BTC": {"address": btc_address, "wallet_name": btc_wallet_name, "private_key": btc_private_key_str},
            "SOL": {"address": solana_address, "private_key": base64.b64encode(solana_keypair.secret_key).decode()}
        }
        
        self.save_wallet(password)
        logging.info("New wallet generated successfully")
        return mnemonic_phrase

    def save_wallet(self, password):
        logging.info("Saving wallet")
        try:
            salt = os.urandom(16)
            key = self.derive_key(password, salt)
            self.fernet = Fernet(key)
            data_to_save = json.dumps(self.wallet_data)
            encrypted_data = self.fernet.encrypt(data_to_save.encode())
            
            wallet_dir = os.path.dirname(WALLET_FILE)
            os.makedirs(wallet_dir, exist_ok=True)
            
            encrypted_bundle = {
                'salt': base64.b64encode(salt).decode(),
                'data': base64.b64encode(encrypted_data).decode()
            }
            with open(WALLET_FILE, 'w') as f:
                json.dump(encrypted_bundle, f)
            logging.info(f"Wallet saved to {WALLET_FILE}")
            return True
        except TypeError as e:
            logging.error(f"JSON serialization error in save_wallet: {str(e)}")
            for key, value in self.wallet_data.items():
                logging.debug(f"wallet_data[{key}]: {type(value)} - {value}")
                if isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        logging.debug(f"wallet_data[{key}][{subkey}]: {type(subvalue)} - {subvalue}")
            raise Exception(f"Failed to save wallet: {str(e)}")
        except Exception as e:
            logging.error(f"Failed to save wallet: {str(e)}")
            raise Exception(f"Failed to save wallet: {str(e)}")

    def load_wallet(self, password):
        logging.info(f"Loading wallet from {WALLET_FILE}")
        if not os.path.exists(WALLET_FILE):
            logging.warning(f"Wallet file {WALLET_FILE} does not exist")
            return False

        try:
            with open(WALLET_FILE, 'r') as f:
                encrypted_bundle = json.load(f)
            salt = base64.b64decode(encrypted_bundle['salt'])
            key = self.derive_key(password, salt)
            self.fernet = Fernet(key)
            decrypted_data = self.fernet.decrypt(base64.b64decode(encrypted_bundle['data']))
            self.wallet_data = json.loads(decrypted_data.decode())
            
            if 'BTC' in self.wallet_data and 'wallet_name' in self.wallet_data['BTC']:
                btc_wallet_name = self.wallet_data['BTC']['wallet_name']
                btc_network = 'testnet' if self.active_chain.startswith('BTC-Testnet') else 'bitcoin'
                try:
                    self.btc_wallet_instance = Wallet(btc_wallet_name)
                except Exception:
                    self.btc_wallet_instance = Wallet.create(
                        btc_wallet_name, keys=self.wallet_data['mnemonic'], network=btc_network
                    )
                logging.info("Bitcoin wallet initialized")
            logging.info("Wallet loaded successfully")
            return True
        except Exception as e:
            logging.error(f"Error loading wallet: {str(e)}")
            return False

    def derive_key(self, password: str, salt: bytes):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def get_balance(self):
        chain_type = NETWORKS[self.active_chain]["type"]
        chain_name = self.active_chain.split('-')[0]
        logging.info(f"Fetching balance for {chain_name}")
        
        if chain_type == "EVM":
            address = self.wallet_data.get(chain_name, {}).get('address')
            if self.w3 and address:
                balance_wei = self.w3.eth.get_balance(address)
                balance = self.w3.from_wei(balance_wei, 'ether')
                logging.info(f"{chain_name} balance: {balance} {chain_name}")
                return balance
            return 0
        elif chain_type == "Solana":
            address = self.wallet_data.get('SOL', {}).get('address')
            if self.solana_client and address:
                balance_lamports = self.solana_client.get_balance(PublicKey(address))['result']['value']
                balance = balance_lamports / 1_000_000_000  # Convert lamports to SOL
                logging.info(f"SOL balance: {balance} SOL")
                return balance
            return 0
        elif chain_type == "Bitcoin":
            wallet_name = self.wallet_data.get('BTC', {}).get('wallet_name')
            if wallet_name:
                w = Wallet(wallet_name)
                w.scan()
                balance = w.balance() / 1e8  # Convert satoshis to BTC
                logging.info(f"BTC balance: {balance} BTC")
                return balance
        return 0

    def send_transaction(self, to_address, amount):
        chain_type = NETWORKS[self.active_chain]["type"]
        chain_name = self.active_chain.split('-')[0]
        logging.info(f"Sending transaction: {amount} {chain_name} to {to_address}")
        
        if chain_type == "EVM":
            from_address = self.wallet_data[chain_name]['address']
            private_key = self.wallet_data[chain_name]['private_key']
            try:
                nonce = self.w3.eth.get_transaction_count(from_address)
                try:
                    fee_history = self.w3.eth.fee_history(1, 'latest', reward_percentiles=[20])
                    base_fee = fee_history['baseFeePerGas'][-1]
                    priority_fee = self.w3.to_wei('2', 'gwei')
                    max_fee = base_fee + priority_fee
                except Exception:
                    max_fee = self.w3.eth.gas_price
                    priority_fee = self.w3.to_wei('2', 'gwei')

                transaction = {
                    'type': '0x2',
                    'nonce': nonce,
                    'to': self.w3.to_checksum_address(to_address),
                    'value': self.w3.to_wei(amount, 'ether'),
                    'maxFeePerGas': max_fee,
                    'maxPriorityFeePerGas': priority_fee,
                    'chainId': NETWORKS[self.active_chain]["chain_id"]
                }
                gas_estimate = self.w3.eth.estimate_gas(transaction)
                transaction['gas'] = gas_estimate
                signed_txn = self.w3.eth.account.sign_transaction(transaction, private_key)
                tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
                tx_hash_hex = self.w3.to_hex(tx_hash)
                logging.info(f"{chain_name} transaction sent: {tx_hash_hex}")
                return tx_hash_hex
            except Exception as e:
                logging.error(f"Failed to send {chain_name} transaction: {str(e)}")
                raise Exception(f"Failed to send transaction: {str(e)}")
        elif chain_type == "Solana":
            # Stub: Implement Solana transaction
            logging.info("Solana transaction sending not implemented yet")
            raise NotImplementedError("Solana transactions not implemented")
        elif chain_type == "Bitcoin":
            wallet_name = self.wallet_data['BTC']['wallet_name']
            w = Wallet(wallet_name)
            try:
                tx = w.send_to(to_address, amount * 1e8)
                logging.info(f"BTC transaction sent: {tx.txid}")
                return tx.txid
            except Exception as e:
                logging.error(f"Failed to send BTC transaction: {str(e)}")
                raise Exception(f"Failed to send transaction: {str(e)}")
        return None

    def get_transaction_history(self, use_api=True):
        chain_type = NETWORKS[self.active_chain]["type"]
        chain_name = self.active_chain.split('-')[0]
        logging.info(f"Fetching transaction history for {chain_name}")
        
        if chain_type == "EVM":
            address = self.wallet_data.get(chain_name, {}).get('address')
            if not address:
                logging.warning(f"No {chain_name} address found for transaction history")
                return []
            if use_api and TRANSACTION_HISTORY_API.get(self.active_chain):
                api_url = TRANSACTION_HISTORY_API[self.active_chain].format(address)
                try:
                    response = requests.get(api_url)
                    response.raise_for_status()
                    data = response.json()
                    if data['status'] == '1':
                        transactions = []
                        for tx in data['result']:
                            tx_type = "Sent" if tx['from'].lower() == address.lower() else "Received"
                            value_eth = self.w3.from_wei(int(tx['value']), 'ether')
                            timestamp = datetime.fromtimestamp(int(tx['timeStamp'])).strftime('%Y-%m-%d %H:%M:%S')
                            transactions.append({
                                'type': tx_type,
                                'amount': value_eth,
                                'timestamp': timestamp,
                                'hash': tx['hash']
                            })
                        logging.info(f"Fetched {len(transactions)} {chain_name} transactions via API")
                        return transactions
                except Exception as e:
                    logging.error(f"Error fetching {chain_name} transaction history via API: {str(e)}")
            # Fallback to RPC
            try:
                transactions = []
                block_number = self.w3.eth.block_number
                for block in range(max(0, block_number - 1000), block_number + 1):
                    block_data = self.w3.eth.get_block(block, full_transactions=True)
                    for tx in block_data['transactions']:
                        if 'from' in tx and 'to' in tx and (tx['from'].lower() == address.lower() or tx.get('to', '').lower() == address.lower()):
                            tx_type = "Sent" if tx['from'].lower() == address.lower() else "Received"
                            value_eth = self.w3.from_wei(tx['value'], 'ether')
                            timestamp = datetime.fromtimestamp(block_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                            transactions.append({
                                'type': tx_type,
                                'amount': value_eth,
                                'timestamp': timestamp,
                                'hash': self.w3.to_hex(tx['hash'])
                            })
                logging.info(f"Fetched {len(transactions)} {chain_name} transactions via RPC")
                return transactions
            except Exception as e:
                logging.error(f"Error fetching {chain_name} transaction history via RPC: {str(e)}")
                return []
        elif chain_type == "Solana":
            # Stub: Implement Solana transaction history
            logging.info("Solana transaction history not implemented yet")
            return []
        elif chain_type == "Bitcoin":
            wallet_name = self.wallet_data.get('BTC', {}).get('wallet_name')
            if not wallet_name:
                logging.warning("No BTC wallet name found for transaction history")
                return []
            w = Wallet(wallet_name)
            txs = w.transactions()
            transactions = []
            for tx in txs:
                tx_type = "Sent" if any(addr.address == w.get_key().address for addr in tx.inputs) else "Received"
                amount_btc = tx.value / 1e8
                timestamp = tx.date.strftime('%Y-%m-%d %H:%M:%S') if tx.date else "Unknown"
                transactions.append({
                    'type': tx_type,
                    'amount': amount_btc,
                    'timestamp': timestamp,
                    'hash': tx.txid
                })
            logging.info(f"Fetched {len(transactions)} BTC transactions")
            return transactions
        return []

    def get_address(self):
        chain_name = self.active_chain.split('-')[0]
        address = self.wallet_data.get(chain_name, {}).get('address', "")
        logging.info(f"Retrieved address for {chain_name}: {address}")
        return address

    def get_current_chain_symbol(self):
        return self.active_chain.split('-')[0]

    def get_portfolio(self):
        if not BITQUERY_API_KEY:
            logging.warning("Bitquery API key not set for portfolio tracking")
            return []
        addresses = {
            chain: data['address'] for chain, data in self.wallet_data.items() 
            if chain in ['ETH', 'Polygon', 'Avalanche', 'BTC', 'SOL'] and 'address' in data
        }
        try:
            response = requests.post(
                "https://graphql.bitquery.io",
                json={'query': BITQUERY_PORTFOLIO_QUERY, 'variables': {'addresses': list(addresses.values())}},
                headers={'X-API-KEY': BITQUERY_API_KEY}
            )
            response.raise_for_status()
            data = response.json()['data']
            portfolio = []
            for chain in ['EVM', 'Solana', 'Bitcoin']:
                for addr_data in data.get(chain, {}).get('address', []):
                    if chain == 'EVM':
                        for balance in addr_data['balances']:
                            portfolio.append({
                                'chain': chain,
                                'address': addr_data['address'],
                                'symbol': balance['currency']['symbol'],
                                'balance': balance['value']
                            })
                    else:
                        portfolio.append({
                            'chain': chain,
                            'address': addr_data['address'],
                            'symbol': chain[:3].upper(),
                            'balance': addr_data['balance']
                        })
            logging.info(f"Fetched portfolio with {len(portfolio)} entries")
            return portfolio
        except Exception as e:
            logging.error(f"Error fetching portfolio: {str(e)}")
            return []

    def swap_tokens(self, from_token, to_token, amount, chain_name):
        if chain_name == "SOL":
            logging.info("Solana token swapping not implemented yet")
            raise NotImplementedError("Solana token swapping not implemented")
        # Stub: Implement 1inch swap for EVM chains
        logging.info(f"Token swap {from_token} to {to_token} on {chain_name} not implemented yet")
        raise NotImplementedError("Token swapping not implemented")

# --- GUI Class ---
class WalletApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.wallet = MultiChainWallet()
        self.prices = {'ETH': 0.0, 'BTC': 0.0, 'SOL': 0.0, 'Polygon': 0.0}
        self.setWindowTitle("Multi-Chain Wallet")
        self.setGeometry(100, 100, 800, 500)
        self.init_ui()
        self.check_existing_wallet()
        self.start_price_update_thread()
        logging.info("WalletApp initialized")

    def init_ui(self):
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QtWidgets.QVBoxLayout(self.central_widget)

        self.tab_widget = QtWidgets.QTabWidget()
        self.main_layout.addWidget(self.tab_widget)
        
        # Wallet Tab
        self.wallet_tab = QtWidgets.QWidget()
        self.wallet_layout = QtWidgets.QVBoxLayout(self.wallet_tab)
        self.network_label = QtWidgets.QLabel("Select Network:")
        self.network_combo = QtWidgets.QComboBox()
        self.network_combo.addItems(list(NETWORKS.keys()))
        self.network_combo.currentTextChanged.connect(self.on_network_changed)
        self.wallet_layout.addWidget(self.network_label)
        self.wallet_layout.addWidget(self.network_combo)
        self.wallet_info_label = QtWidgets.QLabel("No wallet loaded.")
        self.wallet_info_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.wallet_layout.addWidget(self.wallet_info_label)
        self.qr_label = QtWidgets.QLabel()
        self.qr_label.setAlignment(QtCore.Qt.AlignCenter)
        self.wallet_layout.addWidget(self.qr_label)
        self.copy_address_button = QtWidgets.QPushButton("Copy Address")
        self.copy_address_button.clicked.connect(self.copy_address)
        self.copy_address_button.setEnabled(False)
        self.wallet_layout.addWidget(self.copy_address_button)
        self.qr_color_label = QtWidgets.QLabel("QR Code Colors:")
        self.qr_fill_color = QtWidgets.QComboBox()
        self.qr_fill_color.addItems(["Black", "Blue", "Red"])
        self.qr_back_color = QtWidgets.QComboBox()
        self.qr_back_color.addItems(["White", "LightGray", "Yellow"])
        self.wallet_layout.addWidget(self.qr_color_label)
        self.wallet_layout.addWidget(self.qr_fill_color)
        self.wallet_layout.addWidget(self.qr_back_color)
        self.tab_widget.addTab(self.wallet_tab, "Wallet")
        
        # Send Tab
        self.send_tab = QtWidgets.QWidget()
        self.send_layout = QtWidgets.QFormLayout(self.send_tab)
        self.to_address_input = QtWidgets.QLineEdit()
        self.to_address_input.setPlaceholderText("Recipient Address")
        self.send_layout.addRow("To Address:", self.to_address_input)
        self.amount_input = QtWidgets.QLineEdit()
        self.amount_input.setPlaceholderText("Amount")
        self.send_layout.addRow("Amount:", self.amount_input)
        self.send_button = QtWidgets.QPushButton("Send Transaction")
        self.send_button.clicked.connect(self.send_transaction)
        self.send_layout.addWidget(self.send_button)
        self.tx_result_label = QtWidgets.QLabel("")
        self.tx_result_label.setOpenExternalLinks(True)
        self.send_layout.addWidget(self.tx_result_label)
        self.tab_widget.addTab(self.send_tab, "Send")
        
        # Swap Tab
        self.swap_tab = QtWidgets.QWidget()
        self.swap_layout = QtWidgets.QFormLayout(self.swap_tab)
        self.from_token_input = QtWidgets.QLineEdit()
        self.from_token_input.setPlaceholderText("From Token (e.g., ETH)")
        self.swap_layout.addRow("From Token:", self.from_token_input)
        self.to_token_input = QtWidgets.QLineEdit()
        self.to_token_input.setPlaceholderText("To Token (e.g., USDC)")
        self.swap_layout.addRow("To Token:", self.to_token_input)
        self.swap_amount_input = QtWidgets.QLineEdit()
        self.swap_amount_input.setPlaceholderText("Amount")
        self.swap_layout.addRow("Amount:", self.swap_amount_input)
        self.swap_button = QtWidgets.QPushButton("Swap Tokens")
        self.swap_button.clicked.connect(self.swap_tokens)
        self.swap_layout.addWidget(self.swap_button)
        self.swap_result_label = QtWidgets.QLabel("")
        self.swap_result_label.setOpenExternalLinks(True)
        self.swap_layout.addWidget(self.swap_result_label)
        self.tab_widget.addTab(self.swap_tab, "Swap")
        
        # History Tab
        self.history_tab = QtWidgets.QWidget()
        self.history_layout = QtWidgets.QVBoxLayout(self.history_tab)
        self.history_table = QtWidgets.QTableWidget()
        self.history_table.setColumnCount(4)
        self.history_table.setHorizontalHeaderLabels(["Type", "Amount", "Timestamp", "Tx Hash"])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_layout.addWidget(self.history_table)
        self.tab_widget.addTab(self.history_tab, "History")
        
        # Portfolio Tab
        self.portfolio_tab = QtWidgets.QWidget()
        self.portfolio_layout = QtWidgets.QVBoxLayout(self.portfolio_tab)
        self.portfolio_table = QtWidgets.QTableWidget()
        self.portfolio_table.setColumnCount(4)
        self.portfolio_table.setHorizontalHeaderLabels(["Chain", "Address", "Symbol", "Balance"])
        self.portfolio_table.horizontalHeader().setStretchLastSection(True)
        self.portfolio_layout.addWidget(self.portfolio_table)
        self.tab_widget.addTab(self.portfolio_tab, "Portfolio")

    def check_existing_wallet(self):
        if os.path.exists(WALLET_FILE):
            self.load_wallet_dialog()
        else:
            self.create_wallet_dialog()

    def load_wallet_dialog(self):
        password, ok = QtWidgets.QInputDialog.getText(self, "Load Wallet", 
            "Enter your password:", QtWidgets.QLineEdit.Password)
        if ok and password:
            if self.wallet.load_wallet(password):
                self.statusBar().showMessage("Wallet loaded successfully!", 2000)
                self.on_network_changed(self.network_combo.currentText())
                self.copy_address_button.setEnabled(True)
                self.tab_widget.setTabEnabled(1, True)
                self.tab_widget.setTabEnabled(2, True)
            else:
                QtWidgets.QMessageBox.critical(self, "Error", "Incorrect password or corrupted wallet file.")
                self.load_wallet_dialog()
        else:
            logging.info("User cancelled wallet loading")
            sys.exit()

    def create_wallet_dialog(self):
        password, ok = QtWidgets.QInputDialog.getText(self, "Create Wallet", 
            "Enter a strong password (min 8 chars, letters, numbers, symbols):", 
            QtWidgets.QLineEdit.Password)
        if ok and password:
            if not self.is_password_strong(password):
                QtWidgets.QMessageBox.warning(self, "Error", 
                    "Password must be at least 8 characters and include letters, numbers, and symbols.")
                self.create_wallet_dialog()
                return
            try:
                mnemonic = self.wallet.generate_new_wallet(password)
                words = mnemonic.split()
                indices = random.sample(range(12), 2)
                for idx in indices:
                    word, ok = QtWidgets.QInputDialog.getText(self, "Confirm Mnemonic", 
                        f"Enter word #{idx + 1} of your mnemonic phrase:")
                    if not ok or word != words[idx]:
                        QtWidgets.QMessageBox.critical(self, "Error", 
                            f"Incorrect mnemonic word #{idx + 1}. Please save your mnemonic and try again.")
                        return
                self.wallet.save_wallet(password)
                QtWidgets.QMessageBox.warning(self, "CRITICAL: Save Your Mnemonic Phrase!",
                    f"Your new wallet has been created. The 12-word phrase below is the ONLY way to recover your funds:\n\n"
                    f"<b>{mnemonic}</b>\n\n"
                    "<b>WARNING:</b>\n"
                    " - Write it down and store it in a secure, offline location.\n"
                    " - NEVER share this phrase with anyone.\n"
                    " - NEVER store it digitally (e.g., in a text file, email, or cloud storage).\n"
                    " - If you lose this phrase, you lose your crypto forever.")
                self.statusBar().showMessage("Wallet created successfully!", 2000)
                self.on_network_changed(self.network_combo.currentText())
                self.copy_address_button.setEnabled(True)
                self.tab_widget.setTabEnabled(1, True)
                self.tab_widget.setTabEnabled(2, True)
            except Exception as e:
                logging.error(f"Failed to create wallet: {str(e)}")
                QtWidgets.QMessageBox.critical(self, "Error", f"Failed to create wallet: {str(e)}")
                self.create_wallet_dialog()
        else:
            logging.info("User cancelled wallet creation")
            sys.exit()

    def is_password_strong(self, password):
        return (len(password) >= 8 and
                any(c.isalpha() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password))

    def on_network_changed(self, network_name):
        try:
            self.wallet.connect(network_name)
            self.update_ui()
            self.update_balance()
            self.update_transaction_history()
            self.update_portfolio()
            self.statusBar().showMessage(f"Connected to {network_name} successfully.", 2000)
        except ConnectionError as e:
            logging.error(f"Connection error for {network_name}: {str(e)}")
            QtWidgets.QMessageBox.critical(self, "Connection Error", f"Could not connect to {network_name}. Error: {str(e)}")
            self.wallet_info_label.setText(f"Connection to {network_name} failed.")
        except Exception as e:
            logging.error(f"Error updating UI for {network_name}: {str(e)}")
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to update UI for {network_name}. Error: {str(e)}")
            self.wallet_info_label.setText(f"Error updating UI for {network_name}: {str(e)}")

    def update_ui(self):
        address = self.wallet.get_address()
        chain_symbol = self.wallet.get_current_chain_symbol()
        self.wallet_info_label.setText(f"Wallet Address: {address}\nBalance: 0.0 {chain_symbol}\nPrice: N/A")
        self.generate_qr(address)
        self.update_balance()

    def update_balance(self):
        try:
            balance = self.wallet.get_balance()
            address = self.wallet.get_address()
            chain_symbol = self.wallet.get_current_chain_symbol()
            price = self.prices.get(chain_symbol, 0.0)
            balance_usd = balance * price
            self.wallet_info_label.setText(
                f"Wallet Address: {address}\n"
                f"Balance: {balance:.6f} {chain_symbol}\n"
                f"Value: ${balance_usd:,.2f} USD\n"
                f"Price: ${price:,.2f} per {chain_symbol}"
            )
        except Exception as e:
            logging.error(f"Error updating balance: {str(e)}")
            self.wallet_info_label.setText(f"Error updating balance: {str(e)}")

    def update_transaction_history(self):
        self.history_table.setRowCount(0)
        transactions = self.wallet.get_transaction_history(use_api=True)
        self.history_table.setRowCount(len(transactions))
        chain_symbol = self.wallet.get_current_chain_symbol()
        for row, tx in enumerate(transactions):
            self.history_table.setItem(row, 0, QtWidgets.QTableWidgetItem(tx['type']))
            self.history_table.setItem(row, 1, QtWidgets.QTableWidgetItem(f"{tx['amount']:.6f} {chain_symbol}"))
            self.history_table.setItem(row, 2, QtWidgets.QTableWidgetItem(tx['timestamp']))
            self.history_table.setItem(row, 3, QtWidgets.QTableWidgetItem(tx['hash']))

    def update_portfolio(self):
        self.portfolio_table.setRowCount(0)
        portfolio = self.wallet.get_portfolio()
        self.portfolio_table.setRowCount(len(portfolio))
        for row, entry in enumerate(portfolio):
            self.portfolio_table.setItem(row, 0, QtWidgets.QTableWidgetItem(entry['chain']))
            self.portfolio_table.setItem(row, 1, QtWidgets.QTableWidgetItem(entry['address']))
            self.portfolio_table.setItem(row, 2, QtWidgets.QTableWidgetItem(entry['symbol']))
            self.portfolio_table.setItem(row, 3, QtWidgets.QTableWidgetItem(f"{entry['balance']:.6f}"))

    def copy_address(self):
        address = self.wallet.get_address()
        if address:
            clipboard = QtWidgets.QApplication.clipboard()
            clipboard.setText(address)
            self.statusBar().showMessage("Address copied to clipboard!", 2000)
            logging.info("Address copied to clipboard")

    def generate_qr(self, address):
        if not address:
            self.qr_label.clear()
            return
        try:
            qr = qrcode.QRCode(version=1, box_size=5, border=4)
            qr.add_data(address)
            qr.make(fit=True)
            fill_color = self.qr_fill_color.currentText().lower()
            back_color = self.qr_back_color.currentText().lower()
            img = qr.make_image(fill_color=fill_color, back_color=back_color)
            from io import BytesIO
            buffer = BytesIO()
            img.save(buffer, "PNG")
            pixmap = QtGui.QPixmap()
            pixmap.loadFromData(buffer.getvalue(), "PNG")
            self.qr_label.setPixmap(pixmap.scaled(150, 150, QtCore.Qt.KeepAspectRatio))
            logging.info(f"Generated QR code for address: {address}")
        except Exception as e:
            logging.error(f"Error generating QR code: {str(e)}")
            self.qr_label.clear()
            self.statusBar().showMessage(f"Failed to generate QR code: {str(e)}", 5000)

    def send_transaction(self):
        to_address = self.to_address_input.text()
        amount_str = self.amount_input.text()
        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be a positive number.")
            tx_hash = self.wallet.send_transaction(to_address, amount)
            if not tx_hash:
                raise ValueError("Transaction failed to process.")
            chain_symbol = self.wallet.get_current_chain_symbol()
            network = self.network_combo.currentText().split('-')[1]
            if chain_symbol in ["ETH", "Polygon", "Avalanche"]:
                explorer = "etherscan.io" if chain_symbol == "ETH" else "polygonscan.com" if chain_symbol == "Polygon" else "snowtrace.io"
                explorer_link = f"https://{network.lower()}.{explorer}/tx/{tx_hash}"
                self.tx_result_label.setText(f'Transaction sent! <a href="{explorer_link}">View on Explorer</a>')
            elif chain_symbol == "BTC":
                network_suffix = "testnet" if "Testnet" in self.network_combo.currentText() else ""
                blockchain_link = f"https://www.blockchain.com/explorer/transactions/btc{network_suffix}/{tx_hash}"
                self.tx_result_label.setText(f'Transaction sent! <a href="{blockchain_link}">View on Blockchain.com</a>')
            elif chain_symbol == "SOL":
                self.tx_result_label.setText(f'Transaction sent! Hash: {tx_hash}')
            self.update_balance()
            self.update_transaction_history()
            self.update_portfolio()
        except Exception as e:
            logging.error(f"Transaction error: {str(e)}")
            self.tx_result_label.setText(f"<font color='red'>Error: {str(e)}</font>")

    def swap_tokens(self):
        from_token = self.from_token_input.text().upper()
        to_token = self.to_token_input.text().upper()
        amount_str = self.swap_amount_input.text()
        chain_name = self.wallet.get_current_chain_symbol()
        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be a positive number.")
            tx_hash = self.wallet.swap_tokens(from_token, to_token, amount, chain_name)
            self.swap_result_label.setText(f"Swap successful! Hash: {tx_hash}")
            self.update_balance()
            self.update_transaction_history()
            self.update_portfolio()
        except Exception as e:
            logging.error(f"Swap error: {str(e)}")
            self.swap_result_label.setText(f"<font color='red'>Error: {str(e)}</font>")

    def update_prices(self):
        try:
            response = requests.get(PRICE_API)
            response.raise_for_status()
            data = response.json()
            self.prices['ETH'] = data['ethereum']['usd']
            self.prices['BTC'] = data['bitcoin']['usd']
            self.prices['SOL'] = data['solana']['usd']
            self.prices['Polygon'] = data['polygon']['usd']
            self.update_balance()
            logging.info(f"Updated prices: {self.prices}")
        except Exception as e:
            logging.error(f"Error fetching prices: {str(e)}")

    def start_price_update_thread(self):
        self.price_update_thread = Thread(target=self.run_price_update)
        self.price_update_thread.daemon = True
        self.price_update_thread.start()
        logging.info("Started price update thread")

    def run_price_update(self):
        while True:
            self.update_prices()
            time.sleep(60)

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = WalletApp()
    window.show()
    sys.exit(app.exec_())