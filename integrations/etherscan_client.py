"""
Etherscan Integration for Calyx
Fetches real smart contract source code and metadata

Supports: Ethereum Mainnet, Polygon, BSC, Arbitrum, Optimism
"""
import os
import requests
import time
from typing import Dict, Optional
import logging

log = logging.getLogger(__name__)


class EtherscanClient:
    """Fetch contract source code from Etherscan-compatible APIs."""

    NETWORKS = {
        'ethereum': 'https://api.etherscan.io/api',
        'polygon':  'https://api.polygonscan.com/api',
        'bsc':      'https://api.bscscan.com/api',
        'arbitrum': 'https://api.arbiscan.io/api',
        'optimism': 'https://api-optimistic.etherscan.io/api',
    }
    V2_BASE = 'https://api.etherscan.io/v2/api'
    CHAIN_IDS = {
        'ethereum': 1, 'polygon': 137, 'bsc': 56,
        'arbitrum': 42161, 'optimism': 10,
    }

    def __init__(self, api_key: Optional[str] = None, network: str = 'ethereum'):
        self.api_key  = api_key or os.getenv('ETHERSCAN_API_KEY', '')
        self.network  = network
        self.base_url = self.NETWORKS.get(network, self.NETWORKS['ethereum'])
        if not self.api_key:
            log.warning("No Etherscan API key - rate limited to 1 req/5s")

    def get_contract_source(self, address: str) -> Dict:
        address = address.lower().strip()
        if not address.startswith('0x'):
            address = '0x' + address
        log.info(f"Fetching source for {address} on {self.network}...")
        params = {
            'module': 'contract', 'action': 'getsourcecode',
            'address': address, 'apikey': self.api_key,
        }
        try:
            response = requests.get(self.base_url, params=params, timeout=10)
            data = response.json()
            if data['status'] != '1':
                return {'success': False, 'error': data.get('message', 'Unknown error'), 'verified': False}
            result = data['result'][0]
            if result['SourceCode'] == '':
                return {'success': False, 'error': 'Contract not verified on Etherscan', 'verified': False, 'address': address}
            source_code = self._parse_source_code(result['SourceCode'])
            return {
                'success': True, 'verified': True, 'address': address,
                'source_code': source_code, 'contract_name': result['ContractName'],
                'compiler_version': result['CompilerVersion'],
                'optimization': result['OptimizationUsed'] == '1',
                'runs': int(result.get('Runs', 200)),
                'constructor_arguments': result.get('ConstructorArguments', ''),
                'abi': result.get('ABI', ''),
                'implementation': result.get('Implementation', ''),
                'network': self.network,
            }
        except requests.RequestException as e:
            log.error(f"Etherscan API error: {e}")
            return {'success': False, 'error': f'API request failed: {str(e)}', 'verified': False}
        except Exception as e:
            log.error(f"Unexpected error: {e}")
            return {'success': False, 'error': f'Parsing error: {str(e)}', 'verified': False}

    def _parse_source_code(self, source_code: str) -> str:
        if source_code.startswith('{'):
            try:
                import json
                if source_code.startswith('{{'):
                    source_code = source_code[1:-1]
                data = json.loads(source_code)
                if 'sources' in data:
                    files = []
                    for filename, content in data['sources'].items():
                        if 'content' in content:
                            files.append(f"// File: {filename}\n{content['content']}")
                    return '\n\n'.join(files)
                else:
                    files = []
                    for filename, content in data.items():
                        if isinstance(content, dict) and 'content' in content:
                            files.append(f"// File: {filename}\n{content['content']}")
                        elif isinstance(content, str):
                            files.append(f"// File: {filename}\n{content}")
                    return '\n\n'.join(files)
            except Exception:
                pass
        return source_code

    def get_contract_info(self, address: str) -> Dict:
        params = {'module': 'account', 'action': 'balance', 'address': address,
                  'tag': 'latest', 'apikey': self.api_key}
        try:
            response = requests.get(self.base_url, params=params, timeout=10)
            data = response.json()
            if data['status'] == '1':
                return {'success': True, 'balance': data['result'], 'isContract': True}
            return {'success': False, 'error': data.get('message')}
        except Exception as e:
            log.error(f"Info fetch error: {e}")
            return {'success': False, 'error': str(e)}

    def get_transaction_list(self, address: str, limit: int = 100) -> Dict:
        params = {
            'module': 'account', 'action': 'txlist', 'address': address,
            'startblock': 0, 'endblock': 99999999, 'page': 1, 'offset': limit,
            'sort': 'desc', 'apikey': self.api_key,
        }
        try:
            response = requests.get(self.base_url, params=params, timeout=10)
            data = response.json()
            if data['status'] == '1':
                return {'success': True, 'transactions': data['result'][:limit]}
            return {'success': False, 'error': data.get('message')}
        except Exception as e:
            log.error(f"Transaction fetch error: {e}")
            return {'success': False, 'error': str(e)}

    def get_bytecode(self, address: str) -> Dict:
        """Fetch deployed bytecode via Etherscan V2 API (eth_getCode proxy)."""
        address = address.lower().strip()
        if not address.startswith('0x'):
            address = '0x' + address
        chain_id = self.CHAIN_IDS.get(self.network, 1)
        params = {
            'chainid': chain_id, 'module': 'proxy', 'action': 'eth_getCode',
            'address': address, 'tag': 'latest', 'apikey': self.api_key,
        }
        try:
            response = requests.get(self.V2_BASE, params=params, timeout=10)
            data = response.json()
            bytecode = data.get('result', '0x')
            if not isinstance(bytecode, str) or not bytecode.startswith('0x'):
                return {'success': False, 'bytecode': '0x', 'is_contract': False,
                        'error': f'unexpected result: {str(bytecode)[:80]}'}
            is_contract = len(bytecode) > 2
            return {
                'success': True,
                'bytecode': bytecode if is_contract else '0x',
                'is_contract': is_contract,
                'error': None,
            }
        except Exception as e:
            log.error(f"Bytecode fetch error: {e}")
            return {'success': False, 'bytecode': '0x', 'is_contract': False, 'error': str(e)}


def fetch_contract(address: str, network: str = 'ethereum') -> Dict:
    """Quick helper to fetch contract source."""
    client = EtherscanClient(network=network)
    return client.get_contract_source(address)


def is_verified(address: str, network: str = 'ethereum') -> bool:
    """Check if contract is verified on Etherscan."""
    result = fetch_contract(address, network)
    return result.get('verified', False)
