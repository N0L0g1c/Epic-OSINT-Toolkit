"""Web3 / cryptocurrency OSINT — multi-chain wallets, privacy coins, pivots.

Coverage target: top mainstream L1s + major privacy coins.
Privacy note: shielded Monero/Zcash cannot be chain-traced without keys or
exchange off-ramps — we do address classification, transparent-pool lookups,
and OSINT pivots only (no crypto breaks).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests

from modules.http_util import pace, rotate_headers

# Allowlisted public explorer / RPC hosts only (SSRF-safe).
_ALLOWED_HOSTS = frozenset({
    "blockstream.info",
    "mempool.space",
    "api.ethplorer.io",
    "api.etherscan.io",
    "ethereum.publicnode.com",
    "1rpc.io",
    "eth.drpc.org",
    "cloudflare-eth.com",
    "bsc.publicnode.com",
    "bsc-dataseed.binance.org",
    "bsc-dataseed1.defibit.io",
    "polygon-bor.publicnode.com",
    "polygon-rpc.com",
    "avalanche-c-chain.publicnode.com",
    "api.avax.network",
    "base.publicnode.com",
    "mainnet.base.org",
    "arbitrum-one.publicnode.com",
    "optimism.publicnode.com",
    "mainnet.era.zksync.io",
    "rpc.blast.io",
    "andromeda.metis.io",
    "rpc.mainnet.taiko.xyz",
    "mainnet.boba.network",
    "rpc.immutable.com",
    "evm.astar.network",
    "zkevm-rpc.com",
    "api.ensideas.com",
    "api.mainnet-beta.solana.com",
    "apilist.tronscanapi.com",
    "api.xrpscan.com",
    "api.koios.rest",
    "api.blockcypher.com",
    "rpc.mainnet.near.org",
    "starknet-mainnet.public.blastapi.io",
    "filecoin.chain.love",
    "api.hiro.so",
    "arweave.net",
})

# ── address / name patterns ───────────────────────────────────────────────────
_ETH_ADDR = re.compile(r"^0x[a-fA-F0-9]{40}$")
_ETH_TX = re.compile(r"^0x[a-fA-F0-9]{64}$")
_STARK_ADDR = re.compile(r"^0x0*[a-fA-F0-9]{1,63}$")  # felt; not 40-hex ETH
_BTC_ADDR = re.compile(r"^(?:bc1[a-z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
_BTC_TX = re.compile(r"^[a-fA-F0-9]{64}$")
_TRX_ADDR = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
_SOL_ADDR = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_ENS = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.eth$", re.I)
_LTC_ADDR = re.compile(r"^(?:ltc1[a-z0-9]{25,87}|[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})$")
_DOGE_ADDR = re.compile(r"^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$")
_XRP_ADDR = re.compile(r"^r[1-9A-HJ-NP-Za-km-z]{24,34}$")
_ADA_ADDR = re.compile(r"^addr1[a-z0-9]{50,120}$")
_ADA_STAKE = re.compile(r"^stake1[a-z0-9]{50,120}$")
_DASH_ADDR = re.compile(r"^X[1-9A-HJ-NP-Za-km-z]{33}$")
_XMR_ADDR = re.compile(r"^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$|^4[0-9AB][1-9A-HJ-NP-Za-km-z]{104}$")
_ZEC_T = re.compile(r"^t[13][a-km-zA-HJ-NP-Z1-9]{33}$")
_ZEC_Z = re.compile(r"^(?:zs1[a-z0-9]{70,90}|zc[a-zA-Z0-9]{90,120})$")
_NEAR_ADDR = re.compile(r"^(?:[a-z0-9_-]{2,64}\.near|[a-f0-9]{64})$", re.I)
_DOT_ADDR = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{47,48}$")  # SS58 rough
_FIL_ADDR = re.compile(r"^[ft][0-9][a-z0-9]{10,}$", re.I)
_STX_ADDR = re.compile(r"^S[PM][A-Z0-9]{38,41}$")
_AR_ADDR = re.compile(r"^[A-Za-z0-9_-]{43}$")
_CKB_ADDR = re.compile(r"^ckb1[a-z0-9]{40,120}$")
_OASIS_ADDR = re.compile(r"^oasis1[a-z0-9]{40,80}$")
_CELESTIA_ADDR = re.compile(r"^celestia1[a-z0-9]{38,60}$")
_WIF = re.compile(r"^[5KL][1-9A-HJ-NP-Za-km-z]{50,52}$")

# EVM chains sharing 0x addresses — selected as ONE group: "evm"
_EVM_RPCS: Dict[str, Dict[str, Any]] = {
    "ethereum": {
        "rpcs": ("https://ethereum.publicnode.com", "https://1rpc.io/eth", "https://eth.drpc.org"),
        "symbol": "ETH", "explorer": "https://etherscan.io/address/{addr}",
    },
    "bsc": {
        "rpcs": ("https://bsc.publicnode.com", "https://bsc-dataseed.binance.org"),
        "symbol": "BNB", "explorer": "https://bscscan.com/address/{addr}",
    },
    "polygon": {
        "rpcs": ("https://polygon-bor.publicnode.com", "https://polygon-rpc.com"),
        "symbol": "MATIC", "explorer": "https://polygonscan.com/address/{addr}",
    },
    "avalanche": {
        "rpcs": ("https://avalanche-c-chain.publicnode.com",),
        "symbol": "AVAX", "explorer": "https://snowtrace.io/address/{addr}",
    },
    "base": {
        "rpcs": ("https://base.publicnode.com", "https://mainnet.base.org"),
        "symbol": "ETH", "explorer": "https://basescan.org/address/{addr}",
    },
    "arbitrum": {
        "rpcs": ("https://arbitrum-one.publicnode.com",),
        "symbol": "ETH", "explorer": "https://arbiscan.io/address/{addr}",
    },
    "optimism": {
        "rpcs": ("https://optimism.publicnode.com",),
        "symbol": "ETH", "explorer": "https://optimistic.etherscan.io/address/{addr}",
    },
    "zksync": {
        "rpcs": ("https://mainnet.era.zksync.io",),
        "symbol": "ETH", "explorer": "https://explorer.zksync.io/address/{addr}",
    },
    "blast": {
        "rpcs": ("https://rpc.blast.io",),
        "symbol": "ETH", "explorer": "https://blastscan.io/address/{addr}",
    },
    "metis": {
        "rpcs": ("https://andromeda.metis.io/?owner=1088",),
        "symbol": "METIS", "explorer": "https://andromeda-explorer.metis.io/address/{addr}",
    },
    "taiko": {
        "rpcs": ("https://rpc.mainnet.taiko.xyz",),
        "symbol": "ETH", "explorer": "https://taikoscan.io/address/{addr}",
    },
    "boba": {
        "rpcs": ("https://mainnet.boba.network",),
        "symbol": "ETH", "explorer": "https://bobascan.com/address/{addr}",
    },
    "immutable": {
        "rpcs": ("https://rpc.immutable.com",),
        "symbol": "IMX", "explorer": "https://explorer.immutable.com/address/{addr}",
    },
    "astar": {
        "rpcs": ("https://evm.astar.network",),
        "symbol": "ASTR", "explorer": "https://astar.subscan.io/account/{addr}",
    },
    "polygon_zkevm": {
        "rpcs": ("https://zkevm-rpc.com",),
        "symbol": "ETH", "explorer": "https://zkevm.polygonscan.com/address/{addr}",
    },
}

# User-facing selection groups. "evm" = all EVM L1/L2 above as ONE choice.
CHAIN_GROUPS: Dict[str, Dict[str, Any]] = {
    "evm": {
        "label": "EVM (Ethereum + L1/L2s)",
        "family": "evm",
        "members": sorted(_EVM_RPCS.keys()),
        "note": "One 0x address → balances across ETH/BSC/Polygon/Arb/OP/zkSync/Blast/…",
    },
    "bitcoin": {"label": "Bitcoin", "family": "utxo", "members": ["bitcoin"], "note": "BTC UTXO"},
    "solana": {"label": "Solana", "family": "solana", "members": ["solana"], "note": "SOL"},
    "tron": {"label": "TRON", "family": "tron", "members": ["tron"], "note": "TRX"},
    "xrp": {"label": "XRP Ledger", "family": "xrp", "members": ["xrp"], "note": "XRP"},
    "cardano": {"label": "Cardano", "family": "cardano", "members": ["cardano"], "note": "ADA"},
    "dogecoin": {"label": "Dogecoin", "family": "utxo", "members": ["dogecoin"], "note": "DOGE"},
    "litecoin": {"label": "Litecoin", "family": "utxo", "members": ["litecoin"], "note": "LTC"},
    "dash": {"label": "Dash", "family": "privacy-lite", "members": ["dash"], "note": "DASH (+ PrivateSend caveats)"},
    "monero": {"label": "Monero", "family": "privacy", "members": ["monero"], "note": "XMR — pivots only"},
    "zcash": {"label": "Zcash", "family": "privacy", "members": ["zcash"], "note": "ZEC t-addr / shielded"},
    "near": {"label": "NEAR Protocol", "family": "near", "members": ["near"], "note": "NEAR"},
    "starknet": {"label": "Starknet", "family": "starknet", "members": ["starknet"], "note": "STRK / Cairo (not EVM)"},
    "polkadot": {"label": "Polkadot", "family": "substrate", "members": ["polkadot"], "note": "DOT — explorer pivots"},
    "filecoin": {"label": "Filecoin", "family": "filecoin", "members": ["filecoin"], "note": "FIL"},
    "stacks": {"label": "Stacks", "family": "stacks", "members": ["stacks"], "note": "STX (Bitcoin L2)"},
    "arweave": {"label": "Arweave", "family": "arweave", "members": ["arweave"], "note": "AR"},
    "celestia": {"label": "Celestia", "family": "cosmos", "members": ["celestia"], "note": "TIA — explorer pivots"},
    "nervos": {"label": "Nervos / CKB", "family": "nervos", "members": ["nervos"], "note": "CKB — explorer pivots"},
    "oasis": {"label": "Oasis", "family": "oasis", "members": ["oasis"], "note": "ROSE — explorer pivots"},
}

# Image tokens that live on EVM — covered when "evm" is selected (ERC-20 via Ethplorer).
ERC20_VIA_EVM = (
    "UNI", "AAVE", "WLD", "1INCH", "YFI", "ZRX", "SUSHI", "UMA", "OXT",
    "IMX", "LRC", "CTSI", "PHA", "METIS", "ARB", "OP", "STRK", "BLAST", "TAIKO",
)

# Flat chain → group for auto matching
_CHAIN_TO_GROUP = {
    m: g for g, meta in CHAIN_GROUPS.items() for m in meta["members"]
}
_CHAIN_TO_GROUP.update({"ethereum": "evm", **{k: "evm" for k in _EVM_RPCS}})


class CryptoIntel:
    """Passive Web3 OSINT across mainstream + privacy chains."""

    def __init__(self, etherscan_key: Optional[str] = None):
        self.etherscan_key = (etherscan_key or "").strip() or None
        self.session = requests.Session()
        self.session.headers.update(rotate_headers({"Accept": "application/json"}))

    @staticmethod
    def supported() -> Dict[str, Dict[str, Any]]:
        """Return selectable groups (evm = one bucket) + ERC-20 notes."""
        out = {k: dict(v) for k, v in CHAIN_GROUPS.items()}
        out["_erc20_via_evm"] = {
            "label": "ERC-20 tokens (via evm)",
            "members": list(ERC20_VIA_EVM),
            "note": "UNI/AAVE/… appear in Ethplorer token holdings when EVM is selected",
        }
        return out

    @staticmethod
    def group_ids() -> List[str]:
        return sorted(CHAIN_GROUPS.keys())

    @classmethod
    def normalize_selection(cls, chains: Any) -> List[str]:
        """Parse chains option → list of group ids. Default: ['auto']."""
        if chains is None or chains == "" or chains == []:
            return ["auto"]
        if isinstance(chains, str):
            parts = [p.strip().lower() for p in chains.replace(";", ",").split(",") if p.strip()]
        elif isinstance(chains, (list, tuple, set)):
            parts = [str(p).strip().lower() for p in chains if str(p).strip()]
        else:
            return ["auto"]
        if not parts:
            return ["auto"]
        if "all" in parts:
            return ["all"]
        valid = set(CHAIN_GROUPS) | {"auto", "all"}
        # Map legacy chain names (ethereum → evm, btc → bitcoin)
        aliases = {
            "eth": "evm", "ethereum": "evm", "l2": "evm", "btc": "bitcoin",
            "sol": "solana", "ada": "cardano", "dot": "polkadot", "fil": "filecoin",
            "stx": "stacks", "ar": "arweave", "xmr": "monero", "zec": "zcash",
            "tia": "celestia", "ckb": "nervos", "rose": "oasis", "strk": "starknet",
        }
        out: List[str] = []
        for p in parts:
            p = aliases.get(p, p)
            if p in valid and p not in out:
                out.append(p)
        return out or ["auto"]

    def _selection_allows(self, selected: List[str], group: str) -> bool:
        if "all" in selected:
            return True
        if "auto" in selected:
            return True  # auto applies native group only (caller gates)
        return group in selected

    def analyze(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        opts = options or {}
        raw = (target or "").strip()
        if not raw or len(raw) > 200:
            return {"error": "Invalid target", "target": target}

        if self._looks_like_secret(raw):
            return {
                "error": "Input looks like a private key / WIF — refused",
                "hint": "Only pass public addresses, ENS names, or tx hashes",
            }

        selected = self.normalize_selection(opts.get("chains"))
        kind, chain = self.classify(raw)
        native_group = _CHAIN_TO_GROUP.get(chain, chain)
        out: Dict[str, Any] = {
            "target": raw,
            "kind": kind,
            "chain": chain,
            "native_group": native_group,
            "normalized": raw,
            "selection": {
                "requested": selected,
                "hint": "Use chains=evm for all EVM L1/L2; or bitcoin,solana,… independently. Default auto = detected chain only.",
            },
            "groups_available": self.group_ids(),
        }

        if kind == "unknown":
            extracted = self.extract_addresses(raw)
            if extracted:
                out["extracted"] = extracted
                out["hint"] = "No single address detected; found embedded addresses"
            else:
                out["error"] = "Unrecognized wallet / ENS / tx hash"
            out["pivots"] = self._generic_pivots(raw)
            return out

        # Selection gate (auto → only native group; explicit must include native or all)
        if "auto" not in selected and "all" not in selected:
            if native_group not in selected and not (
                chain in _EVM_RPCS and "evm" in selected
            ):
                out["skipped"] = True
                out["reason"] = (
                    f"Address is {native_group}/{chain} but selection={selected}. "
                    f"Add '{native_group}' (or 'all') to --chains."
                )
                out["pivots"] = self._pivots(raw, chain)
                return out

        if kind == "ens":
            if not self._selection_allows(selected, "evm") and "auto" not in selected and "all" not in selected:
                out["skipped"] = True
                out["reason"] = "ENS requires evm selection"
                return out
            resolved = self._resolve_ens(raw)
            out["ens"] = resolved
            addr = (resolved or {}).get("address")
            if addr and _ETH_ADDR.match(addr):
                out["normalized"] = addr
                out["ethereum"] = self._eth_address(addr, opts)
                if "evm" in selected or "all" in selected:
                    out["evm_activity"] = self._evm_multichain(addr, skip=("ethereum",))
                elif "auto" in selected:
                    out["evm_activity"] = {
                        "note": "Skipped multi-EVM sweep (default auto). Pass chains=evm to scan all EVM L2s.",
                        "active_chains": [],
                    }
            out["pivots"] = self._pivots(addr or raw, "ethereum")
            out["risk"] = self._risk_pivots(addr or raw)
            return out

        if kind == "tx":
            out["transaction"] = self._tx_lookup(raw, chain)
            out["pivots"] = self._tx_pivots(raw, chain)
            return out

        # Address dispatch — only run matching handlers
        run_evm_sweep = "evm" in selected or "all" in selected

        if chain == "bitcoin":
            out["bitcoin"] = self._btc_address(raw)
        elif chain == "ethereum":
            out["ethereum"] = self._eth_address(raw, opts)
            ens = self._reverse_ens(raw)
            if ens:
                out["ens"] = ens
            if run_evm_sweep:
                out["evm_activity"] = self._evm_multichain(raw, skip=("ethereum",))
            else:
                out["evm_activity"] = {
                    "note": "Skipped multi-EVM sweep. Pass --chains evm to query Arb/OP/zkSync/Blast/…",
                    "active_chains": [],
                }
        elif chain == "solana":
            out["solana"] = self._sol_address(raw)
        elif chain == "tron":
            out["tron"] = self._trx_address(raw)
        elif chain == "xrp":
            out["xrp"] = self._xrp_address(raw)
        elif chain == "cardano":
            out["cardano"] = self._ada_address(raw)
        elif chain == "dogecoin":
            out["dogecoin"] = self._blockcypher_address(raw, "doge", "DOGE")
        elif chain == "litecoin":
            out["litecoin"] = self._blockcypher_address(raw, "ltc", "LTC")
        elif chain == "dash":
            out["dash"] = self._blockcypher_address(raw, "dash", "DASH")
            out["privacy"] = self._privacy_profile("dash", raw)
        elif chain == "monero":
            out["monero"] = self._privacy_profile("monero", raw)
        elif chain == "zcash":
            out["zcash"] = self._zcash_address(raw)
            out["privacy"] = self._privacy_profile("zcash", raw)
        elif chain == "near":
            out["near"] = self._near_address(raw)
        elif chain == "starknet":
            out["starknet"] = self._starknet_address(raw)
        elif chain == "filecoin":
            out["filecoin"] = self._filecoin_address(raw)
        elif chain == "stacks":
            out["stacks"] = self._stacks_address(raw)
        elif chain == "arweave":
            out["arweave"] = self._arweave_address(raw)
        elif chain in ("polkadot", "celestia", "nervos", "oasis"):
            out[chain] = {
                "address": raw,
                "note": "Explorer pivots only (no free balance API wired)",
                "source": "local",
            }
        else:
            out["note"] = f"Detected {chain}; explorer pivots only"

        out["risk"] = self._risk_pivots(raw)
        out["web_presence"] = self._web_presence_pivots(raw)
        out["pivots"] = self._pivots(raw, chain)
        return out

    @staticmethod
    def classify(raw: str) -> Tuple[str, str]:
        """Return (kind, chain). kind: address|ens|tx|unknown."""
        t = raw.strip()
        if _ENS.match(t):
            return "ens", "ethereum"
        if _ETH_TX.match(t):
            return "tx", "ethereum"
        if _ETH_ADDR.match(t):
            return "address", "ethereum"
        # Starknet: 0x + not exactly 40 hex (felt)
        if t.startswith("0x") and _STARK_ADDR.match(t) and not _ETH_ADDR.match(t) and not _ETH_TX.match(t):
            return "address", "starknet"
        if _XMR_ADDR.match(t):
            return "address", "monero"
        if _ZEC_Z.match(t) or _ZEC_T.match(t):
            return "address", "zcash"
        if _ADA_ADDR.match(t) or _ADA_STAKE.match(t):
            return "address", "cardano"
        if _NEAR_ADDR.match(t) and (t.endswith(".near") or (len(t) == 64 and all(c in "0123456789abcdefABCDEF" for c in t))):
            return "address", "near"
        if _CELESTIA_ADDR.match(t):
            return "address", "celestia"
        if _CKB_ADDR.match(t):
            return "address", "nervos"
        if _OASIS_ADDR.match(t):
            return "address", "oasis"
        if _FIL_ADDR.match(t):
            return "address", "filecoin"
        if _STX_ADDR.match(t):
            return "address", "stacks"
        if _XRP_ADDR.match(t):
            return "address", "xrp"
        if _TRX_ADDR.match(t):
            return "address", "tron"
        if _DOGE_ADDR.match(t):
            return "address", "dogecoin"
        if _DASH_ADDR.match(t):
            return "address", "dash"
        if _BTC_ADDR.match(t):
            return "address", "bitcoin"
        if _LTC_ADDR.match(t):
            return "address", "litecoin"
        if _BTC_TX.match(t):
            return "tx", "bitcoin"
        if _AR_ADDR.match(t) and not _SOL_ADDR.match(t):
            return "address", "arweave"
        if _DOT_ADDR.match(t) and not _SOL_ADDR.match(t) and not _BTC_ADDR.match(t):
            # SS58 overlaps Solana base58 — prefer sol if 32-44 and not 47-48
            if len(t) >= 47:
                return "address", "polkadot"
        if _SOL_ADDR.match(t) and not _BTC_ADDR.match(t) and not _LTC_ADDR.match(t):
            return "address", "solana"
        return "unknown", "unknown"

    @staticmethod
    def extract_addresses(text: str) -> List[Dict[str, str]]:
        found: List[Dict[str, str]] = []
        seen = set()
        patterns = (
            ("ethereum", _ETH_ADDR),
            ("bitcoin", _BTC_ADDR),
            ("tron", _TRX_ADDR),
            ("xrp", _XRP_ADDR),
            ("cardano", _ADA_ADDR),
            ("dogecoin", _DOGE_ADDR),
            ("dash", _DASH_ADDR),
            ("monero", _XMR_ADDR),
            ("zcash_t", _ZEC_T),
            ("zcash_z", _ZEC_Z),
            ("ens", _ENS),
        )
        for chain, rx in patterns:
            for m in rx.finditer(text):
                addr = m.group(0)
                key = addr.lower()
                if key in seen:
                    continue
                seen.add(key)
                found.append({"chain": chain, "address": addr})
        return found[:50]

    def _looks_like_secret(self, raw: str) -> bool:
        if _WIF.match(raw):
            return True
        if raw.lower().startswith(("priv", "private", "seed", "mnemonic")):
            return True
        return False

    # ── privacy OSINT (honest limits) ─────────────────────────────────────────

    def _privacy_profile(self, chain: str, addr: str) -> Dict[str, Any]:
        """OSINT framing for privacy coins — what can / cannot be done."""
        profiles = {
            "monero": {
                "privacy_level": "high",
                "traceable_on_chain": False,
                "limitations": [
                    "Ring signatures + stealth addresses + RingCT hide sender, receiver, amount",
                    "Public explorers cannot show balance or counterparties without a private view key",
                    "Do not attempt to 'break' cryptography — focus on endpoints",
                ],
                "osint_approaches": [
                    "Exchange KYC off-ramp / deposit attribution (legal process)",
                    "Timing / amount correlation around known CEX deposit windows (weak)",
                    "Paste / forum / dark-web mentions of the address string",
                    "Seized wallet view keys disclosed in LE reports",
                    "Merchant / tip-jar reuse of the same primary address",
                ],
                "explorer_pivots": [
                    {"name": "XMRChain", "url": f"https://xmrchain.net/search?value={quote(addr, safe='')}"},
                    {"name": "LocalMonero blocks", "url": f"https://localmonero.co/blocks/search/{quote(addr, safe='')}"},
                ],
            },
            "zcash": {
                "privacy_level": "high_if_shielded",
                "traceable_on_chain": addr.startswith("t"),
                "limitations": [
                    "zs1 / zc shielded pools hide parties and amounts (zk-SNARKs)",
                    "t1 / t3 transparent addresses behave like Bitcoin UTXO — traceable",
                    "Shielded↔transparent boundary txs are the main analytical pivot",
                ],
                "osint_approaches": [
                    "Trace t-addrs fully; mark any z-addr as opaque",
                    "Watch deshielding (z→t) then follow transparent hops to exchanges",
                    "Web / paste mentions; Chainabuse reports",
                ],
                "explorer_pivots": [
                    {"name": "ZcashBlockExplorer", "url": f"https://zcashblockexplorer.com/address/{quote(addr, safe='')}"},
                    {"name": "Blockchair ZEC", "url": f"https://blockchair.com/zcash/address/{quote(addr, safe='')}"},
                ],
            },
            "dash": {
                "privacy_level": "low_medium",
                "traceable_on_chain": True,
                "limitations": [
                    "PrivateSend mixes weaken but do not eliminate graph analysis",
                    "Non-PrivateSend txs are fully transparent UTXO",
                ],
                "osint_approaches": [
                    "Standard UTXO clustering on non-mixed outputs",
                    "Exchange deposit attribution",
                    "Web presence / abuse reports",
                ],
                "explorer_pivots": [
                    {"name": "Blockchair DASH", "url": f"https://blockchair.com/dash/address/{quote(addr, safe='')}"},
                    {"name": "Insight Dash", "url": f"https://insight.dash.org/insight/address/{quote(addr, safe='')}"},
                ],
            },
        }
        base = profiles.get(chain, {
            "privacy_level": "unknown",
            "traceable_on_chain": False,
            "limitations": ["Limited public telemetry"],
            "osint_approaches": ["Web / paste pivots only"],
            "explorer_pivots": [],
        })
        return {"address": addr, "chain": chain, **base}

    def _zcash_address(self, addr: str) -> Dict[str, Any]:
        if addr.startswith("t"):
            # No reliable free ZEC API without keys; pivots + classification
            return {
                "address": addr,
                "pool": "transparent",
                "traceable": True,
                "note": "Transparent Zcash — follow via explorer pivots (UTXO graph)",
                "source": "local",
            }
        return {
            "address": addr,
            "pool": "shielded",
            "traceable": False,
            "balance": None,
            "note": "Shielded Zcash — no public balance/counterparties without viewing key",
            "source": "local",
        }

    def _blockcypher_address(self, addr: str, coin: str, symbol: str) -> Dict[str, Any]:
        """UTXO balance via Blockcypher (doge/ltc/dash). Never call /addrs create (returns keys)."""
        data = self._get_json(
            f"https://api.blockcypher.com/v1/{quote(coin, safe='')}/main/addrs/{quote(addr, safe='')}/balance"
        )
        if not isinstance(data, dict) or data.get("error"):
            return data if isinstance(data, dict) else {"error": f"{coin} lookup failed"}
        bal = data.get("balance")
        try:
            human = int(bal) / 1e8 if bal is not None else None
        except (TypeError, ValueError):
            human = None
        return {
            "address": addr,
            f"balance_{symbol.lower()}": human,
            "balance_raw": bal,
            "tx_count": data.get("n_tx"),
            "total_received_raw": data.get("total_received"),
            "total_sent_raw": data.get("total_sent"),
            "source": "blockcypher",
        }

    def _ada_address(self, addr: str) -> Dict[str, Any]:
        headers_note = "koios"
        if addr.startswith("stake1"):
            data = self._post_json(
                "https://api.koios.rest/api/v1/account_info",
                {"_stake_addresses": [addr]},
            )
            rows = data if isinstance(data, list) else []
            if not rows and isinstance(data, dict) and data.get("error"):
                return data
            if not rows:
                return {"address": addr, "error": "No Koios stake data", "source": headers_note}
            row = rows[0] if isinstance(rows[0], dict) else {}
            bal = row.get("total_balance")
            try:
                ada = int(bal) / 1e6 if bal is not None else None
            except (TypeError, ValueError):
                ada = None
            return {
                "address": addr,
                "balance_ada": ada,
                "delegated_pool": row.get("delegated_pool"),
                "status": row.get("status"),
                "source": headers_note,
            }

        data = self._post_json(
            "https://api.koios.rest/api/v1/address_info",
            {"_addresses": [addr]},
        )
        if isinstance(data, dict) and data.get("error"):
            return data
        rows = data if isinstance(data, list) else []
        if not rows:
            return {
                "address": addr,
                "note": "No UTXO data (empty or unknown); use Cardanoscan pivot",
                "source": headers_note,
            }
        row = rows[0] if isinstance(rows[0], dict) else {}
        bal = row.get("balance")
        try:
            ada = int(bal) / 1e6 if bal is not None else None
        except (TypeError, ValueError):
            ada = None
        return {
            "address": addr,
            "balance_ada": ada,
            "stake_address": row.get("stake_address"),
            "script_address": row.get("script_address"),
            "source": headers_note,
        }

    def _btc_address(self, addr: str) -> Dict[str, Any]:
        data = self._get_json(f"https://blockstream.info/api/address/{quote(addr, safe='')}")
        if data.get("error"):
            data = self._get_json(f"https://mempool.space/api/address/{quote(addr, safe='')}")
        if data.get("error"):
            return data
        chain_stats = data.get("chain_stats") or {}
        mempool_stats = data.get("mempool_stats") or {}
        funded = int(chain_stats.get("funded_txo_sum") or 0)
        spent = int(chain_stats.get("spent_txo_sum") or 0)
        balance_sats = funded - spent
        txs = self._btc_recent_txs(addr)
        counterparties = self._btc_counterparties(addr, txs)
        return {
            "address": addr,
            "balance_sats": balance_sats,
            "balance_btc": round(balance_sats / 1e8, 8),
            "tx_count": chain_stats.get("tx_count"),
            "funded_sats": funded,
            "spent_sats": spent,
            "mempool_tx_count": mempool_stats.get("tx_count"),
            "recent_txs": txs[:10],
            "counterparties": counterparties[:25],
            "source": "blockstream/mempool",
        }

    def _btc_recent_txs(self, addr: str) -> List[Dict[str, Any]]:
        data = self._get_json(f"https://blockstream.info/api/address/{quote(addr, safe='')}/txs")
        if isinstance(data, dict) and data.get("error"):
            return []
        if not isinstance(data, list):
            return []
        return [
            {
                "txid": tx.get("txid"),
                "status": (tx.get("status") or {}).get("confirmed"),
                "block_time": (tx.get("status") or {}).get("block_time"),
                "fee": tx.get("fee"),
            }
            for tx in data[:15]
        ]

    def _btc_counterparties(self, addr: str, txs_meta: List[Dict[str, Any]]) -> List[str]:
        peers: List[str] = []
        seen = {addr}
        for meta in txs_meta[:8]:
            txid = meta.get("txid")
            if not txid:
                continue
            tx = self._get_json(f"https://blockstream.info/api/tx/{quote(str(txid), safe='')}")
            if not isinstance(tx, dict) or tx.get("error"):
                continue
            for vin in (tx.get("vin") or [])[:20]:
                prev = (vin.get("prevout") or {}).get("scriptpubkey_address")
                if prev and prev not in seen:
                    seen.add(prev)
                    peers.append(prev)
            for vout in (tx.get("vout") or [])[:20]:
                a = vout.get("scriptpubkey_address")
                if a and a not in seen:
                    seen.add(a)
                    peers.append(a)
        return peers

    def _eth_address(self, addr: str, opts: Dict[str, Any]) -> Dict[str, Any]:
        addr = addr.lower() if addr.startswith("0x") else addr
        result: Dict[str, Any] = {"address": addr}
        bal = self._evm_rpc("ethereum", "eth_getBalance", [addr, "latest"])
        nonce = self._evm_rpc("ethereum", "eth_getTransactionCount", [addr, "latest"])
        if isinstance(bal, str) and bal.startswith("0x"):
            wei = int(bal, 16)
            result["balance_wei"] = wei
            result["balance_eth"] = round(wei / 1e18, 8)
        if isinstance(nonce, str) and nonce.startswith("0x"):
            result["tx_count"] = int(nonce, 16)

        if opts.get("tokens", True):
            info = self._get_json(
                f"https://api.ethplorer.io/getAddressInfo/{quote(addr, safe='')}?apiKey=freekey"
            )
            if isinstance(info, dict) and not info.get("error"):
                tokens = []
                for t in (info.get("tokens") or [])[:30]:
                    tok = t.get("tokenInfo") or {}
                    raw_bal = t.get("balance") or 0
                    decimals = int(tok.get("decimals") or 0) or 0
                    try:
                        human = float(raw_bal) / (10 ** decimals) if decimals else float(raw_bal)
                    except (TypeError, ValueError, OverflowError):
                        human = None
                    tokens.append({
                        "symbol": tok.get("symbol"),
                        "name": tok.get("name"),
                        "address": tok.get("address"),
                        "balance": human,
                        "price_usd": (tok.get("price") or {}).get("rate")
                        if isinstance(tok.get("price"), dict) else None,
                    })
                result["tokens"] = tokens
                result["token_count"] = len(tokens)
                eth = info.get("ETH") or {}
                if eth.get("balance") is not None and "balance_eth" not in result:
                    result["balance_eth"] = eth.get("balance")
                result["source"] = "ethplorer+rpc"

        if self.etherscan_key and opts.get("txs", True):
            result["etherscan"] = self._etherscan_txs(addr)
        elif opts.get("txs", True):
            result["etherscan"] = {"skipped": True, "reason": "No --etherscan-key"}

        result["counterparties"] = self._eth_counterparties(addr, result.get("etherscan"))
        result.setdefault("source", "rpc")
        return result

    def _evm_multichain(self, addr: str, skip: Tuple[str, ...] = ()) -> Dict[str, Any]:
        """Sweep top EVM L1/L2s for native balance + nonce (same 0x address)."""
        addr = addr.lower()
        activity: Dict[str, Any] = {}
        for chain, meta in _EVM_RPCS.items():
            if chain in skip:
                continue
            bal = self._evm_rpc(chain, "eth_getBalance", [addr, "latest"])
            nonce = self._evm_rpc(chain, "eth_getTransactionCount", [addr, "latest"])
            bal_int = int(bal, 16) if isinstance(bal, str) and bal.startswith("0x") else 0
            nonce_int = int(nonce, 16) if isinstance(nonce, str) and nonce.startswith("0x") else 0
            entry = {
                "symbol": meta["symbol"],
                "balance_wei": bal_int,
                "balance": round(bal_int / 1e18, 8),
                "tx_count": nonce_int,
                "active": bal_int > 0 or nonce_int > 0,
                "explorer": meta["explorer"].format(addr=addr),
            }
            if entry["active"]:
                activity[chain] = entry
            else:
                activity[chain] = {"active": False, "symbol": meta["symbol"]}
        return {
            "address": addr,
            "active_chains": [k for k, v in activity.items() if v.get("active")],
            "chains": activity,
        }

    def _eth_counterparties(self, addr: str, etherscan: Any) -> List[str]:
        peers: List[str] = []
        seen = {addr.lower()}
        if isinstance(etherscan, dict):
            for tx in (etherscan.get("transactions") or [])[:40]:
                for key in ("from", "to"):
                    v = (tx.get(key) or "").lower()
                    if v and _ETH_ADDR.match(v) and v not in seen:
                        seen.add(v)
                        peers.append(v)
        return peers[:30]

    def _etherscan_txs(self, addr: str) -> Dict[str, Any]:
        url = (
            "https://api.etherscan.io/api"
            f"?module=account&action=txlist&address={quote(addr, safe='')}"
            f"&startblock=0&endblock=99999999&page=1&offset=25&sort=desc"
            f"&apikey={quote(self.etherscan_key or '', safe='')}"
        )
        data = self._get_json(url)
        if not isinstance(data, dict):
            return {"error": "Bad response"}
        if data.get("status") != "1" and data.get("message") != "No transactions found":
            return {"error": data.get("result") or data.get("message") or "Etherscan error"}
        txs = []
        for tx in data.get("result") or []:
            if not isinstance(tx, dict):
                continue
            try:
                val = int(tx.get("value") or 0) / 1e18
            except (TypeError, ValueError):
                val = None
            txs.append({
                "hash": tx.get("hash"),
                "from": tx.get("from"),
                "to": tx.get("to"),
                "value_eth": val,
                "timeStamp": tx.get("timeStamp"),
                "isError": tx.get("isError"),
            })
        return {"transactions": txs, "count": len(txs)}

    def _sol_address(self, addr: str) -> Dict[str, Any]:
        bal = self._post_json(
            "https://api.mainnet-beta.solana.com",
            {"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [addr]},
        )
        out: Dict[str, Any] = {"address": addr, "source": "solana-rpc"}
        if isinstance(bal, dict) and "result" in bal:
            lamports = ((bal.get("result") or {}).get("value"))
            if isinstance(lamports, int):
                out["balance_lamports"] = lamports
                out["balance_sol"] = round(lamports / 1e9, 9)
        elif isinstance(bal, dict) and bal.get("error"):
            out["error"] = bal["error"]
        return out

    def _near_address(self, addr: str) -> Dict[str, Any]:
        data = self._post_json(
            "https://rpc.mainnet.near.org",
            {
                "jsonrpc": "2.0",
                "id": "osint",
                "method": "query",
                "params": {"request_type": "view_account", "finality": "final", "account_id": addr},
            },
        )
        if not isinstance(data, dict):
            return {"error": "NEAR RPC failed"}
        if data.get("error"):
            return {"address": addr, "error": data["error"], "source": "near-rpc"}
        res = data.get("result") or {}
        amt = res.get("amount")
        try:
            near = int(amt) / 1e24 if amt is not None else None
        except (TypeError, ValueError):
            near = None
        return {
            "address": addr,
            "balance_near": near,
            "storage_usage": res.get("storage_usage"),
            "source": "near-rpc",
        }

    def _starknet_address(self, addr: str) -> Dict[str, Any]:
        # Starknet JSON-RPC starknet_getBalance / getNonce variants differ by node.
        data = self._post_json(
            "https://starknet-mainnet.public.blastapi.io",
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "starknet_getNonce",
                "params": {"block_id": "latest", "contract_address": addr},
            },
        )
        out: Dict[str, Any] = {
            "address": addr,
            "note": "Starknet is not EVM — select starknet independently from evm",
            "source": "starknet-rpc",
        }
        if isinstance(data, dict) and "result" in data:
            out["nonce"] = data.get("result")
            out["active"] = True
        elif isinstance(data, dict) and data.get("error"):
            out["error"] = data.get("error")
        return out

    def _filecoin_address(self, addr: str) -> Dict[str, Any]:
        data = self._post_json(
            "https://filecoin.chain.love/rpc/v1",
            {"jsonrpc": "2.0", "id": 1, "method": "Filecoin.WalletBalance", "params": [addr]},
        )
        if not isinstance(data, dict):
            return {"error": "Filecoin RPC failed"}
        if "result" in data:
            try:
                atto = int(data["result"])
                fil = atto / 1e18
            except (TypeError, ValueError):
                atto, fil = None, None
            return {"address": addr, "balance_fil": fil, "balance_attofil": atto, "source": "filecoin-rpc"}
        return {"address": addr, "error": data.get("error") or "lookup failed", "source": "filecoin-rpc"}

    def _stacks_address(self, addr: str) -> Dict[str, Any]:
        data = self._get_json(f"https://api.hiro.so/extended/v1/address/{quote(addr, safe='')}/stx")
        if not isinstance(data, dict) or data.get("error"):
            return data if isinstance(data, dict) else {"error": "Stacks lookup failed"}
        bal = data.get("balance")
        try:
            stx = int(bal) / 1e6 if bal is not None else None
        except (TypeError, ValueError):
            stx = None
        return {
            "address": addr,
            "balance_stx": stx,
            "total_sent": data.get("total_sent"),
            "total_received": data.get("total_received"),
            "source": "hiro",
        }

    def _arweave_address(self, addr: str) -> Dict[str, Any]:
        data = self._get_json(f"https://arweave.net/wallet/{quote(addr, safe='')}/balance")
        # arweave returns plain winston integer as body — _get_json may fail
        if isinstance(data, dict) and data.get("error"):
            # retry as text
            if not self._host_ok("https://arweave.net/"):
                return data
            try:
                pace()
                r = self.session.get(
                    f"https://arweave.net/wallet/{quote(addr, safe='')}/balance",
                    timeout=20,
                )
                if r.status_code != 200:
                    return {"error": f"HTTP {r.status_code}"}
                winston = int(r.text.strip())
                return {
                    "address": addr,
                    "balance_winston": winston,
                    "balance_ar": round(winston / 1e12, 8),
                    "source": "arweave.net",
                }
            except (requests.RequestException, ValueError) as exc:
                return {"error": str(exc)}
        return {"address": addr, "raw": data, "source": "arweave.net"}

    def _trx_address(self, addr: str) -> Dict[str, Any]:
        data = self._get_json(
            f"https://apilist.tronscanapi.com/api/account?address={quote(addr, safe='')}"
        )
        if not isinstance(data, dict) or data.get("error"):
            return data if isinstance(data, dict) else {"error": "Tron lookup failed"}
        balance = data.get("balance")
        try:
            trx = float(balance) / 1e6 if balance is not None else None
        except (TypeError, ValueError):
            trx = None
        return {
            "address": addr,
            "balance_trx": trx,
            "transactions": data.get("totalTransactionCount"),
            "create_time": data.get("date_created") or data.get("dateCreated"),
            "source": "tronscan",
        }

    def _xrp_address(self, addr: str) -> Dict[str, Any]:
        data = self._get_json(f"https://api.xrpscan.com/api/v1/account/{quote(addr, safe='')}")
        if not isinstance(data, dict) or data.get("error"):
            return data if isinstance(data, dict) else {"error": "XRP lookup failed"}
        # XRPSCAN returns flat account fields at top level
        bal = data.get("xrpBalance") or data.get("Balance")
        try:
            if isinstance(bal, str) and bal.isdigit() and len(bal) > 6:
                xrp = int(bal) / 1e6
            else:
                xrp = float(bal) if bal is not None else None
        except (TypeError, ValueError):
            xrp = None
        return {
            "address": addr,
            "balance_xrp": xrp,
            "parent": data.get("parent"),
            "inception": data.get("inception"),
            "domain": data.get("domain") or data.get("Domain"),
            "sequence": data.get("sequence"),
            "source": "xrpscan",
        }

    def _tx_lookup(self, txid: str, chain: str) -> Dict[str, Any]:
        if chain == "bitcoin":
            data = self._get_json(f"https://blockstream.info/api/tx/{quote(txid, safe='')}")
            if isinstance(data, dict) and not data.get("error"):
                return {
                    "txid": data.get("txid"),
                    "fee": data.get("fee"),
                    "status": data.get("status"),
                    "vin_count": len(data.get("vin") or []),
                    "vout_count": len(data.get("vout") or []),
                    "source": "blockstream",
                }
            return data if isinstance(data, dict) else {"error": "TX lookup failed"}
        if chain == "ethereum":
            raw = self._evm_rpc("ethereum", "eth_getTransactionByHash", [txid])
            if isinstance(raw, dict):
                return {
                    "hash": raw.get("hash"),
                    "from": raw.get("from"),
                    "to": raw.get("to"),
                    "value_wei": int(raw["value"], 16) if isinstance(raw.get("value"), str) else None,
                    "blockNumber": raw.get("blockNumber"),
                    "source": "eth-rpc",
                }
            return {"error": "TX not found or RPC error", "detail": raw}
        return {"error": f"Unsupported chain for tx: {chain}"}

    def _resolve_ens(self, name: str) -> Dict[str, Any]:
        data = self._get_json(f"https://api.ensideas.com/ens/resolve/{quote(name, safe='')}")
        if isinstance(data, dict) and not data.get("error"):
            return {
                "name": data.get("name") or name,
                "address": data.get("address"),
                "avatar": data.get("avatar"),
                "source": "ensideas",
            }
        return data if isinstance(data, dict) else {"error": "ENS resolve failed"}

    def _reverse_ens(self, addr: str) -> Optional[Dict[str, Any]]:
        data = self._get_json(f"https://api.ensideas.com/ens/reverse/{quote(addr, safe='')}")
        if isinstance(data, dict) and data.get("name"):
            return {"name": data.get("name"), "address": addr, "source": "ensideas"}
        return None

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _host_ok(self, url: str) -> bool:
        try:
            from urllib.parse import urlparse
            host = (urlparse(url).hostname or "").lower()
            return host in _ALLOWED_HOSTS
        except Exception:
            return False

    def _get_json(self, url: str) -> Any:
        if not self._host_ok(url):
            return {"error": "Host not allowlisted"}
        try:
            pace()
            r = self.session.get(url, headers=rotate_headers({"Accept": "application/json"}), timeout=20)
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}", "body": r.text[:200]}
            return r.json() if r.text else {}
        except (requests.RequestException, ValueError) as exc:
            return {"error": str(exc)}

    def _post_json(self, url: str, payload: Any) -> Any:
        if not self._host_ok(url):
            return {"error": "Host not allowlisted"}
        try:
            pace()
            r = self.session.post(
                url,
                json=payload,
                headers=rotate_headers({"Accept": "application/json", "Content-Type": "application/json"}),
                timeout=20,
            )
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}", "body": r.text[:200]}
            return r.json() if r.text else {}
        except (requests.RequestException, ValueError) as exc:
            return {"error": str(exc)}

    def _evm_rpc(self, chain: str, method: str, params: list) -> Any:
        meta = _EVM_RPCS.get(chain) or {}
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        for url in meta.get("rpcs") or ():
            data = self._post_json(url, payload)
            if isinstance(data, dict) and "result" in data:
                return data["result"]
        return None

    # ── pivots ────────────────────────────────────────────────────────────────

    def _risk_pivots(self, addr: str) -> Dict[str, Any]:
        q = quote(addr, safe="")
        return {
            "note": "Manual review pivots — confirm before action",
            "pivots": [
                {"name": "OpenSanctions", "url": f"https://www.opensanctions.org/search/?q={q}"},
                {"name": "Chainabuse", "url": f"https://www.chainabuse.com/address/{q}"},
                {"name": "BitcoinAbuse (archive)", "url": f"https://www.bitcoinabuse.com/reports/{q}"},
                {"name": "ScamSniffer", "url": "https://www.scamsniffer.io/"},
                {"name": "OFAC SDN search", "url": "https://sanctionssearch.ofac.treas.gov/"},
            ],
        }

    @staticmethod
    def _web_presence_pivots(addr: str) -> List[Dict[str, str]]:
        q = quote(addr, safe="")
        qq = quote(f'"{addr}"', safe="")
        return [
            {"name": "Google", "url": f"https://www.google.com/search?q={qq}"},
            {"name": "GitHub code", "url": f"https://github.com/search?q={q}&type=code"},
            {"name": "Reddit", "url": f"https://www.reddit.com/search/?q={q}"},
            {"name": "Twitter/X", "url": f"https://x.com/search?q={q}"},
            {"name": "Pastebin search", "url": f"https://www.google.com/search?q=site:pastebin.com+{q}"},
            {"name": "Arkham (manual)", "url": "https://platform.arkhamintelligence.com/"},
            {"name": "Breadcrumbs", "url": f"https://www.breadcrumbs.app/reports/{q}"},
        ]

    @staticmethod
    def _pivots(addr: str, chain: str) -> List[Dict[str, str]]:
        q = quote(addr, safe="")
        common = [{"name": "Blockchair", "url": f"https://blockchair.com/search?q={q}"}]
        table = {
            "bitcoin": [
                {"name": "Mempool.space", "url": f"https://mempool.space/address/{q}"},
                {"name": "Blockstream", "url": f"https://blockstream.info/address/{q}"},
            ],
            "ethereum": [
                {"name": "Etherscan", "url": f"https://etherscan.io/address/{q}"},
                {"name": "Debank", "url": f"https://debank.com/profile/{q}"},
                {"name": "Arbiscan", "url": f"https://arbiscan.io/address/{q}"},
                {"name": "Optimistic", "url": f"https://optimistic.etherscan.io/address/{q}"},
                {"name": "zkSync", "url": f"https://explorer.zksync.io/address/{q}"},
                {"name": "Blastscan", "url": f"https://blastscan.io/address/{q}"},
            ],
            "solana": [{"name": "Solscan", "url": f"https://solscan.io/account/{q}"}],
            "tron": [{"name": "Tronscan", "url": f"https://tronscan.org/#/address/{q}"}],
            "xrp": [{"name": "XRPSCAN", "url": f"https://xrpscan.com/account/{q}"}],
            "cardano": [{"name": "Cardanoscan", "url": f"https://cardanoscan.io/address/{q}"}],
            "dogecoin": [{"name": "Blockchair DOGE", "url": f"https://blockchair.com/dogecoin/address/{q}"}],
            "litecoin": [{"name": "Blockchair LTC", "url": f"https://blockchair.com/litecoin/address/{q}"}],
            "dash": [{"name": "Blockchair DASH", "url": f"https://blockchair.com/dash/address/{q}"}],
            "monero": [{"name": "XMRChain", "url": f"https://xmrchain.net/search?value={q}"}],
            "zcash": [{"name": "ZcashBlockExplorer", "url": f"https://zcashblockexplorer.com/address/{q}"}],
            "near": [{"name": "NEAR Explorer", "url": f"https://nearblocks.io/address/{q}"}],
            "starknet": [{"name": "Voyager", "url": f"https://voyager.online/contract/{q}"}],
            "polkadot": [{"name": "Subscan", "url": f"https://polkadot.subscan.io/account/{q}"}],
            "filecoin": [{"name": "Filfox", "url": f"https://filfox.info/en/address/{q}"}],
            "stacks": [{"name": "Explorer", "url": f"https://explorer.hiro.so/address/{q}?chain=mainnet"}],
            "arweave": [{"name": "ViewBlock", "url": f"https://viewblock.io/arweave/address/{q}"}],
            "celestia": [{"name": "Celestia Explorer", "url": f"https://celenium.io/address/{q}"}],
            "nervos": [{"name": "CKB Explorer", "url": f"https://explorer.nervos.org/address/{q}"}],
            "oasis": [{"name": "Oasis Scan", "url": f"https://www.oasisscan.com/accounts/detail/{q}"}],
        }
        return (table.get(chain) or []) + common

    @staticmethod
    def _tx_pivots(txid: str, chain: str) -> List[Dict[str, str]]:
        q = quote(txid, safe="")
        if chain == "bitcoin":
            return [
                {"name": "Mempool.space", "url": f"https://mempool.space/tx/{q}"},
                {"name": "Blockstream", "url": f"https://blockstream.info/tx/{q}"},
            ]
        return [
            {"name": "Etherscan", "url": f"https://etherscan.io/tx/{q}"},
        ]

    @staticmethod
    def _generic_pivots(raw: str) -> List[Dict[str, str]]:
        q = quote(raw, safe="")
        return [
            {"name": "Google", "url": f"https://www.google.com/search?q={quote(chr(34) + raw + chr(34), safe='')}"},
            {"name": "Blockchair", "url": f"https://blockchair.com/search?q={q}"},
        ]
