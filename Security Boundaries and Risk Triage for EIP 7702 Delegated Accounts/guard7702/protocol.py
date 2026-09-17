"""Authorization-phase model; not a full EVM or transaction validator."""
from dataclasses import dataclass, field
import copy
import rlp
from eth_keys import keys
from eth_keys.constants import SECPK1_N
from eth_utils import keccak

ZERO = '0x' + '00' * 20
PREFIX = bytes.fromhex('ef0100')

def address_bytes(address):
    if not isinstance(address, str) or not address.startswith('0x'):
        raise ValueError('address must be 0x-prefixed')
    b = bytes.fromhex(address[2:])
    if len(b) != 20:
        raise ValueError('address must contain 20 bytes')
    return b

def delegated(code):
    return len(code) == 23 and code.startswith(PREFIX)

@dataclass(frozen=True)
class Authorization:
    chain_id: int
    address: str
    nonce: int
    y_parity: int
    r: int
    s: int

    def validate_shape(self):
        address_bytes(self.address)
        for name, bits in [('chain_id',256),('nonce',64),('y_parity',8),('r',256),('s',256)]:
            v = getattr(self,name)
            if type(v) is not int or not 0 <= v < 2**bits:
                raise ValueError('out-of-range ' + name)

    def digest(self):
        return keccak(b'\x05' + rlp.encode([self.chain_id,address_bytes(self.address),self.nonce]))

    def recover(self):
        if self.y_parity not in (0,1) or not 0 < self.r < SECPK1_N or not 0 < self.s <= SECPK1_N//2:
            raise ValueError('invalid signature')
        return keys.Signature(vrs=(self.y_parity,self.r,self.s)).recover_public_key_from_msg_hash(self.digest()).to_address()

def sign(private_key, chain_id, target, nonce):
    a = Authorization(chain_id,target,nonce,0,1,1)
    a.validate_shape()
    sig = keys.PrivateKey(private_key).sign_msg_hash(a.digest())
    return Authorization(chain_id,target,nonce,sig.v,sig.r,sig.s)

@dataclass
class Account:
    nonce: int = 0
    balance: int = 0
    code: bytes = b''
    storage: dict = field(default_factory=dict)

    def exists(self):
        return bool(self.nonce or self.balance or self.code)

class World:
    def __init__(self, chain_id, accounts=None):
        self.chain_id = chain_id
        self.accounts = copy.deepcopy(accounts or {})

    def process(self, sender, authorizations, execution=None):
        # Envelope validation happens before any mutation. Outer signature,
        # fee sufficiency, gas limit and EVM execution are outside this model.
        if not authorizations:
            raise ValueError('empty authorization list')
        for a in authorizations:
            a.validate_shape()
        sender = sender.lower()
        acc = self.accounts.get(sender, Account())
        if acc.code and not delegated(acc.code):
            raise ValueError('sender has ordinary code')
        if acc.nonce >= 2**64-1:
            raise ValueError('sender nonce exhausted')
        self.accounts.setdefault(sender,acc).nonce += 1
        outcomes, refund = [], 0
        for a in authorizations:
            reason, authority = 'accepted', None
            if a.chain_id not in (0,self.chain_id):
                reason = 'chain'
            elif a.nonce >= 2**64-1:
                reason = 'nonce_bound'
            else:
                try:
                    authority = a.recover()
                except Exception:
                    reason = 'signature'
            if reason == 'accepted':
                state = self.accounts.get(authority, Account())
                if state.code and not delegated(state.code):
                    reason = 'authority_code'
                elif state.nonce != a.nonce:
                    reason = 'nonce'
                else:
                    refund += 12500 * state.exists()
                    state.code = b'' if a.address.lower() == ZERO else PREFIX + address_bytes(a.address)
                    state.nonce += 1
                    self.accounts[authority] = state
            outcomes.append({'authority':authority,'reason':reason})
        checkpoint = copy.deepcopy(self.accounts)
        success = True
        if execution:
            try:
                execution(self.accounts)
            except Exception:
                self.accounts = checkpoint
                success = False
        return {'outcomes':outcomes,'execution_success':success,
                'authorization_charge':25000*len(authorizations),'refund_counter':refund}
