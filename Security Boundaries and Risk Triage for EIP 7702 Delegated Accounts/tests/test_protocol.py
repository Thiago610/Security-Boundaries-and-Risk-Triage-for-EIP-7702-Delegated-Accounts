import unittest
from dataclasses import replace
from eth_keys import keys
from eth_keys.constants import SECPK1_N
from eth_account import Account as SDKAccount
from guard7702.protocol import *

KEY=(1).to_bytes(32,'big') # public test key, never fund
USER=keys.PrivateKey(KEY).public_key.to_address()
SPONSOR='0x'+'22'*20
TARGET='0x'+'33'*20
OTHER='0x'+'44'*20

class ProtocolTests(unittest.TestCase):
    def test_sdk_differential_signatures(self):
        for chain in (0,1,31337):
            for nonce in (0,1,127,128,2**64-2):
                a=sign(KEY,chain,TARGET,nonce)
                b=SDKAccount.sign_authorization({'chainId':chain,'address':TARGET,'nonce':nonce},KEY)
                self.assertEqual((a.y_parity,a.r,a.s),(b.y_parity,b.r,b.s))
                self.assertEqual(a.recover(),USER)

    def test_persistence_after_revert(self):
        w=World(1,{USER:Account(balance=100)})
        def fail(states):
            states[USER].balance=0
            states[USER].storage['x']=1
            raise RuntimeError()
        r=w.process(SPONSOR,[sign(KEY,1,TARGET,0)],fail)
        self.assertFalse(r['execution_success'])
        self.assertEqual(w.accounts[USER].balance,100)
        self.assertEqual(w.accounts[USER].storage,{})
        self.assertEqual(w.accounts[USER].nonce,1)
        self.assertEqual(len(w.accounts[USER].code),23)

    def test_replay_and_cross_chain(self):
        a=sign(KEY,0,TARGET,0)
        for chain in (1,31337):
            w=World(chain)
            self.assertEqual(w.process(SPONSOR,[a])['outcomes'][0]['reason'],'accepted')
            self.assertEqual(w.process(SPONSOR,[a])['outcomes'][0]['reason'],'nonce')
        self.assertEqual(World(31337).process(SPONSOR,[sign(KEY,1,TARGET,0)])['outcomes'][0]['reason'],'chain')

    def test_self_sponsor_nonce(self):
        w=World(1)
        self.assertEqual(w.process(USER,[sign(KEY,1,TARGET,0)])['outcomes'][0]['reason'],'nonce')
        w=World(1)
        w.process(USER,[sign(KEY,1,TARGET,1)])
        self.assertEqual(w.accounts[USER].nonce,2)

    def test_last_valid_and_clear_storage(self):
        w=World(1,{USER:Account(storage={'old':7})})
        w.process(SPONSOR,[sign(KEY,1,TARGET,0),sign(KEY,1,OTHER,1),sign(KEY,1,TARGET,1)])
        self.assertEqual(w.accounts[USER].code,PREFIX+address_bytes(OTHER))
        w.process(SPONSOR,[sign(KEY,1,ZERO,2)])
        self.assertEqual(w.accounts[USER].code,b'')
        self.assertEqual(w.accounts[USER].storage,{'old':7})

    def test_invalid_tuple_skipped_and_charged(self):
        a=sign(KEY,1,TARGET,0)
        w=World(1)
        r=w.process(SPONSOR,[replace(a,s=SECPK1_N-a.s),a])
        self.assertEqual([x['reason'] for x in r['outcomes']],['signature','accepted'])
        self.assertEqual(r['authorization_charge'],50000)

    def test_invalid_envelope_atomicity(self):
        for a in (replace(sign(KEY,1,TARGET,0),nonce=2**64),replace(sign(KEY,1,TARGET,0),address='0x12')):
            w=World(1)
            with self.assertRaises(ValueError):w.process(SPONSOR,[a])
            self.assertEqual(w.accounts,{})

    def test_authority_not_target_code_check(self):
        w=World(1,{TARGET:Account(code=b'\x60\x00')})
        w.process(SPONSOR,[sign(KEY,1,TARGET,0)])
        self.assertTrue(delegated(w.accounts[USER].code))
        w=World(1,{USER:Account(code=b'\x60\x00')})
        self.assertEqual(w.process(SPONSOR,[sign(KEY,1,TARGET,0)])['outcomes'][0]['reason'],'authority_code')

    def test_refund_counter(self):
        for balance,expected in [(0,0),(1,12500)]:
            w=World(1,{USER:Account(balance=balance)})
            self.assertEqual(w.process(SPONSOR,[sign(KEY,1,TARGET,0)])['refund_counter'],expected)

    def test_nonce_boundary(self):
        a=sign(KEY,1,TARGET,2**64-1)
        self.assertEqual(World(1).process(SPONSOR,[a])['outcomes'][0]['reason'],'nonce_bound')

    def test_empty_and_ordinary_sender(self):
        with self.assertRaises(ValueError):World(1).process(SPONSOR,[])
        with self.assertRaises(ValueError):World(1,{SPONSOR:Account(code=b'a')}).process(SPONSOR,[sign(KEY,1,TARGET,0)])
