import os
import pickle
import string
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        raise Exception("not implemented!")
        return

    def signCert(self, cert):
        ecdsa = ec.ECDSA(hashes.SHA256())
        sig = self.server_signing_key.sign(cert, ecdsa)
        return sig

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}  
        self.friends = dict[str, Keys] = {} #dict of {name, Keys(pk, mk, root, ck)}
        self.certs = {}
        self.sending = {} #stores name of person talking to with a boolean of whether you sent the last message (true if it was you)
        self.private_key = None
        
        #These need to be fixed because there's one for each convo
        self.mk = None
        self.root = None
        self.chain = None

        #Need to save each root and chain for each person 
        

    def generateCertificate(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        pk = self.private_key.public_key()
        return Certificate(pk, self.name)

    def receiveCertificate(self, certificate, foreign_signature):
        ecdsa = ec.ECDSA(hashes.SHA256())
        self.server_signing_pk.verify(foreign_signature,certificate, ecdsa)
        self.certs[certificate.name] = [self.private_key.exchange(ec.ECDH, certificate.publickey), certificate.publickey]
        return

    def sendMessage(self, name, message):
        if name not in self.conns: 
            self.sending[name] = True
            # DH ratchet and symm 

            self.friends[name].rk, self.friends[name].ck, my_public_key = self.dhRatchet(self.certs[name][1], self.certs[name][0])


            self.friends[name].ck, self.friends[name].mk = self.symmRatchet(self.root)

            #encrypt the message with the resulting message key (mk)

            #my public key should go in the header 


            return
        elif self.sending[name] is False:
            self.sending[name] = True
            self.friends[name].rk, my_public_key = self.dhRatchet(self.friends[name].pk, self.friends[name].rk)
            self.friends[name].ck, self.friends[name].mk = self.symmRatchet(self.root)

            #encrypt
            return
            #DH ratchet and symm
        else:
            #NO DH ratchet, but symm ratchet
            self.friends[name].ck, self.friends[name].mk = self.symmRatchet(self.mk)

            #encrypt
            return
        

    def receiveMessage(self, name, header, ciphertext):

        self.conns[name] = header #loading this in 
        
        #first check if we were receiving before, if not them self.sending[name] = False ELSE don't change it because it's already false

        raise Exception("not implemented!")
        return

    def report(self, name, message):
        raise Exception("not implemented!")
        return
    def dhRatchet(self, pubkey, root):
        #generate a new pub priv key pair
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = self.private_key.public_key()
        #where do we send this?
        #DH
        dh_out = self.private_key.exchange(ec.ECDH(), pubkey)

        #Key Derive
        key_der = HKDF(hashes.SHA256(),64, root, b'root key').derive(dh_out)
        
        root_key = key_der[63:32]
        chain_key = key_der[31:0]
        
        return root_key, chain_key, public_key

    def symmRatchet(self, chain_key):
        h = hmac.HMAC(chain_key, hashes.SHA256())

        h.update("0x02")

        new_chain = h.finalize()

        j = hmac.HMAC(chain_key, hashes.SHA256())

        j.update("0x01")

        new_message = j.finalize()

        return new_chain, new_message



class Certificate:
    
    def __init__(self, publicKey, userName):
        self.name = userName
        self.publicKey = publicKey

class Keys:
    
    def __init__(self, publicKey, chainKey, messageKey, rootKey):
        self.pk = publicKey
        self.ck = chainKey
        self.mk = messageKey
        self.rk = rootKey