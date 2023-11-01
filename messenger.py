import os
import pickle
import string
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        raise Exception("not implemented!")
        return

    def signCert(self, cert):
        ecdsa = ec.ECDSA(hashes.SHA256())
        sig = self.server_signing_key.sign(pickle.dumps(cert), ecdsa)
        return sig

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns: dict[str, Keys] = {} #dict of {name, Keys(their_pk, mk, root, ck, my_pk)}
        self.certs = {}
        self.sending = {} #stores name of person talking to with a boolean of whether you sent the last message (true if it was you)
        self.private_key = None
        
        #These need to be fixed because there's one for each convo
        self.mk = None
        self.root = None
        self.chain = None
        self.counter = 2**64


        #Need to save each root and chain for each person 
        

    def generateCertificate(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        pk = self.private_key.public_key()
        return Certificate(pk, self.name)

    def receiveCertificate(self, certificate, foreign_signature):
        ecdsa = ec.ECDSA(hashes.SHA256())
        self.server_signing_pk.verify(foreign_signature,pickle.dumps(certificate), ecdsa)
        self.certs[certificate.name] = [self.private_key.exchange(ec.ECDH(), load_pem_public_key(certificate.publicKey)), load_pem_public_key(certificate.publicKey)]
        return 

    def sendMessage(self, name, message):
        if name not in self.conns: 
            self.sending[name] = True
            # DH ratchet and symm 

            rk, ck, my_pk = self.dhRatchet(self.certs[name][1], self.certs[name][0]) #we dont use the first one


            ck, mk = self.symmRatchet(rk)
            self.conns[name] = Keys(self.certs[name][1],ck,mk,rk,my_pk)

            #encrypt the message with the resulting message key (mk)

            #my public key should go in the header             
        elif self.sending[name] is False:
            self.sending[name] = True
            self.conns[name].rk, self.conns[name].my_pk = self.dhRatchet(self.conns[name].pk, self.conns[name].rk)
            self.conns[name].ck, self.conns[name].mk = self.symmRatchet(self.root)

            #encrypt
            
            #DH ratchet and symm
        else:
            #NO DH ratchet, but symm ratchet
            self.conns[name].ck, self.conns[name].mk = self.symmRatchet(self.mk)

            #encrypt
            
        self.counter +=1    
        head = Header(self.conns[name].my_pk, self.counter)
        
        a = AESGCM(self.conns[name].mk)
        print(self.conns[name].mk)
        c = a.encrypt(nonce=bytes(str(self.counter), 'ascii'), data=bytes(message, 'ascii'), associated_data=self.conns[name].my_pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        
        return head, c
        
        

    def receiveMessage(self, name, header, ciphertext):

        self.conns[name] = header #loading this in
        if name not in self.sending:
            self.sending[name] = False
            # DH ratchet and symm 
            rk, ck, my_pk = self.dhRatchet(self.certs[name][1], self.certs[name][0]) #we dont use the first one
            ck, mk = self.symmRatchet(rk)
            self.conns[name] = Keys(self.certs[name][1],ck,mk,rk,my_pk)
        
        elif self.sending[name] == True:
            self.sending[name] = False
            self.conns[name].rk, self.conns[name].my_pk = self.dhRatchet(self.conns[name].pk, self.conns[name].rk)
            self.conns[name].ck, self.conns[name].mk = self.symmRatchet(self.root)
        
        else:
            self.conns[name].ck, self.conns[name].mk = self.symmRatchet(self.mk)
        a = AESGCM(self.conns[name].mk)
        print(self.conns[name].mk)
        message = a.decrypt(nonce=bytes(str(header.nonce), 'ascii'), data=ciphertext,associated_data=header.pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        return message
         
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
        
        root_key = key_der[32:63]
        chain_key = key_der[0:31]
        
        return root_key, chain_key, public_key

    def symmRatchet(self, chain_key):
        h = hmac.HMAC(chain_key, hashes.SHA256())

        h.update(b"0x02")

        new_chain = h.finalize()

        j = hmac.HMAC(chain_key, hashes.SHA256())

        j.update(b"0x01")

        new_message = j.finalize()

        return new_chain, new_message



class Certificate:
    
    def __init__(self, publicKey, userName):
        self.name = userName
        self.publicKey = publicKey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

class Keys:
    
    def __init__(self, their_publicKey, chainKey, messageKey, rootKey, my_pk):
        self.their_pk = their_publicKey
        self.ck = chainKey
        self.mk = messageKey
        self.rk = rootKey
        self.my_pk = my_pk

class Header:
    def __init__(self, pk, nonce):
        self.pk= pk
        self.nonce = nonce