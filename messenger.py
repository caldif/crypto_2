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
        nonce, u, cipher_text = ct
        v = self.server_decryption_key.exchange(ec.ECDH(), u)
        h = hashes.Hash(hashes.SHA256())
        h.update(u.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        h.update(v)
        k = h.finalize()
        a = AESGCM(k)
        message = a.decrypt(nonce=bytes(str(nonce), 'ascii'), data=cipher_text, associated_data=None)
        return str(message,encoding='utf-8')

    def signCert(self, cert):
        
        ecdsa = ec.ECDSA(hashes.SHA256())
        sig = self.server_signing_key.sign(pickle.dumps(cert), ecdsa)
        return sig

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns: dict[str, Keys] = {} #dict of {name, Keys(their_pk, mk, root, ck, my_pubk, my_privk)}
        self.certs = {}
        self.sending = {} #stores name of person talking to with a boolean of whether you sent the last message (true if it was you)
        self.private_key = None
        
        
        self.counter = 2**64
        self.reoprt_counter = 2**64


        #Need to save each root and chain for each person 
        

    def generateCertificate(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        pk = self.private_key.public_key()
        return Certificate(pk, self.name)

    def receiveCertificate(self, certificate, foreign_signature):
        ecdsa = ec.ECDSA(hashes.SHA256())
        self.server_signing_pk.verify(foreign_signature,pickle.dumps(certificate), ecdsa)
        self.certs[certificate.name] = [self.private_key.exchange(ec.ECDH(), load_pem_public_key(certificate.publicKey)), load_pem_public_key(certificate.publicKey)] #what is this???
        return 

    def sendMessage(self, name, message):
        if name not in self.conns: 
            self.sending[name] = True

            dh_out = self.certs[name][0]

            rk, ck = self.dhRatchet(dh_out, dh_out)

            ck, mk = self.symmRatchet(ck)

            self.conns[name] = Keys(self.certs[name][1],ck,mk,rk, self.private_key.public_key(),self.private_key)


        elif self.sending[name] is False:
            self.sending[name] = True

            #about to send a message so need new key pair
            private_key = ec.generate_private_key(ec.SECP256K1())
            public_key = private_key.public_key()
            self.conns[name].my_pubk = public_key
            self.conns[name].my_privk = private_key

            dh_out = self.conns[name].my_privk.exchange(ec.ECDH(), self.conns[name].their_pk)

            self.conns[name].rk, self.conns[name].ck = self.dhRatchet(self.conns[name].rk, dh_out)

            self.conns[name].ck, self.conns[name].mk = self.symmRatchet(self.conns[name].ck)
            


        else:
            #NO DH ratchet, but symm ratchet
            self.conns[name].ck, self.conns[name].mk = self.symmRatchet(self.conns[name].ck)

            
        self.counter +=1    
        head = Header(self.conns[name].my_pubk, self.counter)
        
        a = AESGCM(self.conns[name].mk)
        c = a.encrypt(nonce=bytes(str(self.counter), 'ascii'), data=bytes(message, 'ascii'), associated_data=self.conns[name].my_pubk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        
        return head, c 

    def receiveMessage(self, name, header, ciphertext):


        #first time receiving
        if name not in self.conns:
            self.sending[name] = False

            dh_out = self.certs[name][0]

            rk, ck = self.dhRatchet(dh_out, dh_out)

            ck, mk = self.symmRatchet(ck)

            self.conns[name] = Keys(header.pk,ck,mk,rk,self.private_key, self.private_key.public_key())

        elif self.conns[name].their_pk != header.pk:
            self.sending[name] = False

            self.conns[name].their_pk = header.pk

            dh_out = self.conns[name].my_privk.exchange(ec.ECDH(), header.pk)
            self.conns[name].rk, self.conns[name].ck = self.dhRatchet(self.conns[name].rk, dh_out)

            self.conns[name].ck, self.conns[name].mk = self.symmRatchet(self.conns[name].ck)
            
        else:
            self.conns[name].ck, self.conns[name].mk = self.symmRatchet(self.conns[name].ck)
        
        
        a = AESGCM(self.conns[name].mk)
        try:
            message = a.decrypt(nonce=bytes(str(header.nonce), 'ascii'), data=ciphertext,associated_data=header.pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        except:
            return None
        return str(message,encoding='utf-8')
         

    def report(self, name, message):
        y = ec.generate_private_key(ec.SECP256R1())
        u = y.public_key()
        v = y.exchange(ec.ECDH(), self.server_encryption_pk)
        h = hashes.Hash(hashes.SHA256())
        h.update(u.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        h.update(v)
        k = h.finalize()

        a = AESGCM(k)
        concated = name + message
        ct = a.encrypt(nonce=bytes(str(self.reoprt_counter), "ascii"), data=bytes(concated, 'ascii'), associated_data=None)
        out = (self.reoprt_counter, u, ct)
        self.reoprt_counter += 1

    
        return concated, out
    
    def dhRatchet(self, root, dh_out):
        #Key Derive
        key_der = HKDF(hashes.SHA256(),64, root, b'root key').derive(dh_out)
        
        root_key = key_der[32:63]
        chain_key = key_der[0:31]
        
        return root_key, chain_key

    def symmRatchet(self, chain_key):
        h = hmac.HMAC(bytes(chain_key), hashes.SHA256())

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
    
    def __init__(self, their_publicKey, chainKey, messageKey, rootKey, my_pubk, my_privk):
        self.their_pk = their_publicKey
        self.ck = chainKey
        self.mk = messageKey
        self.rk = rootKey
        self.my_pubk = my_pubk
        self.my_privk = my_privk

class Header:
    def __init__(self, pk, nonce):
        self.pk= pk
        self.nonce = nonce