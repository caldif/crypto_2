import os
import pickle
import string
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


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
        self.certs = {}
        self.private_key = None
        

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
            return
        raise Exception("not implemented!")
        return

    def receiveMessage(self, name, header, ciphertext):
        raise Exception("not implemented!")
        return

    def report(self, name, message):
        raise Exception("not implemented!")
        return


class Certificate:
    
    def __init__(self, publicKey, userName):
        self.name = userName
        self.publicKey = publicKey