1. don't need n or pn because you don't have to handle out of order messages
2. every time alice sends a message, symmetric ratchet happens
3. when sender changes, alice v bob, new diffie hellman key 
4. receive certificates 
5. service public key is given in parameters
6. need to have a number of old keys stored
7. root key, send key, receieve key, DH key, server verification key, and one more 

When name changes, you make a new DH

self.conns is to store lists of conversations
- store conversations by storing their respective keys
- we make a server and they are the certificate authority

- we manage crypto for server
- we don't need to store our certificate but we are storing everyone we can talk to's certificate
