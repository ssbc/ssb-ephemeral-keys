
`generateAndStore(dbKey, callback)` 
This function will generate a keypair, store the secret key
to disk, indexed by the given database key and return
the public key to be included in a request

`boxMessage(message, pubKeyBase64)`
This function will generate a keypair, encrypt a given shard to
a given public key, delete the generated private key, and return
the message
  
`unBoxMessage(dbKey, fullMsg, callback)`
This function will grab a stored secret key from disk, using the
given dbKey, use it to decrypt a given message and return the
result in the callback


`deleteKeyPair(dbKey, callback)`
This function will delete a keyPair identified by dbKey
