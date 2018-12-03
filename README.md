
Methods for sending messages using ephemeral keys over Secure Scuttlebutt

**Warning:** This module is experimental and is **not yet recommended** for use

## API

### `generateAndStore(databaseKey, callback)` 

This function will generate a keypair, store the secret key
to disk, indexed by the given database key and return
the public key to be included in a request.

### `boxMessage(message, recipientPublicKey, contextMessage)`

This function will generate a keypair, encrypt a given shard to
a given ephemeral public key, delete the generated private key, 
and return the encrypted message.
 
The context message is a short message which is added to the shared
secret so that it may only be used for a specific purpose.

### `unBoxMessage(databaseKey, encryptedMessage, contextMessage, callback)`

This function will grab a stored secret key from disk using the
given database key, use it to decrypt a given message and return the
result in the callback.  

The context message is a short message which is added to the shared
secret so that it may only be used for a specific purpose.

### `deleteKeyPair(dbKey, callback)`

This function will delete a keyPair identified by the given database key
