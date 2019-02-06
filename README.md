
Scuttlebot plugin for sending messages using ephemeral keys over Secure Scuttlebutt

**Warning:** This is an experimental module, use at your own risk

## Why? 

Scuttlebutt messages cannot be deleted.  But sometimes we might want to send information to someone which we don't want to leave in the logs indefinitely, regardless of whether it is encrypted.  This is to give 'forward security' to account for the situation that a private key might be compromised in the future.

This module provides a way to do this by creating keypairs which are used just once for a specific message and can then be deleted. 

## Example - bob sends a message to alice

```js
var sbot = require('scuttlebot')
  .use(require('ssb-ephemeral-keys'))  
  .call(null, config)

const contextMessage = 'alice and bob' // this is included in the shared secret

// alice does this:
const dbKey = 'message from bob'

sbot.ephemeral.generateAndStore(dbKey, (err, pk) => {
  // she sends the public key, pk, in a request to bob

  // bob does this using the public key from alice:
  const message = 'its nice to be important but its more important to be nice'
  const boxedMsg = sbot.ephemeral.boxMessage(message, pk, contextMessage)
  // he sends the encrypted message, boxedMsg, to alice

  // alice decrypts the message like this:
  sbot.ephemeral.unBoxMessage(dbKey, boxedMsg, contextMessage, (err, msg) => {

    // after reading the message, msg, she deletes it's keypair and it is gone forever...    
    sbot.ephemeral.deleteKeyPair(dbKey, (err) => {
    })
  })
})
```

The `contextMessage` is optional.  If given, both alice and bob must use the same context message.

## API

### `generateAndStore(databaseKey, callback)` (async)

This function will generate a keypair, store the secret key
to disk, indexed by the given database key and return
the public key to be included in a request in the callback.

### `boxMessage(message, recipientPublicKey, contextMessage)` (sync)

This function will generate a keypair, encrypt a given shard to
a given ephemeral public key, delete the generated private key, 
and return the encrypted message encoded as a base64 string.
 
The context message is a string which, if given, is added to the shared
secret so that it may only be used for a specific purpose.

### `unBoxMessage(databaseKey, encryptedMessage, contextMessage, callback)` (async)

This function will grab a stored secret key from disk using the
given database key, use it to decrypt a given message and return the
result in the callback.

The context message is a string which is added to the shared
secret so that it may only be used for a specific purpose.

### `deleteKeyPair(dbKey, callback)` (async)

This function will delete a keyPair identified by the given database key
