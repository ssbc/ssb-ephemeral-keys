
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
  sbot.ephemeral.boxMessage(message, pk, contextMessage, (err, boxedMsg) => {

    // he sends the encrypted message, boxedMsg, to alice

    // alice decrypts the message like this:
    sbot.ephemeral.unBoxMessage(dbKey, boxedMsg, contextMessage, (err, msg) => {

      // after reading the message, msg, she deletes it's keypair and it is gone forever...    
      sbot.ephemeral.deleteKeyPair(dbKey, (err) => {
      })
    })
  })
})
```

The `contextMessage` is optional.  If given, both alice and bob must use the same context message.

## Security Review

First an ephemeral key is generated, and stored on the local system for later, under an arbitrary
key that the user selects. (since ssb is a async system for non-realtime communication it's necessary to store the ephemeral keys)

All keys are `curve25519` type.

### Encryption

A `message` is encrypted to a `recipientEphemeralKey` with a `contextMessage`.
The `contextMessage` serves to prevent ephemeral messages intended for one purpose
unusable for another purpose. A 24 byte random `nonce` is generated.

A `singleUseKey` is generated just for encrypting this message. A shared secret is generated,
via

```
// interpret + as concatinate.
sharedSecret = hash(
  singleUseKey.public +
  recipientEphemeralKey.public +
  contextMessage +
  hash(scalarmult(singleUseKey.private, recipientEphemeralKey.public)
)
```

then that is used to encrypt the message:

``` js
cyphertext = secretbox(message, nonce, sharedSecret)
```

The `sharedSecret` and `singleUseKey` are zerod,
and `nonce + singeUseKey.public + cyphertext` is returned.

### Decryption

The user has to know which stored ephemeral key is to be used.
Probably the stored key should be identified with a message id,
since they will need to post it to another peer so that they may encrypt to it.

To decrypt, the user receives

``` js
  ephemeral_message = nonce + singeUseKey.public + cyphertext
```
that is parsed, and from their stored ephemeralKey, (the `recipientEphemeralKey` that was sent to)
they reconstruct the shared secret,

``` js
sharedSecret = hash(
  singleUseKey.public +
  recipientEphemeralKey.public +
  contextMessage +
  hash(scalarmult(recipientEphemeralKey.private, singleUseKey.public)
)
```
and then that is used to decrypt the key.

### Comments on security

Although there is nothing wrong with the crypto operations used in this library,
It only solves half the problem, and leaves quite a bit of the responsibility of
implementing a secure system to the application which uses it. That is to say,
it's would be easy for the application to screw things up. For example,
by not deleting the key, or reusing the key too many times.

## API

### `generateAndStore(databaseKey, callback)` (async)

This function will generate a keypair, store the secret key
to disk, indexed by the given database key and return
the public key to be included in a request in the callback.

### `boxMessage(message, recipientPublicKey, contextMessage, cb)` (async)

This function will generate a keypair, encrypt a given shard to
a given ephemeral public key, delete the generated private key, 
and return the encrypted message encoded as a base64 string in the callback.
 
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

