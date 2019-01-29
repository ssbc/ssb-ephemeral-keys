const mkdirp = require('mkdirp')
const { join } = require('path')
const level = require('level')
const sodium = require('sodium-native')
const { assert, isString } = require('./util')

const secretBox = sodium.crypto_secretbox_easy
const secretBoxOpen = sodium.crypto_secretbox_open_easy
const NONCEBYTES = sodium.crypto_secretbox_NONCEBYTES
const KEYBYTES = sodium.crypto_secretbox_KEYBYTES
const zero = sodium.sodium_memzero
const concat = Buffer.concat
const curve = 'curve25519'
const defaultContextMessage = 'SSB Ephemeral key'
const cipherTextSuffix = '.box'

module.exports = {
  name: 'ephemeral',
  version: require('./package.json').version,
  manifest: {
    generateAndStore: 'async',
    boxMessage: 'sync',
    unBoxMessage: 'async',
    deleteKeypair: 'async'
  },
  init: function (server, config) {
    mkdirp.sync(join(config.path, 'ephemeral-keys'))
    const db = level(join(config.path, 'ephemeral-keys'), {
      // valueEncoding: charwise // TODO: ?
    })

    function generateAndStore (dbKey, callback) {
      const ephKeypairBuffer = keyPair()
      var ephKeypair = {}

      for (var k in ephKeypairBuffer) ephKeypair[k] = packKey(ephKeypairBuffer[k])

      db.put(dbKey, ephKeypair, {valueEncoding: 'json'}, (err) => {
        if (err) return callback(err)
        callback(null, ephKeypair.publicKey)
      })
    }

    function boxMessage (message, pubKeyBase64, contextMessageString) {
      assert(isString(message), 'Message must be a string')
      const messageBuffer = Buffer.from(message, 'utf-8')

      assert(isString(pubKeyBase64), 'Public key must be a string')
      const pubKey = unpackKey(pubKeyBase64)

      contextMessageString = contextMessageString || defaultContextMessage
      assert(isString(contextMessageString), 'Context message must be a string')
      const contextMessage = Buffer.from(contextMessageString, 'utf-8')

      var boxed = Buffer.alloc(messageBuffer.length + sodium.crypto_secretbox_MACBYTES)
      const ephKeypair = keyPair()
      const nonce = randomBytes(NONCEBYTES)

      var sharedSecret = genericHash(
        concat([ ephKeypair.publicKey, pubKey, contextMessage ]),
        genericHash(scalarMult(ephKeypair.secretKey, pubKey)))

      secretBox(boxed, messageBuffer, nonce, sharedSecret)

      zero(sharedSecret)
      zero(ephKeypair.secretKey)

      return concat([nonce, ephKeypair.publicKey, boxed]).toString('base64') + cipherTextSuffix
    }

    function unBoxMessage (dbKey, cipherTextBase64, contextMessageString, callback) {
      if (isFunction(contextMessageString) && !callback) {
        callback = contextMessageString
        contextMessageString = defaultContextMessage
      }

      contextMessageString = contextMessageString || defaultContextMessage
      assert(isString(contextMessageString), 'Context message must be a string')
      const contextMessage = Buffer.from(contextMessageString, 'utf-8')

      assert(isString(cipherTextBase64), 'Ciphertext must be a string')

      if (cipherTextBase64.slice(-1 * cipherTextSuffix.length) !== cipherTextSuffix) {
        return callback(new Error('Ciphertext must end in ' + cipherTextSuffix))
      }

      try {
        var cipherText = Buffer.from(cipherTextBase64.slice(0, -1 * cipherTextSuffix.length), 'base64')
        var nonce = cipherText.slice(0, NONCEBYTES)
        var pubKey = cipherText.slice(NONCEBYTES, NONCEBYTES + KEYBYTES)
        var box = cipherText.slice(NONCEBYTES + KEYBYTES, cipherText.length)
        var unboxed = Buffer.alloc(box.length - sodium.crypto_secretbox_MACBYTES)
      } catch (err) {
        return callback(new Error('Invalid ciphertext'))
      }

      db.get(dbKey, {valueEncoding: 'json'}, (err, ephKeypairBase64) => {
        if (err) return callback(err)

        var ephKeypair = {}
        try {
          for (var k in ephKeypairBase64) ephKeypair[k] = unpackKey(ephKeypairBase64[k])
        } catch (err) {
          return callback(err)
        }

        var sharedSecret = genericHash(
          concat([ pubKey, ephKeypair.publicKey, contextMessage ]),
          genericHash(scalarMult(ephKeypair.secretKey, pubKey)))

        const success = secretBoxOpen(unboxed, box, nonce, sharedSecret)
        zero(sharedSecret)
        zero(ephKeypair.secretKey)
        zero(ephKeypair.publicKey)

        if (!success) {
          callback(new Error('Decryption failed'))
        } else {
          callback(null, unboxed.toString())
        }
      })
    }

    function deleteKeyPair (dbKey, callback) {
      db.del(dbKey, (err) => {
        if (err) return callback(err)
        callback()
      })
    }

    return {
      generateAndStore,
      boxMessage,
      unBoxMessage,
      deleteKeyPair
    }
  }
}

function randomBytes (n) {
  var b = Buffer.alloc(n)
  sodium.randombytes_buf(b)
  return b
}

function genericHash (msg, key) {
  var hash = sodium.sodium_malloc(sodium.crypto_generichash_BYTES_MAX)
  sodium.crypto_generichash(hash, msg, key)
  return hash
}

function scalarMult (sk, pk) {
  var result = sodium.sodium_malloc(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult(result, sk, pk)
  return result
}

function keyPair () {
  var ephKeypair = {}
  ephKeypair.publicKey = sodium.sodium_malloc(KEYBYTES)
  ephKeypair.secretKey = sodium.sodium_malloc(KEYBYTES)
  sodium.crypto_box_keypair(ephKeypair.publicKey, ephKeypair.secretKey)
  return ephKeypair
}

const packKey = k => k.toString('base64') + '.' + curve

function unpackKey (k) {
  assert((k.split('.').slice(-1)[0] === curve), 'Encountered key with unsupported curve')
  return Buffer.from(k.slice(0, -curve.length - 1), 'base64')
}

function isFunction (f) {
  return typeof f === 'function'
}
