const level = require('level')
var db = level('./db')

const sodium = require('sodium-native')
const secretBox = sodium.crypto_secretbox_easy
const secretBoxOpen = sodium.crypto_secretbox_open_easy
const NONCEBYTES = sodium.crypto_secretbox_NONCEBYTES
const KEYBYTES = sodium.crypto_secretbox_KEYBYTES

const concat = Buffer.concat
const curve = 'ed25519'

function randomBytes (n) {
  var b = Buffer.alloc(n)
  sodium.randombytes_buf(b)
  return b
}

function genericHash (msg) {
  var hash = sodium.sodium_malloc(sodium.crypto_generichash_BYTES_MAX)
  sodium.crypto_generichash(hash, msg)
  return hash
}

function scalarMult (sk, pk) {
  var result = sodium.sodium_malloc(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult(result, sk, pk)
  return result
}

function keyPair () {
  var ephKeys = {}
  ephKeys.publicKey = sodium.sodium_malloc(KEYBYTES)
  ephKeys.secretKey = sodium.sodium_malloc(KEYBYTES)
  sodium.crypto_box_keypair(ephKeys.publicKey, ephKeys.secretKey)
  return ephKeys
}

const packKey = k => k.toString('base64') + '.' + curve
const unpackKey = k => Buffer.from(k.slice(0, -curve.length - 1), 'base64')

module.exports = {

  generateAndStore: function (dbKey, callback) {
    const ephKeysBuffer = keyPair()
    var ephKeys = {}

    for (var k in ephKeysBuffer) ephKeys[k] = packKey(ephKeysBuffer[k])

    db.put(dbKey, ephKeys, {valueEncoding: 'json'}, (err) => {
      if (err) return callback(err)
      callback(null, ephKeys.publicKey)
    })
  },

  boxMessage: function (message, pubKeyBase64) {
    const contextMessage = Buffer.from('blah', 'utf-8')
    const messageBuffer = Buffer.from(message, 'utf-8')
    const pubKey = unpackKey(pubKeyBase64)
    var boxed = Buffer.alloc(messageBuffer.length + sodium.crypto_secretbox_MACBYTES)
    const ephKeys = keyPair()
    const nonce = randomBytes(NONCEBYTES)
    var sharedSecret = genericHash(concat([ genericHash(scalarMult(ephKeys.secretKey, pubKey)), ephKeys.publicKey, pubKey, contextMessage ]))
    secretBox(boxed, messageBuffer, nonce, sharedSecret)

    sharedSecret.fill(0)
    ephKeys.secretKey.fill(0)

    return concat([nonce, ephKeys.publicKey, boxed])
  },

  unBoxMessage: function (dbKey, fullMsg, callback) {
    db.get(dbKey, {valueEncoding: 'json'}, (err, ephKeysBase64) => {
      if (err) return callback(err)
      const contextMessage = Buffer.from('blah', 'utf-8')
      var ephKeys = {}
      for (var k in ephKeysBase64) ephKeys[k] = unpackKey(ephKeysBase64[k])
      const nonce = fullMsg.slice(0, NONCEBYTES)
      const pubKey = fullMsg.slice(NONCEBYTES, NONCEBYTES + KEYBYTES)
      const msg = fullMsg.slice(NONCEBYTES + KEYBYTES, fullMsg.length)
      var unboxed = Buffer.alloc(msg.length - sodium.crypto_secretbox_MACBYTES)

      var sharedSecret = genericHash(concat([ genericHash(scalarMult(ephKeys.secretKey, pubKey)), pubKey, ephKeys.publicKey, contextMessage ]))

      if (!secretBoxOpen(unboxed, msg, nonce, sharedSecret)) {
        sodium.sodium_memzero(sharedSecret)
        sodium.sodium_memzero(ephKeys.secretKey)
        sodium.sodium_memzero(ephKeys.publicKey)

        callback(new Error('Decryption failed'))
      } else {
        sodium.sodium_memzero(sharedSecret)
        sodium.sodium_memzero(ephKeys.secretKey)
        sodium.sodium_memzero(ephKeys.publicKey)

        callback(null, unboxed.toString())
      }
    })
  },

  deleteKeyPair: function (dbKey, callback) {
    db.del(dbKey, (err) => {
      if (err) return callback(err)
      callback()
    })
  }
}
