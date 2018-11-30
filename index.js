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
  var hash = Buffer.alloc(sodium.crypto_generichash_BYTES_MAX)
  sodium.crypto_generichash(hash, msg)
  return hash
}

function scalarMult (sk, pk) {
  var result = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult(result, sk, pk)
  return result
}

function keyPair () {
  var ephKeys = {}
  ephKeys.publicKey = Buffer.alloc(KEYBYTES)
  ephKeys.secretKey = Buffer.alloc(KEYBYTES)
  sodium.crypto_box_keypair(ephKeys.publicKey, ephKeys.secretKey)
  return ephKeys
}

const packKey = k => k.toString('base64') + '.' + curve
const unpackKey = k => Buffer.from(k.slice(0, -curve.length - 1), 'base64')


module.exports = {

  // this function will generate a keypair, store the secret key
  // to disk, indexed by the given database key and return
  // the public key to be included in a request

  // Note: in the case of dark-crystal the dbKey will be a rootId
  //       and a recipient feed id.  either concatonated or json.

  generateAndStore: function (dbKey, callback) {
    const ephKeysBuffer = keyPair()
    var ephKeys = {}

    for (var k in ephKeysBuffer) ephKeys[k] = packKey(ephKeysBuffer[k])

    db.put(dbKey, ephKeys, {valueEncoding: 'json'}, (err) => {
      if (err) return callback(err)
      callback(null, ephKeys.publicKey)
    })
  },

  // this function will generate a keypair, encrypt a given shard to
  // a given public key, delete the generated private key, and return
  // the message

  boxMessage: function (message, pubKeyBase64) {
    const messageBuffer = Buffer.from(message, 'utf-8')
    const pubKey = unpackKey(pubKeyBase64)
    var boxed = Buffer.alloc(messageBuffer.length + sodium.crypto_secretbox_MACBYTES)
    const ephKeys = keyPair()
    const nonce = randomBytes(NONCEBYTES)
    var sharedSecret = genericHash(concat([ ephKeys.publicKey, pubKey, genericHash(scalarMult(ephKeys.secretKey, pubKey)) ]))
    secretBox(boxed, messageBuffer, nonce, sharedSecret)

    sharedSecret.fill(0)
    ephKeys.secretKey.fill(0)

    return concat([nonce, ephKeys.publicKey, boxed])
  },

  // this function will grab a stored secret key from disk, using the
  // given dbKey, use it to decrypt a given message and return the
  // result in the callback

  unBoxMessage: function (dbKey, fullMsg, callback) {
    db.get(dbKey, {valueEncoding: 'json'}, (err, ephKeysBase64) => {
      if (err) return callback(err)
      var ephKeys = {}
      for (var k in ephKeysBase64) ephKeys[k] = unpackKey(ephKeysBase64[k])
      const nonce = fullMsg.slice(0, NONCEBYTES)
      const pubKey = fullMsg.slice(NONCEBYTES, NONCEBYTES + KEYBYTES)
      const msg = fullMsg.slice(NONCEBYTES + KEYBYTES, fullMsg.length)
      var unboxed = Buffer.alloc(msg.length - sodium.crypto_secretbox_MACBYTES)
      var sharedSecret = genericHash(concat([ pubKey, ephKeys.publicKey, genericHash(scalarMult(ephKeys.secretKey, pubKey)) ]))
      secretBoxOpen(unboxed, msg, nonce, sharedSecret)

      sharedSecret.fill(0)
      ephKeys.secretKey.fill(0)
      ephKeys.publicKey.fill(0)

      callback(null, unboxed.toString())
    })
  },

  // this function will delete a keyPair identified by dbKey

  deleteKeyPair: function (dbKey, callback) {
    db.del(dbKey, (err) => {
      if (err) return callback(err)
      callback()
    })
  }
}
