
const sodium = require('sodium-native')
const secretBox = sodium.crypto_secretbox_easy
const secretBoxOpen = sodium.crypto_secretbox_open_easy
const NONCEBYTES = sodium.crypto_secretbox_NONCEBYTES
const KEYBYTES = sodium.crypto_secretbox_KEYBYTES
const zero = sodium.sodium_memzero
const concat = Buffer.concat

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

function encryptMessage (pubKey, messageBuffer, contextMessage) {
  var boxed = Buffer.alloc(messageBuffer.length + sodium.crypto_secretbox_MACBYTES)
  const ephKeypair = keyPair()
  const nonce = randomBytes(NONCEBYTES)
  var sharedSecret = genericHash(
    concat([ ephKeypair.publicKey, pubKey, contextMessage ]),
    genericHash(scalarMult(ephKeypair.secretKey, pubKey)))

  secretBox(boxed, messageBuffer, nonce, sharedSecret)

  zero(sharedSecret)
  zero(ephKeypair.secretKey)
  return concat([nonce, ephKeypair.publicKey, boxed]).toString('base64')
}

function decryptMessage (cipherText, ephKeypair, contextMessage) {
  try {
    var nonce = cipherText.slice(0, NONCEBYTES)
    var pubKey = cipherText.slice(NONCEBYTES, NONCEBYTES + KEYBYTES)
    var box = cipherText.slice(NONCEBYTES + KEYBYTES, cipherText.length)
    var unboxed = Buffer.alloc(box.length - sodium.crypto_secretbox_MACBYTES)
  } catch (err) {
    return false
  }
  var sharedSecret = genericHash(
    concat([ pubKey, ephKeypair.publicKey, contextMessage ]),
    genericHash(scalarMult(ephKeypair.secretKey, pubKey)))

  const success = secretBoxOpen(unboxed, box, nonce, sharedSecret)
  zero(sharedSecret)
  zero(ephKeypair.secretKey)
  zero(ephKeypair.publicKey)
  return success ? unboxed.toString() : false
}

module.exports = {
  keyPair, decryptMessage, encryptMessage
}
