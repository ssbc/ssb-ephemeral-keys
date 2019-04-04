const mkdirp = require('mkdirp')
const { join } = require('path')
const fs = require('fs')
const skrub = require('skrub')

const { assert, isString, isObject } = require('./util')
const curve = 'curve25519'
const cipherTextSuffix = '.box'

const { keyPair, decryptMessage, encryptMessage } = require('./crypto')

const dbPath = 'ephemeral-keys'

module.exports = {
  name: 'ephemeral',
  version: require('./package.json').version,
  manifest: {
    generateAndStore: 'async',
    boxMessage: 'async',
    unBoxMessage: 'async',
    deleteKeypair: 'async'
  },
  init: function (server, config) {
    mkdirp.sync(join(config.path, dbPath))

    function generateAndStore (dbKey, callback) {
      const ephKeypairBuffer = keyPair()
      var ephKeypair = {}

      for (var k in ephKeypairBuffer) ephKeypair[k] = packKey(ephKeypairBuffer[k])

      fs.writeFile(buildFileName(dbKey), JSON.stringify(ephKeypair, null, 2), (err) => {
        if (err) return callback(err)
        callback(null, ephKeypair.publicKey)
      })
    }

    function boxMessage (message, pubKeyBase64, contextMessageString, callback) {
      assert(isString(message), 'Message must be a string')
      const messageBuffer = Buffer.from(message, 'utf-8')
      assert(isString(pubKeyBase64), 'Public key must be a string')
      const pubKey = unpackKey(pubKeyBase64)

      if (isObject(contextMessageString)) contextMessageString = JSON.stringify(contextMessageString)
      assert(isString(contextMessageString), 'Context message must be a string')
      const contextMessage = Buffer.from(contextMessageString, 'utf-8')

      callback(null, encryptMessage(pubKey, messageBuffer, contextMessage) + cipherTextSuffix)
    }

    function unBoxMessage (dbKey, cipherTextBase64, contextMessageString, callback) {
      if (isObject(contextMessageString)) contextMessageString = JSON.stringify(contextMessageString)
      assert(isString(contextMessageString), 'Context message must be a string')
      const contextMessage = Buffer.from(contextMessageString, 'utf-8')

      assert(isString(cipherTextBase64), 'Ciphertext must be a string')

      if (cipherTextBase64.slice(-1 * cipherTextSuffix.length) !== cipherTextSuffix) {
        return callback(new Error('Ciphertext must end in ' + cipherTextSuffix))
      }

      fs.readFile(buildFileName(dbKey), (err, data) => {
        if (err) return callback(err)
        const ephKeypairBase64 = JSON.parse(data)
        var ephKeypair = {}
        try {
          for (var k in ephKeypairBase64) ephKeypair[k] = unpackKey(ephKeypairBase64[k])
        } catch (err) {
          return callback(err)
        }

        var cipherText = Buffer.from(cipherTextBase64.slice(0, -1 * cipherTextSuffix.length), 'base64')
        const plainText = decryptMessage(cipherText, ephKeypair, contextMessage)
        if (!plainText) {
          callback(new Error('Decryption failed'))
        } else {
          callback(null, plainText)
        }
      })
    }

    function deleteKeyPair (dbKey, callback) {
      skrub([ buildFileName(dbKey) ], {dryRun: false}).then(
        paths => { callback() },
        err => callback(err)
      )
    }

    function buildFileName (dbKey) {
      return join(config.path, dbPath, dbKey)
    }

    return {
      generateAndStore,
      boxMessage,
      unBoxMessage,
      deleteKeyPair
    }

  }
}

const packKey = k => k.toString('base64') + '.' + curve

function unpackKey (k) {
  assert((k.split('.').slice(-1)[0] === curve), 'Encountered key with unsupported curve')
  return Buffer.from(k.slice(0, -curve.length - 1), 'base64')
}
