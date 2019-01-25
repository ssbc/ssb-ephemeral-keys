const { describe } = require('tape-plus')
const Server = function TestBot (opts) {
  return require('scuttle-testbot').use(require('..')).call(opts)
}

describe('Ephemeral Keys', context => {
  let server, message, dbKey, contextMessage

  context.beforeEach(c => {
    server = Server()
    message = 'its nice to be important but its more important to be nice'
    dbKey = 'someKey'
    contextMessage = 'test'
  })

  context.afterEach(c => {
    server.close()
  })

  context('Encrypts and decrypts successfully', (assert, next) => {
    server.ephemeral.generateAndStore(dbKey, (err, pk) => {
      assert.notOk(err, 'error from generating and storing keys is null')
      const boxedMsg = server.ephemeral.boxMessage(message, pk, contextMessage)
      server.ephemeral.unBoxMessage(dbKey, boxedMsg, contextMessage, (err, msg) => {
        assert.notOk(err, 'error from unbox is null')
        assert.equal(message, msg, 'output is the same as input')
        server.ephemeral.deleteKeyPair(dbKey, (err) => {
          assert.notOk(err, 'error from delete Keypair is null')
          server.ephemeral.unBoxMessage(dbKey, boxedMsg, contextMessage, (err, msg) => {
            assert.ok(err, 'fails to unencrypt message after deleting keys')
            assert.notOk(msg, 'returns no keys')
            next()
          })
        })
      })
    })
  })

  context('Encrypts and decrypts successfully using default context message if none is given', (assert, next) => {
    server.ephemeral.generateAndStore(dbKey, (err, pk) => {
      assert.notOk(err, 'error from generating and storing keys is null')
      const boxedMsg = server.ephemeral.boxMessage(message, pk)
      server.ephemeral.unBoxMessage(dbKey, boxedMsg, null, (err, msg) => {
        assert.notOk(err, 'error from unbox is null')
        assert.equal(message, msg, 'output is the same as input')
        next()
      })
    })
  })

  context('Returns an error when given the wrong message to decrypt', (assert, next) => {
    server.ephemeral.generateAndStore(dbKey, (err, pk) => {
      if (err) console.error(err)
      var boxedMsg = server.ephemeral.boxMessage(message, pk, contextMessage)
      boxedMsg = 'something else'
      server.ephemeral.unBoxMessage(dbKey, boxedMsg, contextMessage, (err, msg) => {
        assert.ok(err, 'throws error')
        assert.notOk(msg, 'message is null')
        next()
      })
    })
  })

  context('Throws an error when given an incorrect key', (assert, next) => {
    server.ephemeral.generateAndStore(dbKey, (err, pk) => {
      assert.notOk(err, 'error from generating and storing keys is null')
      const boxedMsg = server.ephemeral.boxMessage(message, pk)
      server.ephemeral.unBoxMessage('the wrong key', boxedMsg, null, (err, msg) => {
        assert.ok(err, 'throws error')
        assert.notOk(msg, 'msg is null')
        next()
      })
    })
  })

  // context('Throws error on encountering unsupported key type')
})
