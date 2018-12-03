const { describe } = require('tape-plus')

const eph = require('..')

const contextMessage = 'test'


describe('Ephemeral Keys', context => {
  let message, dbKey

  context.beforeEach(c => {
    message = 'its nice to be important but its more important to be nice'
    dbKey = 'someKey'
  })

  context('Encrypts and decrypts successfully', (assert, next) => {
    eph.generateAndStore(dbKey, (err, pk) => {
      assert.notOk(err, 'error from generating and storing keys is null')
      const boxedMsg = eph.boxMessage(message, pk, contextMessage)
      eph.unBoxMessage('someKey', boxedMsg, contextMessage, (err, msg) => {
        assert.notOk(err, 'error from unbox is null')
        assert.equal(message, msg, 'output is the same as input')
        eph.deleteKeyPair(dbKey, (err) => {
          assert.notOk(err, 'error from delete Keypair is null')
          eph.unBoxMessage('someKey', boxedMsg, contextMessage, (err, msg) => {
            assert.ok(err, 'fails to unencrypt message after deleting keys')
            assert.notOk(msg, 'returns no keys')
            next()
          })
        })
      })
    })
  })
})
