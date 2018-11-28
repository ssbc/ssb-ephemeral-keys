//const { describe } = require('tape-plus')

const eph = require('..')

eph.generateAndStore('someKey', (err, pk) => {
  if (err) console.error(err)
  const bmsg = eph.boxMessage('hello',pk)  
  eph.unBoxMessage('someKey', bmsg, (err,msg) => {
     console.log(msg)
  })
})
