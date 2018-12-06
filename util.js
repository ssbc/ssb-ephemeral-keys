module.exports = {
  isString:
    function isString (variable) {
      return typeof variable === 'string'
    },
  assert:
    function assert (test, message) {
      if (!test) throw new Error(message || 'AssertionError')
    }
}
