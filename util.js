module.exports = {
  isString:
    function isString (variable) {
      return typeof variable === 'string'
    },
  isObject:
    function isObject (o) {
      return typeof o === 'object'
    },
  assert:
    function assert (test, message) {
      if (!test) throw new Error(message || 'AssertionError')
    }
}
