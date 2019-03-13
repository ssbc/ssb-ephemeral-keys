module.exports = {
  isString:
    function isString (variable) {
      return typeof variable === 'string'
    },
  isFunction:
    function isFunction (f) {
      return typeof f === 'function'
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
