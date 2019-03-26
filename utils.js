/**
 * Converts PublicKeyCredential into serialised JSON
 * @param  {Object} pubKeyCred
 * @return {Object}            - JSON encoded publicKeyCredential
 */

const base64 = require('./base64url-arraybuffer')

let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

    // Use a lookup table to find the index.
let lookup = new Uint8Array(256)
for (let i = 0; i < chars.length; i++) {
  lookup[chars.charCodeAt(i)] = i
}

let encode = function (arraybuffer) {
  let bytes = new Uint8Array(arraybuffer),
    i, len = bytes.length, base64url = ''

  for (i = 0; i < len; i += 3) {
    base64url += chars[bytes[i] >> 2]
    base64url += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)]
    base64url += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)]
    base64url += chars[bytes[i + 2] & 63]
  }

  if ((len % 3) === 2) {
    base64url = base64url.substring(0, base64url.length - 1)
  } else if (len % 3 === 1) {
    base64url = base64url.substring(0, base64url.length - 2)
  }

  return base64url
}

let decode = function (base64string) {
  let bufferLength = base64string.length * 0.75,
    len = base64string.length, i, p = 0,
    encoded1, encoded2, encoded3, encoded4

  let bytes = new Uint8Array(bufferLength)

  for (i = 0; i < len; i += 4) {
    encoded1 = lookup[base64string.charCodeAt(i)]
    encoded2 = lookup[base64string.charCodeAt(i + 1)]
    encoded3 = lookup[base64string.charCodeAt(i + 2)]
    encoded4 = lookup[base64string.charCodeAt(i + 3)]

    bytes[p++] = (encoded1 << 2) | (encoded2 >> 4)
    bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2)
    bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63)
  }

  return bytes.buffer
}

const publicKeyCredentialToJSON = (pubKeyCred) => {
  if (pubKeyCred instanceof Array) {
    let arr = []
    for (let i of pubKeyCred) { arr.push(publicKeyCredentialToJSON(i)) }

    return arr
  }

  if (pubKeyCred instanceof ArrayBuffer) {
    return encode(pubKeyCred)
  }

  if (pubKeyCred instanceof Object) {
    let obj = {}

    for (let key in pubKeyCred) {
      obj[key] = publicKeyCredentialToJSON(pubKeyCred[key])
    }

    return obj
  }

  return pubKeyCred
}

/**
 * Generate secure random buffer
 * @param  {Number} len - Length of the buffer (default 32 bytes)
 * @return {Uint8Array} - random string
 */
const generateRandomBuffer = (len) => {
  len = len || 32

  let randomBuffer = new Uint8Array(len)
  window.crypto.getRandomValues(randomBuffer)

  return randomBuffer
}

/**
 * Decodes arrayBuffer required fields.
 */
const preformatMakeCredReq = (makeCredReq) => {
  makeCredReq.challenge = new Uint8Array(decode(makeCredReq.challenge))
  makeCredReq.user.id = new Uint8Array(decode(makeCredReq.user.id))

  console.log('RET: ')
  console.log(makeCredReq)
  return makeCredReq
}

/**
 * Decodes arrayBuffer required fields.
 */
const preformatGetAssertReq = (getAssert) => {
  getAssert.challenge = decode(getAssert.challenge)

  for (let allowCred of getAssert.allowCredentials) {
    allowCred.id = decode(allowCred.id)
  }

  return getAssert
}

module.exports = {
  publicKeyCredentialToJSON,
  generateRandomBuffer,
  preformatMakeCredReq,
  preformatGetAssertReq
}
