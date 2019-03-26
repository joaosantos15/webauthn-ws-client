const {WebAuthnRequests} = require('./webAuthnRequests')
const utils = require('./utils')
class WebAuthnHandler {
  constructor () {
    this.webAuthnRequests = new WebAuthnRequests()
  }

  async handleRegistration (username, name, secret) {
    let authResponse
    try {
      const response = await this.webAuthnRequests.getMakeCredentialsChallenge({username, name, secret})
      let publicKey = utils.preformatMakeCredReq(response)
      const credential = await navigator.credentials.create({publicKey})
      let makeCredResponse = utils.publicKeyCredentialToJSON(credential)
      makeCredResponse.username = username
      authResponse = await this.webAuthnRequests.sendWebAuthnResponse(makeCredResponse)
    } catch (error) {
      console.error(error.message)
      return new Error('Failed to process registration: ' + error)
    }
    return authResponse
  }

  async handleLogin2 (username) {
    this.webAuthnRequests.getGetAssertionChallenge({username})
    .then((response) => {
      let publicKey = utils.preformatGetAssertReq(response)
    //   publicKey.rp = {}
    //   publicKey.rp.id = 'localhost'

      return navigator.credentials.get({ publicKey })
    })
    .then((response) => {
      let getAssertionResponse = utils.publicKeyCredentialToJSON(response)
      getAssertionResponse.username = username
      return this.webAuthnRequests.sendWebAuthnResponse(getAssertionResponse)
    })
    .then((response) => {
      if (response.status === 'ok') {
        alert('You are LOGGED IN!! 🚀🚀')
      } else {
        alert(`Server responed with error. The message is: ${response.message}`)
      }
    })
    .catch((error) => alert(error))
  }

  async handleLogin (username) {
    try {
      const response = await this.webAuthnRequests.getGetAssertionChallenge({username})
      let publicKey = utils.preformatGetAssertReq(response)
      const credential = await navigator.credentials.get({ publicKey })
      let getAssertionResponse = utils.publicKeyCredentialToJSON(credential)
      getAssertionResponse.username = username
      const webauthnResponse = await this.webAuthnRequests.sendWebAuthnResponse(getAssertionResponse)
      return webauthnResponse
    } catch (error) {
      console.error(error.message)
      throw new Error('Error loging in: ' + error)
    }
  }
}

module.exports.WebAuthnHandler = WebAuthnHandler
