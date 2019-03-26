
class WebAuthnRequests {
  constructor (
    _responsePath = '/response',
    _registerPath = '/register',
    _loginPath = '/login'
   ) {
    this.responsePath = _responsePath
    this.registerPath = _registerPath
    this.loginPath = _loginPath
  }

  sendWebAuthnResponse (body) {
    return fetch('/webauthn/response', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    })
      .then((response) => response.json())
      .then((response) => {
        if (response.status !== 'ok') { throw new Error(`Server responed with error. The message is: ${response.message}`) }

        return response
      })
  }

  getMakeCredentialsChallenge (formBody) {
    return fetch('/webauthn/register', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formBody)
    })
  .then((response) => response.json())
  .then((response) => {
    if (response.status !== 'ok') { throw new Error(`Server responed with error. The message is: ${response.message}`) }

    return response.body
  }).catch(error => {
    console.error(error)
  })
  }

  getGetAssertionChallenge ({username}) {
    return fetch('/webauthn/login', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({username})
    })
      .then((response) => response.json())
      .then((response) => {
        if (response.status !== 'ok') { throw new Error(`Server responed with error. The message is: ${response.message}`) }

        return response
      })
  }
}

module.exports.WebAuthnRequests = WebAuthnRequests
