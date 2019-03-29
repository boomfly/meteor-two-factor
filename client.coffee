import * as RLocalStorage from 'meteor/simply:reactive-local-storage'
import phone from 'phone'
# state = new ReactiveDict('TwoFactor')
state = RLocalStorage

# state.setItem('user', '')
# state.setItem('password', '')
# state.setItem('verifying', false)
# state.setItem('method', '')

export TwoFactor = {}

getState = (name = 'TwoFactor.check') ->
  stateJson = RLocalStorage.getItem(name)
  if stateJson
    JSON.parse(stateJson)
  else
    return {}

setState = (newState, name = 'TwoFactor.check') ->
  state = getState()
  Object.assign(state, newState)
  RLocalStorage.setItem(name, JSON.stringify(state))
  state

clearState = (name = 'TwoFactor.check') ->
  state = getState()
  Object.assign state, {
    verifying: false
    user: ''
    phone: ''
    password: ''
    method: ''
    codeSentAt: ''
  }
  RLocalStorage.setItem(name, '{}')

getSelector = (user) ->
  if typeof user is 'string'
    if user.indexOf('@') isnt -1
      return { email: user }
    else
      normalizedPhone = phone(user)
      if normalizedPhone.length > 0
        normalizedPhone = normalizedPhone[0]
      if normalizedPhone
        return { 'phone.number': normalizedPhone }
      else
        return { username: user }
  return user

callbackHandler = (cb, handlerCb) ->
  return (error, result) ->
    if error
      return typeof cb is 'function' and cb(error)

    if typeof handlerCb is 'function'
      handlerCb(null, result)

    typeof cb is 'function' and cb(null, result)

registerMethod = (options, cb) ->
  options = {} unless options
  { phone, method } = options
  callback = callbackHandler cb, (error, result) ->
    state = getState('TwoFactor.newMethod')
    Object.assign state, {
      verifying: true
      phone: phone
      method: method
    }

    if method is 'phone'
      Object.assign state, {
        codeSentAt: new Date()
      }
    setState(state, 'TwoFactor.newMethod')

  Meteor.call 'TwoFactor.registerMethod', options, callback

getNewRegisterMethodCode = (cb) ->
  phone = state.getItem('user')
  password = state.getItem('password')
  callback = callbackHandler(cb)

  Meteor.call('TwoFactor.newMethod', 'phone', {phone}, callback)

verifyMethod = (options, cb) ->
  options = {} unless options
  { phone, method } = options
  callback = callbackHandler cb, (error, result) ->
    if not error
      state = getState('TwoFactor.newMethod')
      Object.assign state, {
        verifying: false
        method: ''
        codeSentAt: ''
      }
      setState(state, 'TwoFactor.newMethod')

  Meteor.call 'TwoFactor.verifyMethod', options, callback

getAuthCode = (user, password, cb) ->
  selector = getSelector(user)
  hashedPassword = null
  if not Meteor.userId()
    hashedPassword = Accounts._hashPassword(password)

  callback = callbackHandler cb, (error, result) ->
    state = getState()
    Object.assign state, {
      verifying: true
      user: user
      password: hashedPassword
      method: result
    }

    if result is 'phone'
      Object.assign state, {
        codeSentAt: new Date()
      }
    setState(state)

  Meteor.call 'TwoFactor.getAuthenticationCode', selector, hashedPassword, callback

getNewAuthCode = (cb) ->
  state = getState()
  selector = getSelector(state.user)
  password = state.password
  callback = callbackHandler(cb)

  Meteor.call 'TwoFactor.getAuthenticationCode', selector, password, callback

verifyAndLogin = (code, cb) ->
  state = getState()
  selector = getSelector(state.user)
  password = state.password

  Accounts.callLoginMethod {
    methodName: 'TwoFactor.verifyCodeAndLogin'
    methodArguments: [
      {
        user: selector
        password
        code
      }
    ]
    userCallback: callbackHandler cb, ->
      clearState()
  }

disable = (code, cb) ->
  callback = callbackHandler(cb)

  Meteor.call 'TwoFactor.disable', {code}, callback

isVerifying = -> state.getItem('verifying')
verificationMethod = -> state.getItem('method')
verifyingIdentity = -> state.getItem('user')
codeSentAt = -> state.getItem('codeSentAt')

abort = (cb) ->
  state = getState()
  selector = getSelector(state.user)
  password = state.password

  callback = (error, result) ->
    state = getState('TwoFactor.newMethod')
    Object.assign state, {
      verifying: false
      method: ''
      codeSentAt: ''
    }
    setState(state, 'TwoFactor.newMethod')
    clearState()
    # console.log('aborted')
    cb?(error, result)

  Meteor.call 'TwoFactor.abort', selector, password, callback

TwoFactor.getAuthCode = getAuthCode
TwoFactor.getNewAuthCode = getNewAuthCode
TwoFactor.verifyAndLogin = verifyAndLogin
TwoFactor.getState = getState
TwoFactor.registerMethod = registerMethod
TwoFactor.verifyMethod = verifyMethod
TwoFactor.abort = abort
TwoFactor.disable = disable
