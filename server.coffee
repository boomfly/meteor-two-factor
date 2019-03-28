import Authenticator from 'meteor/dyaa:authenticator'
import moment from 'moment'
import momentDurationFormatSetup from 'moment-duration-format'
momentDurationFormatSetup(moment)

export TwoFactor = {
  options: {}
}

generateCode = ->
  Array(...Array(6)).map ->
    Math.floor(Math.random() * 10)
  .join('')

NonEmptyString = Match.Where (x) ->
  check(x, String)
  x.length > 0

userQueryValidator = Match.Where (user) ->
  check user, {
    id: Match.Optional(NonEmptyString)
    username: Match.Optional(NonEmptyString)
    email: Match.Optional(NonEmptyString)
  }
  if Object.keys(user).length isnt 1
    throw new Match.Error('User property must have exactly one field')
  true

passwordValidator = { digest: String, algorithm: String }

invalidLogin = ->  new Meteor.Error(403, 'Invalid login credentials')

getFieldName = -> TwoFactor.options.fieldName or 'TwoFactorCode'

Meteor.methods
  'TwoFactor.registerMethod': (options) ->
    throw new Meteor.Error(403, 'Access restricted') unless this.userId
    currentUser = Meteor.users.findOne(this.userId)
    { method } = options
    # if (!currentUser.TwoFactor) {
    #   # Set user common TwoFactor property with empty object
    #   Meteor.users.update(
    #     {_id: this.userId},
    #     {
    #       $set: {
    #         TwoFactor: currentUser.TwoFactor = {}
    #       }
    #     }
    #   )
    # }
    switch method
      when 'google-authenticator'
        # Generate new totp from google and set to newToken
        domain = TwoFactor.options.googleAuthenticatorDomain or 'example.com'
        label = currentUser.username + '@' + domain
        # issuer = TwoFactor.options.googleAuthenticatorIssuer
        issuer = ''
        token = Authenticator.getAuthCode(label, issuer)
        Meteor.users.update {_id: this.userId}, {
          $set:
            'googleAuthenticator.newToken': token
        }
        return token

      when 'phone'
        { phone } = options
        if currentUser.newPhone and currentUser.newPhone.codeSentAt
          limitTimeoutMin = 1
          currentTime = moment()
          codeSentAt = moment(currentUser.newPhone.codeSentAt)
          deadline = codeSentAt.add(limitTimeoutMin, 'minutes')
          elapsedTimeString = moment.duration(deadline.diff(currentTime), "milliseconds").format(
            'mm[m] ss[s]',
            {trim: false}
          )
          if currentTime.isBefore(deadline)
            throw new Meteor.Error(403, 'Too many calls', {timeout: elapsedTimeString})
        code = if typeof TwoFactor.generateCode is 'function' then TwoFactor.generateCode() else generateCode()
        newPhone =  {
          number: phone,
          code,
          codeSentAt: new Date()
        }
        Meteor.users.update {_id: this.userId}, {
          $set:
            newPhone
        }
        if typeof TwoFactor.sendCode is 'function'
          TwoFactor.sendCode(newPhone.number, code)
        # return from 'phone' condition
        return
      else
        throw new Meteor.Error(500, 'Unknown method')

  'TwoFactor.verifyMethod': (options) ->
    throw new Meteor.Error(403, 'Access restricted') unless this.userId
    currentUser = Meteor.users.findOne(this.userId)
    { method, code } = options

    switch method
      when 'google-authenticator'
        if not currentUser.googleAuthenticator or not currentUser.googleAuthenticator.newToken
          throw new Meteor.Error(400, 'Call begin method first')
        newToken = currentUser.googleAuthenticator.newToken
        verified = null
        try
          verified = Authenticator.verifyAuthCode(code, newToken.key)
        catch e
          if e.reason is 'Security code is invalid'
            throw new Meteor.Error(406, 'Security code is invalid')

        if verified
          Meteor.users.update {_id: this.userId}, {
            $set:
              'googleAuthenticator.token': newToken
              'googleAuthenticator.enabled': true
            $unset:
              'googleAuthenticator.newToken': 1
          }
        # return from GA
        return newToken

      when 'phone'
        newPhone = currentUser.newPhone
        if newPhone and newPhone.code is code
          Meteor.users.update {_id: this.userId}, {
            $set:
              'phone.number': newPhone.number
              'phone.verified': true
              'phone.enabled': true
            $unset:
              newPhone: 1
          }
        else
          throw new Meteor.Error(403, 'Invalid code')
        return
      else
        throw new Meteor.Error(500, 'Unknown method')

  'TwoFactor.disable': (options) ->
    console.log('TwoFactor.disable', options)
    throw new Meteor.Error(403, 'Access restricted') unless this.userId
    currentUser = Meteor.users.findOne(this.userId)
    options = {} unless options
    { code } = options

    if currentUser.googleAuthenticator and currentUser.googleAuthenticator.enabled
      token = currentUser.googleAuthenticator.token
      verified = null
      try
        verified = Authenticator.verifyAuthCode(code, token.key)
      catch e
        if e.reason is 'Security code is invalid'
          throw new Meteor.Error(406, 'Security code is invalid')
      if verified
        Meteor.users.update this.userId, {
          $set:
            'googleAuthenticator.enabled': false
          $unset:
            'googleAuthenticator.newToken': 1
        }
    else if currentUser.phone and currentUser.phone.enabled
      codeSentAt = moment(currentUser.phone.codeSentAt)

      if options.code isnt currentUser.phone.code
        throw new Meteor.Error(406, 'Security code is invalid');

      Meteor.users.update this.userId, {
        $set:
          'phone.enabled': false
        $unset:
          'phone.code': '',
          'phone.codeSentAt': '',
          'newPhone': '',
      }

  'TwoFactor.getAuthenticationCode': (userQuery, password) ->
    check(userQuery, userQueryValidator)
    check(password, passwordValidator)

    fieldName = getFieldName()

    user = Accounts._findUserByQuery(userQuery)
    throw invalidLogin() unless user

    checkPassword = Accounts._checkPassword(user, password)
    throw invalidLogin() if checkPassword.error

    code = if typeof TwoFactor.generateCode is 'function' then TwoFactor.generateCode() else generateCode()

    if typeof TwoFactor.sendCode is 'function'
      TwoFactor.sendCode(user, code)

    Meteor.users.update user._id, {
      $set:
        [fieldName]: code
    }

  'TwoFactor.verifyCodeAndLogin': (options) ->
    check options, {
      user: userQueryValidator
      password: passwordValidator
      code: String
    }

    fieldName = getFieldName()

    user = Accounts._findUserByQuery(options.user)
    if not user
      throw invalidLogin()

    checkPassword = Accounts._checkPassword(user, options.password)
    if checkPassword.error
      throw invalidLogin()

    if options.code isnt user[fieldName]
      throw new Meteor.Error(403, 'Invalid code')

    Meteor.users.update user._id, {
      $unset:
        [fieldName]: ''
    }

    Accounts._attemptLogin this, 'login', '', {
      type: '2FALogin'
      userId: user._id
    }

  'TwoFactor.abort': (userQuery, password) ->
    check(userQuery, userQueryValidator)
    check(password, passwordValidator)

    fieldName = getFieldName()

    user = Accounts._findUserByQuery(userQuery)
    if not user
      throw invalidLogin()

    checkPassword = Accounts._checkPassword(user, password)
    if checkPassword.error
      throw invalidLogin()

    Meteor.users.update user._id, {
      $unset:
        [fieldName]: ''
    }

Accounts.validateLoginAttempt (options) ->
  customValidator = ->
    if typeof TwoFactor.validateLoginAttempt is 'function'
      return TwoFactor.validateLoginAttempt(options)
    false

  allowedMethods = ['createUser', 'resetPassword', 'verifyEmail']

  if customValidator() or options.type is 'resume' or allowedMethods.indexOf(options.methodName) isnt -1
    return true

  if options.type is '2FALogin' and options.methodName is 'login'
    return options.allowed

  false
