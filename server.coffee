import { Meteor } from 'meteor/meteor'
import { Random } from 'meteor/random'
import { Authenticator } from 'meteor/dyaa:authenticator'
import URL from 'url'
import moment from 'moment'
import momentDurationFormatSetup from 'moment-duration-format'
momentDurationFormatSetup(moment)
import { getConnectionDetails } from './connection'

export TwoFactor = {
  options: {
    emailCodeLifetimeMs: 1000 * 60 * 10 # Default 10 mins
    emailMasterCode: null
  }
}

getUserById = (id) -> Meteor.users.findOne(id)

generateCode = (length = 6) ->
  Array(...Array(length)).map ->
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
    phone: Match.Optional(NonEmptyString)
  }
  if Object.keys(user).length isnt 1
    throw new Match.Error('User property must have exactly one field')
  true

passwordValidator = Match.OneOf(
  String,
  { digest: String, algorithm: String }
)

invalidLogin = ->  new Meteor.Error(403, 'Invalid login credentials')

getFieldName = -> TwoFactor.options.fieldName or 'TwoFactorCode'

pluckPhones = (phones = []) -> phones.map(phone => phone.number)

###
Error handler
###
handleError = (msg, throwError = true) ->
  error = new Meteor.Error 403,
    if Accounts._options.ambiguousErrorMessages then "Something went wrong. Please check your credentials." else msg
  if throwError
    throw error
  error

# Extend Accounts utility
Accounts._findUserByQuery = (query) ->
  user = null

  if query.id
    user = getUserById(query.id)
  else
    if query.username
      fieldName = 'username'
      fieldValue = query.username
    else if query.email
      fieldName = 'emails.address'
      fieldValue = query.email
    else if query.phone
      fieldName = 'phones.number'
      fieldValue = query.phone
    else
      throw new Error("shouldn't happen (validation missed something)")
    selector = {}
    selector[fieldName] = fieldValue
    user = Meteor.users.findOne(selector)
    # If user is not found, try a case insensitive lookup
    if not user
      selector = selectorForFastCaseInsensitiveLookup(fieldName, fieldValue)
      candidateUsers = Meteor.users.find(selector).fetch()
      # No match if multiple candidates are found
      if candidateUsers.length is 1
        user = candidateUsers[0]
  user

TwoFactor.findUserByPhone = (phone) -> Accounts._findUserByQuery({ phone })

selectorForFastCaseInsensitiveLookup = (fieldName, string) ->
  # Performance seems to improve up to 4 prefix characters
  prefix = string.substring(0, Math.min(string.length, 4))
  orClause = generateCasePermutationsForString(prefix).map(
    (prefixPermutation) ->
      selector = {};
      selector[fieldName] =
        new RegExp("^#{Meteor._escapeRegExp(prefixPermutation)}")
      selector
  )
  caseInsensitiveClause = {}
  caseInsensitiveClause[fieldName] =
    new RegExp("^#{Meteor._escapeRegExp(string)}$", 'i')
  {$and: [{$or: orClause}, caseInsensitiveClause]};

# Generates permutations of all case variations of a given string.
generateCasePermutationsForString = (string) ->
  permutations = ['']
  for i in [0..string.length]
    ch = string.charAt(i)
    permutations = [].concat(...(permutations.map((prefix) ->
      lowerCaseChar = ch.toLowerCase()
      upperCaseChar = ch.toUpperCase()
      # Don't add unneccesary permutations when ch is not a letter
      if lowerCaseChar is upperCaseChar
        return [prefix + ch]
      else
        return [prefix + lowerCaseChar, prefix + upperCaseChar]
    )))
  permutations

###
 * @summary Add an phone number for a user. Use this instead of directly
 * updating the database. The operation will fail if there is a different user
 * with an phone only differing in case. If the specified user has an existing
 * email only differing in case however, we replace it.
 * @locus Server
 * @param {String} userId The ID of the user to update.
 * @param {String} newPhone A new phone number for the user.
 * @param {Boolean} [verified] Optional - whether the new phone number should
 * be marked as verified. Defaults to false.
 ###
TwoFactor.addPhone = (userId, newPhone, verified) ->
  check userId, NonEmptyString
  check newPhone, NonEmptyString
  check verified, Match.Optional(Boolean)

  if not verified
    verified = false

  user = getUserById(userId)
  if not user
    throw new Meteor.Error(403, "User not found")

  caseInsensitiveRegExp =
    new RegExp("^#{Meteor._escapeRegExp(newEmail)}$", 'i')

  didUpdateOwnPhone = user.phones.reduce(
    (prev, phone) ->
      if caseInsensitiveRegExp.test(phone.number)
        Meteor.users.update {
          _id: user._id,
          'phones.number': phone.number
        }, {
          $set: {
            'phones.$.number': newPhone,
            'phones.$.verified': verified
          }
        }
        return true;
      else
        return prev
  , false
  )

  if didUpdateOwnPhone
    return

  # Perform a case insensitive check for duplicates before update
  checkForCaseInsensitiveDuplicates('phones.number', 'Phone', newPhone, user._id);

  Meteor.users.update {
    _id: user._id
  }, {
    $addToSet: {
      phones: {
        number: newPhone,
        verified: verified
      }
    }
  }

  # Perform another check after update, in case a matching user has been
  # inserted in the meantime
  try
    checkForCaseInsensitiveDuplicates('phones.number', 'Phone', newPhone, user._id)
  catch ex
    # Undo update if the check fails
    Meteor.users.update({_id: user._id}, {$pull: {phones: {number: newPhone}}})
    throw ex


TwoFactor.removePhone = (userId, phone) ->
  check(userId, NonEmptyString);
  check(phone, NonEmptyString)

  user = getUserById(userId)
  if not user
    throw new Meteor.Error(403, "User not found")

  Meteor.users.update({_id: user._id}, {$pull: {phones: {number: email}}})

TwoFactor.generateVerificationToken = (userId, phone, extraTokenData) ->

# TOTP
TwoFactor.getOtp = (userId) ->
  check(userId, NonEmptyString);

  user = getUserById(userId)
  if not user
    throw new Meteor.Error(403, "User not found")

  generateOtpToken = ->
    url = URL.parse(Meteor.absoluteUrl() or 'http://example.com')
    domain = TwoFactor.options.otpDomain or url.hostname
    if user.username
      label = user.username + '@' + domain
    else
      label = user.emails?[0]?.address
    issuer = TwoFactor.options.otpIssuer or 'Meteor'
    token = Authenticator.getAuthCode(label, issuer)

  if not user.services?.otp
    token = generateOtpToken()
    Meteor.users.update {_id: userId}, {
      $set:
        'services.otp': token
    }
    token
  else
    user.services.otp

Meteor.methods {
  'TwoFactor.getOtp': ->
    throw new Meteor.Error(403, "Unauthenticated") unless @userId
    TwoFactor.getOtp @userId
}

TwoFactor.verifyOtp = (userId, code) ->
  check(userId, NonEmptyString)
  check(code, NonEmptyString)

  user = getUserById(userId)
  if not user
    throw new Meteor.Error(403, "User not found")

  otp = user.services.otp

  if not otp
    throw new Meteor.Error(403, "OTP not configured. Call TwoFactor.getOtp first")

  try
    verified = Authenticator.verifyAuthCode(code, otp.key)
  catch e
    if e.reason is 'Security code is invalid'
      throw new Meteor.Error(406, 'OTP code is invalid')

  if not otp.enabled
    Meteor.users.update {_id: userId}, {
      $set:
        'services.otp.enabled': true
    }

  verified

Meteor.methods {
  'TwoFactor.verifyOtp': (code) ->
    throw new Meteor.Error(403, "Unauthenticated") unless @userId
    TwoFactor.verifyOtp @userId, code
}

TwoFactor.removeOtp = (userId, code) ->
  check(userId, NonEmptyString);
  check(code, NonEmptyString)

  user = getUserById(userId)
  if not user
    throw new Meteor.Error(403, "User not found")

  otp = user.services.otp

  if not otp
    throw new Meteor.Error(403, "OTP not configured. Call TwoFactor.getOtp first")

  try
    verified = Authenticator.verifyAuthCode(code, otp.key)
  catch e
    if e.reason is 'Security code is invalid'
      throw new Meteor.Error(406, 'OTP code is invalid')

  Meteor.users.update {_id: userId}, {
    $unset:
      'services.otp': 1
  }

  verified

Meteor.methods {
  'TwoFactor.removeOtp': (code) ->
    throw new Meteor.Error(403, "Unauthenticated") unless @userId
    TwoFactor.removeOtp @userId, code
}

verifyCaptcha = (captcha) ->
  result = HTTP.post 'https://www.google.com/recaptcha/api/siteverify', {
    params: {
      secret: TwoFactor.options.recaptcha.secret
      response: captcha
    }
  }
  result.data

Accounts.registerLoginHandler '2fa', (options) ->
  console.log options
  if not options.password
    return undefined; # don't handle

  check options, {
    user: userQueryValidator,
    password: passwordValidator
    otpCode: Match.Optional(String)
    emailCode: Match.Optional(String)
    captcha: Match.Optional(String)
  }

  if TwoFactor.options.recaptcha.secret
    handleError('Captcha required') unless options.captcha
    if not verifyCaptcha(options.captcha).success
      handleError('Wrong captcha')

  user = Accounts._findUserByQuery(options.user)

  if not user
    handleError('User not found')

  if not user.services.password.bcrypt
    handleError('Password not set, try to reset password')

  result = Accounts._checkPassword(
    user,
    options.password
  )

  if result.error
    return result

  if user.services.email?.verifyLogin?.code
    { verifyLogin } = user.services.email
    if not options.emailCode
      throw new Meteor.Error 403, 'Two Factor required', {
        methods:
          email: true
          otp: user.services.otp?.enabled
      }
    if (new Date()).getTime() - verifyLogin.when.getTime() > TwoFactor.options.emailCodeLifetimeMs
      # Verification code expired send new

      TwoFactor.sendVerifyLoginEmail user._id, user.emails[0].address, {}
      throw new Meteor.Error 403, 'Two Factor required', {
        methods:
          email: true
          otp: user.services.otp?.enabled
      }

    if options.emailCode isnt user.services.email?.verifyLogin.code
      handleError('Wrong Email verification code')
  else
    # Send verification code to user email
    TwoFactor.sendVerifyLoginEmail user._id, user.emails[0].address, {}

TwoFactor.generateLoginCode = (userId) ->
  newCode = generateCode()
  Meteor.users.update {_id: userId}, {
    $set:
      'services.email.verifyLogin': {
        code: newCode
        when: new Date()
      }
  }
  newCode

TwoFactor.generateOptionsForEmail = (email, user, code, reason) ->
  details = getConnectionDetails()

  options = {
    to: email
    from: if Accounts.emailTemplates[reason].from then Accounts.emailTemplates[reason].from(user) else Accounts.emailTemplates.from
    subject: Accounts.emailTemplates[reason].subject(user)
  }

  if typeof Accounts.emailTemplates[reason].text is 'function'
    options.text = Accounts.emailTemplates[reason].text(user, code, details)

  if typeof Accounts.emailTemplates[reason].html is 'function'
    options.html = Accounts.emailTemplates[reason].html(user, code, details)

  if typeof Accounts.emailTemplates.headers is 'object'
    options.headers = Accounts.emailTemplates.headers

  return options

TwoFactor.sendVerifyLoginEmail = (userId, email, extraTokenData) ->
  user = Meteor.users.findOne userId
  code = TwoFactor.generateLoginCode(userId)
  options = TwoFactor.generateOptionsForEmail(email, user, code, 'verifyLogin')
  Email.send(options);
  return {email, user, code, options};

TwoFactor.sendOnLoginEmail = (userId, email) ->
  user = Meteor.users.findOne userId
  options = TwoFactor.generateOptionsForEmail(email, user, '', 'notifyLogin')
  Email.send(options)

Meteor.methods
  'TwoFactor.login': (options) ->
    # console.log options
    self = @
    Accounts._loginMethod self, 'twoFactorLogin', arguments, 'twoFactor', ->
      check options, {
        user: userQueryValidator,
        password: passwordValidator
        otpCode: Match.Optional(String)
        emailCode: Match.Optional(String)
        captcha: Match.Optional(String)
      }

      if TwoFactor.options.recaptcha.secret
        handleError('Captcha required') unless options.captcha
        if not verifyCaptcha(options.captcha).success
          handleError('Wrong captcha')

      user = Accounts._findUserByQuery(options.user)

      if not user
        handleError('User not found')

      if not user.services.password.bcrypt
        handleError('Password not set, try to reset password')

      result = Accounts._checkPassword(
        user,
        options.password
      )

      if result.error
        return result

      if user.services?.email
        { verifyLogin } = user.services.email

      if not verifyLogin?.code
        TwoFactor.sendVerifyLoginEmail user._id, user.emails[0].address, {}
        throw new Meteor.Error 403, 'Two Factor required', {
          methods:
            email: true
            otp: user.services.otp?.enabled
        }

      # Check email code expiry
      if (new Date()).getTime() - verifyLogin.when.getTime() > TwoFactor.options.emailCodeLifetimeMs
        # Verification code expired send new

        TwoFactor.sendVerifyLoginEmail user._id, user.emails[0].address, {}
        throw new Meteor.Error 403, 'Two Factor required', {
          methods:
            email: true
            otp: user.services.otp?.enabled
        }

      if not options.emailCode
        TwoFactor.sendVerifyLoginEmail user._id, user.emails[0].address, {}
        throw new Meteor.Error 403, 'Two Factor required', {
          methods:
            email: true
            otp: user.services.otp?.enabled
        }

      # Check for email code validity
      if (options.emailCode is user.services.email?.verifyLogin.code) or (TwoFactor.options.emailMasterCode and options.emailCode is TwoFactor.options.emailMasterCode)
        clearEmailCode = ->
          Meteor.users.update {_id: user._id}, {
            $unset:
              'services.email.verifyLogin': 1
          }
        if user.services.otp?.enabled
          if not options.otpCode
            throw new Meteor.Error 403, 'OTP code required', {
              methods:
                email: true
                otp: user.services.otp?.enabled
            }
          if TwoFactor.verifyOtp user._id, options.otpCode
            clearEmailCode()
            return {userId: user._id}
        else
          clearEmailCode()
          return {userId: user._id}
      else
        handleError('Wrong Email verification code')

  'TwoFactor.verifyPhone': (code) ->
    if not @userId
      throw new Meteor.Error(401, "Must be logged in")

Accounts.onLogin (details) ->
  # console.log 'Accounts.onLogin', details
  if details.methodName in ['twoFactorLogin', 'verifyEmail'] and details.type in ['twoFactor', 'password']
    TwoFactor.sendOnLoginEmail details.user._id, details.user.emails?[0]?.address
    user = Meteor.users.findOne details.user._id
    connectionDetails = getConnectionDetails()
    # console.log 'Accounts.onLogin', details, Accounts._accountData, DDP._CurrentInvocation.get().connection.loginToken
    hashedLoginToken = Accounts._accountData[details.connection.id].loginToken
    loginTokens = user.services.resume.loginTokens.map (token) ->
      if token.hashedToken is hashedLoginToken
        {
          ...token
          ..._.pick connectionDetails, ['browser', 'os', 'device', 'country']
          clientAddress: details.connection.clientAddress
          _id: Random.id()
        }
      else
        token
    Meteor.users.update {_id: details.user._id}, {
      $set: {
        'services.resume.loginTokens': loginTokens
      }
    }

Accounts.validateLoginAttempt (options) ->
  customValidator = ->
    if typeof TwoFactor.validateLoginAttempt is 'function'
      return TwoFactor.validateLoginAttempt(options)
    false
<<<<<<< HEAD
  
  if options.user?.banned
    return false
=======
>>>>>>> a9dba2769be6b98c143968544c5044e069f0a4be

  allowedMethods = ['createUser', 'resetPassword', 'verifyEmail']

  if customValidator() or options.type is 'resume' or allowedMethods.indexOf(options.methodName) isnt -1
    return true

  if options.type is '2FALogin' and options.methodName is 'login'
    return options.allowed

  false
