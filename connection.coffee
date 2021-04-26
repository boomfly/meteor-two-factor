import { DDP } from 'meteor/ddp'
import UAParser from 'ua-parser-js'
import geoip from 'geoip-lite'

export getConnectionDetails = ->
  connection = DDP._CurrentInvocation.get().connection
  # console.log connection
  parser = new UAParser connection.httpHeaders['user-agent']
  userAgent = parser.getResult()
  geo = geoip.lookup connection.clientAddress
  if geo
    country = "#{geo?.country}/#{geo?.city}"
  details = {
    ..._.pick userAgent, ['browser', 'os', 'device']
    clientAddress: connection.clientAddress
    country
    _id: Random.id()
  }
