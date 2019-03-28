Package.describe({
  name: 'boomfly:two-factor',
  version: '1.3.1',
  summary: 'Two-factor authentication for accounts-password',
  git: 'https://github.com/boomfly/meteor-two-factor.git',
  documentation: 'README.md',
});

Npm.depends({
  "moment": "2.20.0",
  "moment-duration-format": "2.2.1",
  "phone": "https://github.com/boomfly/node-phone/archive/835e80c6e15a97b6e3d63d1c593848ddbb2348fb.tar.gz"
});

Package.onUse(function(api) {
  api.versionsFrom('1.6');
  api.use(['ecmascript', 'coffeescript', 'check']);
  api.use('reactive-dict', 'client');
  api.use('accounts-password', ['client', 'server']);
  api.use('dyaa:authenticator', 'server');
  api.use('simply:reactive-local-storage', 'client');
  api.mainModule('client.coffee', 'client');
  api.mainModule('server.coffee', 'server');
});

Package.onTest(function(api) {
  api.use('ecmascript');
  api.use('tinytest');
  api.use('dburles:two-factor');
  api.addFiles('tests.js');
});
