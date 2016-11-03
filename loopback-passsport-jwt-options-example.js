module.exports = {
  authPath: '/auth'
  ,authOpts: {
    scope: []
  }
  ,jwt: {
    secretOrKey: 'ssssssssssssh',
    expiresInSeconds: (30)
  }
  ,facebook: {
    clientID: '-------',
    clientSecret: '--------',
    profileFields: ['id', 'displayName', 'photos', 'email'],
    scope: []
  }
  ,google: {
    clientID: '------',
    clientSecret: '------'
  }
  ,instagram: {
    clientID: '------',
    clientSecret: '------'
  }
  ,local: {
    usernameField: 'usename'
  }
};
