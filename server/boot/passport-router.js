'use strict';

module.exports = function(app) {
  var router = app.loopback.Router();
  var jwt = require('jsonwebtoken');

  var AuthUser = app.models.AuthUser;

  var passport = require('passport');
  var FacebookStrategy = require('passport-facebook').Strategy;
  //var googleStrategy = require('passport-google').Strategy;

  //facebook auth setup
  var options = {
    secret: 'ssssssssssssh',
    expiresInSeconds: (30),
    authPath: '/auth',
    facebook: {
      clientID: '882422281866614',
      clientSecret: '5fcf8f7efb718e447e22c7dee5458121',
      callbackURL: 'http://localhost:3000/auth/facebook/callback',
      profileFields: ['id', 'displayName', 'photos', 'email']
    }
  };
  passport.use(
       new FacebookStrategy(
           options.facebook,
           function(accessToken, refreshToken, profile, done) {
               console.log('profile: '+ JSON.stringify(profile));
               AuthUser.replaceOrCreate(
                   { facebookId: profile.id },
                   function (err, result) {
                       if(result) {
                           result.email = result.email ? result.email : profile.email;
                           result.facebookProfile = profile;
                           result.facebookToken = accessToken;
                           result.save(function(err, doc) {
                               done(err, doc);
                           });
                       } else {
                           done(err, result);
                       }
                   }
               );
           }
       )
   );
   
   router.get(options.authPath+'/facebook',
       passport.authenticate('facebook', { session: false, scope: [] })
   );

   router.get(options.authPath+'/facebook/callback',
       passport.authenticate('facebook', { session: false, failureRedirect: "/" }),
       function(req, res) {
           var token = jwt.sign(req.user, options.secret, { expiresIn: options.expiresInSeconds });
           console.log('user: '+ JSON.stringify(req.user));
           console.log('token: %s ', token);
           res.set("Authorization", "Bearer "+token);
           res.redirect(options.authPath+'/status');
       }
   );
   router.get(options.authPath+'/status',
      function(req, res) {
        var token = req.get("Authorization")
        // verify a token symmetric
        jwt.verify(token, options.secret, function(err, decoded) {
          console.log('user: '+ JSON.stringify(decoded));
          res.send("LOGGED IN as: " + JSON.stringify(decoded));
        });
      }
  );


  console.log('Auth at: %s', options.authPath);
  app.use(router);
};
