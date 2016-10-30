'use strict';

module.exports = function(app) {
  var router = app.loopback.Router();

  var User = app.models.User;

  var passport = require('passport');
  var BearerStrategy = require('passport-http-bearer').Strategy
  var FacebookStrategy = require('passport-facebook').Strategy;
  //var googleStrategy = require('passport-google').Strategy;

  //facebook auth setup
  var options = {
    authPath: '/auth',
    facebook: {
      clientID: '882422281866614',
      clientSecret: '5fcf8f7efb718e447e22c7dee5458121',
      callbackURL: 'http://localhost:3000/auth/facebook/callback'
    }
  };
  passport.use(
       new FacebookStrategy(
           options.facebook,
           function(accessToken, refreshToken, profile, done) {
               User.findOrCreate(
                   { facebookId: profile.id },
                   function (err, result) {
                       if(result) {
                           result.access_token = accessToken;
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
   passport.use(
      new BearerStrategy(
          function(token, done) {
              User.findOne({ access_token: token },
                  function(err, user) {
                      if(err) {
                          return done(err)
                      }
                      if(!user) {
                          return done(null, false)
                      }

                      return done(null, user, { scope: 'all' })
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
           res.redirect("/status?access_token=" + req.user.access_token);
       }
   );
   router.get(options.authPath+'/status',
      passport.authenticate('bearer', { session: false }),
      function(req, res) {
          res.send("LOGGED IN as " + req.user.facebookId + " - <a href=\"/logout\">Log out</a>");
      }
  );


  console.log('Auth at: %s', options.authPath);
  app.use(router);
};
