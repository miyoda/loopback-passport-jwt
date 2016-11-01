'use strict';

module.exports = function(app) {
  var jwt = require('jsonwebtoken');
  let yyyymmdd = require('yyyy-mm-dd');
  let extend = require('extend');

  var passport = require('passport');
  var FacebookStrategy = require('passport-facebook').Strategy;
  //var GoogleStrategy = require('passport-google').Strategy;
  //var InstagramStrategy = require('passport-instagram').Strategy;
  //var LocalStrategy = require('passport-local').Strategy;
  var JwtStrategy = require('passport-jwt').Strategy;
  var ExtractJwt = require('passport-jwt').ExtractJwt;

  var router = app.loopback.Router();
  var Authuser = app.models.Authuser;
  var Login = app.models.Login;

  //facebook auth setup
  var options = {
    authPath: '/auth'
    ,authOpts: {
      passReqToCallback : true,
      session: false,
      scope: []
    }
    ,common: {
      passReqToCallback : true,
      session: false
    }
    ,jwt: {
      jwtFromRequest: ExtractJwt.fromAuthHeader(),
      secretOrKey: 'ssssssssssssh',
      expiresInSeconds: (30)
    }
    ,facebook: {
      clientID: '882422281866614',
      clientSecret: '5fcf8f7efb718e447e22c7dee5458121',
      profileFields: ['id', 'displayName', 'photos', 'email'],
      scope: []
    }
    /*,google: {
      clientID: '------',
      clientSecret: '------'
    }
    ,instagram: {
      clientID: '------',
      clientSecret: '------'
    }
    ,local: {
      usernameField: 'usename'
    }*/
  };

  var callback = function(req, accessToken, refreshToken, profile, done) {
    console.log('profile: '+ JSON.stringify(profile));
    var filter = { "where": {"or": [] }};
    var profileEmail = profile.email ? profile.email : profile._json.email;
    if (profile.id) {
      var or = {};
      or[req.params.method+"Id"] = profile.id;
      filter.where.or.push(or);
    }
    if (profileEmail) {
      filter.where.or.push({"email": profileEmail});
    }
    if (req.user) {
      filter.where.or.push({id: req.user.id});
    }
    console.log("callback filter: "+JSON.stringify(filter));

    Authuser.findOne(
        filter,
        function (err, authuserPm) {
            if(authuserPm) {
              fillInfo(authuserPm.__data);
              authuserPm.save(callbackFinish);
            } else {
              Authuser.create(fillInfo({}), callbackFinish);
            }
        }
    );

    function callbackFinish(err, authuser) {
      authuser = authuser.__data ? authuser.__data : authuser;
      done(err, authuser);
      Login.create({authuserId: authuser.id, date: yyyymmdd()});
    }

    function fillInfo(authuser) {
      authuser[req.params.method+"Id"] = profile.id;
      authuser[req.params.method+"Token"] = accessToken;
      authuser.name = authuser.name ? authuser.name : ((profile.name.givenName ? profile.name.givenName : '') + (profile.name.givenName && profile.name.familyName ? ' ' : '') + (profile.name.familyName ? profile.name.familyName : ''));
      authuser.name = authuser.name ? authuser.name : profile.displayName;
      authuser.lastName = authuser.lastName ? authuser.lastName : profile.name.familyName;
      authuser.birthday = authuser.birthday ? authuser.birthday : profile.birthday;
      authuser.gender = authuser.gender ? authuser.gender : profile.gender;
      authuser.email = authuser.email ? authuser.email : profileEmail;
      if (typeof authuser.photos == 'undefined') {
        authuser.photos = [];
      }
      if (profile.photos) {
        for (var photoJson of profile.photos) {
          if (authuser.photos.indexOf(photoJson.value) == -1) {
            authuser.photos.push(photoJson.value);
          }
        }
      }
      return authuser;
    }
  }

  if (options.facebook) passport.use(new FacebookStrategy(extend({callbackURL: options.authPath + '/login/facebook/callback'}, options.common, options.facebook), callback));
  if (options.google) passport.use(new GoogleStrategy(extend({callbackURL: options.authPath + '/login/google/callback'}, options.common, options.google), callback));
  if (options.instagram) passport.use(new InstagramStrategy(extend({callbackURL: options.authPath + '/login/instagram/callback'}, options.common, options.instagram), callback));
  if (options.local) passport.use(new LocalStrategy(extend({callbackURL: options.authPath + '/login/local/callback'}, options.common, options.local), function(req, email, password, done) {
      Authuser.findOne({ email: email }, function (err, authuser) {
        if (err) { return done(err); }
        if (!authuser) { return done(null, false); }
        if (!authuser.verifyLocalPassword(password)) {
          return done(null, false);
        }
        return done(null, authuser);
      });
  }));
  if (options.jwt) passport.use(new JwtStrategy(extend({}, options.common, options.jwt), function(jwt_payload, done) {
      Authuser.findOne({id: jwt_payload.sub}, function(err, authuser) {
          if (err) {
              return done(err, false);
          }
          if (authuser) {
              done(null, authuser);
          } else {
              done(null, false);
          }
      });
  }));

  router.get('/login/:method', function(req, res, next) {
      var method = req.params.method;
      console.log('/'+method);
      var reqScope = req.query.scope ? req.query.scope.split('|') : [];
      var authOpts = extend({}, options.authOpts);
      authOpts.scope = [].concat(authOpts.scope, options[method].scope, reqScope);
      if (req.query.callback) {
        authOpts.callbackURL = options.authPath + '/login/' + method + '/callback';
        authOpts.state = req.query.callback;
        console.log('authOpts.callbackURL='+authOpts.callbackURL);
      }
      if (req.user) {
        passport.authenticate(method, authOpts)( req, res, next );
      } else {
        passport.authorize(method, authOpts)( req, res, next );
      }
  });
  router.get('/login/:method/callback',  function(req, res, next) {
      var method = req.params.method;
      console.log('/'+method+'/callback query='+ JSON.stringify(req.query));
      passport.authenticate(method, options.authOpts, function(err, authuser) {//function(req, res, next) {
        var callbackRedirect = req.query.callback;
        callbackRedirect = callbackRedirect ? callbackRedirect : req.query.state;
        callbackRedirect = callbackRedirect ? callbackRedirect : '../../callbackdefault';
        var indexOfQ = callbackRedirect.indexOf('?');
        var query = '';
        if (err) {
          query = 'err=' + err;
        } else {
          //var authuser = req.user;
          var token = jwt.sign(authuser, options.jwt.secretOrKey, { expiresIn: options.jwt.expiresInSeconds });
          console.log('user: '+ JSON.stringify(req.user));
          console.log('token: %s ', token);

          query = 'jwt=' + encodeURIComponent(token);
        }
        res.redirect(callbackRedirect + (indexOfQ == -1 ? '?' : '&') + query);
      })(req, res, next);
   });

   router.get('/callbackdefault', function(req, res, next){
     var token = req.query.jwt;
     var err = req.query.err;
     console.log('/callbackdefault jwt=' + token +' && err=' + err);
     if (err) {
       res.send("Err: " + err);
     } else {
       jwt.verify(token, options.jwt.secretOrKey, function(err, decoded) {
          if (err) {
            res.send("Error: "+err);
          } else {
            res.send("JWT decoded: " + JSON.stringify(decoded));
          }
       });
     }
   });

   router.get('/callbacktest', function(req, res, next){
     var token = req.query.jwt;
     var err = req.query.err;
     console.log('/callbacktest jwt=' + token +' && err=' + err);
     res.send('/callbacktest jwt=' + token +' && err=' + err);
   });

   router.get('/status',
      passport.authenticate('jwt', options.authOpts, function(req, res, next) {
          res.send("LOGGED IN as: " + JSON.stringify(req.user));
       })
   );


  console.log('Auth rest at: %s', options.authPath);
  app.use(options.authPath, router);
};
