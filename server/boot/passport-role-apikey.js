'use strict';

module.exports = function enableAuthentication(app) {
  var VALID_API_KEYS = ["1234"];

  var Role = app.models.Role;
  Role.registerResolver('apikey', function(role, context, cb) {
    var apikey = context.remotingContext.req.query.apikey;
    apikey = apikey ? apikey : context.remotingContext.req.query.access_token;
    console.log("apikey=", apikey);
    if (apikey) {
      if (VALID_API_KEYS.indexOf(apikey) != -1) {
        cb(null, true);
        return;
      }
    }
    cb(null, false);
  });
};
