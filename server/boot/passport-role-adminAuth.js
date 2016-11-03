'use strict';

module.exports = function enableAuthentication(app) {
  var VALID_API_KEYS = ["1234"];

  var Role = app.models.Role;
  Role.registerResolver('adminAuth', function(role, context, cb) {
    cb(null, false);
  });
};
