/*

	(The MIT License)

	Copyright (C) 2005-2013 Kai Davenport

	Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 */

/*
  Module dependencies.
*/

var _ = require('lodash');
var async = require('async');
var passport = require('passport')

/*

  Facebook auth strategy

  App is the express app upon which to mount the auth routes

  authfn is the function that will contact the auth supplier

  routerfn is the function that decides how to route the req after authentication
d
  options are the oauth settings for passport
  
*/
module.exports = function(name, version, Strategy, passportoptions){

  return function(app, options, api){

    var base_route = options.mountpath + '/' + name;

    var strategyOptions = {
      callbackURL:'http://' + options.hostname + base_route + '/callback',
      passReqToCallback: true
    }

    if(version==1){
      strategyOptions.consumerKey = options.provider.key;
      strategyOptions.consumerSecret = options.provider.secret;
    }
    else if(version==2){
      strategyOptions.clientID = options.provider.key;
      strategyOptions.clientSecret = options.provider.secret;
    }

    function oauthhandler(req, accessToken, refreshToken, rawprofile, done){

      var provider_config = options.provider;
      var provider_keys = {
        key:provider_config.key,
        secret:provider_config.secret
      }

      var profile = {
        id:rawprofile.id,
        name:rawprofile.displayName,
        emails:rawprofile.emails,
        tokens:{
          user:{
            access:accessToken,
            refresh:refreshToken  
          },
          provider:provider_keys
        }
      }

      if(api && api.extract){
        profile = _.extend({}, profile, api.extract(rawprofile));
      }

      var login_packet = {
        provider:name,
        profile:profile,
        user:req.user
      }

      app.emit('login:oauth', login_packet, function(error, user){
        console.log('-------------------------------------------');
        console.log('sending done');
        return done(null, user);
      });
    }

    var strategy_instance = new Strategy(strategyOptions, oauthhandler);

    passport.use(strategy_instance);

    var httproutes = options.httproutes || {};

    var auth_fn = passport.authenticate(name, _.extend({}, passportoptions));
    var return_fn = passport.authenticate(name,  _.extend({}, {      
      failureRedirect: httproutes.failure || '/'
    }))

    app.get(base_route, auth_fn);
    app.get(base_route + '/callback', return_fn, function(req, res) {
      res.redirect(httproutes.success || '/');
    })
  }
}