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
var LocalStrategy = require('passport-local').Strategy;

/*

  Facebook auth strategy

  App is the express app upon which to mount the auth routes

  authfn is the function that will contact the auth supplier

  routerfn is the function that decides how to route the req after authentication

  options are the oauth settings for passport
  
*/
module.exports = function(app, options, api){

  var mountpath = options.mountpath + '/local';

  passport.use(new LocalStrategy(
    function(username, password, done) {

      var login_packet = {
        username:username,
        password:password
      }

      app.emit('login:local', login_packet, done);

    }
  ))

  app.post(mountpath,
    passport.authenticate('local', {
      successRedirect: options.httproutes.success,
      failureRedirect: options.httproutes.failure
    })
  )
}

/*

  control what gets exposed into the browsers
  
*/
module.exports.extract = function(profile){
  return {};
}