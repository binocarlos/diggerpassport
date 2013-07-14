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
var passport = require('passport');
var digger = require('digger.io');
var fs = require('fs');
var redback = require('redback');
var EventEmitter = require('events').EventEmitter;

var providers = {};

_.each(fs.readdirSync(__dirname + '/providers'), function(filename){
  var provider_name = filename.replace(/\.js$/, '');

  providers[provider_name] = require('./providers/' + provider_name);
})

function mount(app, options){

  options = _.defaults(options, {
    mountpath:'/login',
    httproutes:{}
  })

  var mountpath = options.mountpath;

  /*
  
    loop each provider and create the auth handlers via the closures above
    (they accept the provider name and delegate to that module)
    
  */
  _.each(options.providers, function(providerconfig, name){

    if(!providers[name]){
      throw new Error(name + ' is not an auth provider');
    }
    
    /*
    
      run the provider function providing the app and the 2 routing functions above
      
    */
    providers[name].apply(null, [app, _.extend({}, {
      provider:providerconfig
    }, options)])

  })


  /*
  
    LOGOUT
    
  */

  app.get(options.mountpath + '/logout', function(req, res, next){
    
    if(req.session){
      req.session.destroy();
    }
    
    req.logout();

    process.nextTick(function(){
      res.redirect('/');
    })
    
  })
}

function setup_supplychain(app, options){
    
  var db = options.supplychain;

  function loaduser(id, provider, done){
    /*
    
      profile.local#kai < user (parent user of profile with id kai that is local)
      
    */
    db('profile.' + provider + '#' + id + ' < user:tree').ship(function(user){
      if(user.count()>0){
        done(null, user);
      }
      else{
        done();
      }
    })
  }

  function loaduserid(id, done){
    db('=' + id + ':tree').ship(function(user){
      if(user.count()>0){
        done(null, user);
      }
      else{
        done();
      }
    })
  }
  

  function ensureprofile(user, provider, profile, done){
    var profilecontainer = user.find('profile.' + provider);

    if(profilecontainer.count()>0){
      /*
      
        we are all up to date
        
      */
      done();
    }
    else{

      var profileid = provider==='local' ? profile.username : profile.id;
      /*
            
        create the new profile on the existing user
        
      */
      profilecontainer = digger.create('profile', profile);
      profilecontainer.id(profileid).addClass(provider);
      profilecontainer.attr('provider', provider);

      user
        .append(profilecontainer)
        .ship(function(){
          done();
        })
      
    }

    
  }

  function createuser(provider, profile, done){
    var usercontainer = digger.create('user', {
      name:profile.name || profile.fullname,
      image:profile.image
    })

    usercontainer.attr('id', usercontainer.diggerid());

    db
      .append(usercontainer)
      .ship(function(){
        ensureprofile(usercontainer, provider, profile, function(){
          done(null, usercontainer.get(0));
        })
      })
  }

  /*
  
    setup the register and save user routes
    
  */
  if(options.providers.local){
    app.on('user:local:register', function(data, done){
      createuser('local', data, function(error, userdata){
        done(error, userdata);
      });
    })

    app.on('user:local:save', function(userid, data, done){
      loaduserid(userid, function(error, user){
        if(!user){
          done('no user loaded');
          return;
        }
        var profile = user.find('profile.local');
        if(profile.isEmpty()){
          done('no profile loaded');
          return; 
        }
        profile
          .inject_data(data)
          .save()
          .ship(function(){

            user.attr('name', profile.attr('fullname')).save().ship(function(){
              /*
            
                save the user to the session as well as the DB
                
              */
              app.emit('user:serialize', user.get(0), function(){
                done(null, user.get(0));  
              })              
            })
            
          })

      })
      
    })
  }

  app.on('user:load', loaduserid);

  app.on('login:local', function(login_packet, done){
    loaduser(login_packet.username, 'local', function(error, user){
      if(!user){
        return done(null, false);
      }
      else if(user.count()<=0){
        return done(null, false);
      }
      else{
        var profile = user.find('profile.local');
        if(!profile || profile.count()<=0){
          return done(null, false);
        }
        else{
          if(profile.attr('password')!=login_packet.password){
            return done(null, false);
          }
          else{
            return done(null, user.get(0));
          }
        }
      }
    })
  })

  app.on('login:oauth', function(login_packet, done){

    var existinguser = login_packet.user;
    var provider = login_packet.provider;
    var profile = login_packet.profile;

    /*
    
      they are already logged in - this is another provider ontop
      
    */
    if(existinguser){
      loaduserid(existinguser.id, function(error, user){
      
        if(!user){
          done('The logged in user has not loaded');
          return;
        }

        ensureprofile(user, provider, profile, function(){
          done(null, user.get(0));
        })
      })
    }
    /*
    
      they are not logged in - this is either a brand new user or returning user
      
    */
    else{

      loaduser(profile.id, provider, function(error, user){
        if(user){
          ensureprofile(user, provider, profile, function(){
            done(null, user.get(0));
          })
        }
        else{
          createuser(provider, profile, function(){
            done(null, user.get(0));
          })
        }
      })
    }

  })
}

/*

  quarry.io - auth middleware

  mounts routes onto a website that enable OAUTH and normal authentications
  
*/


module.exports = function(app, options){

  if(!options.id){
    throw new Error('DiggerPassport requires an app id to distinquish between other apps');
  }

  /*
    
    only save the id of the user into the browser cookie
    
  */
  app.passport.serializeUser(function(user, done) {

    app.emit('user:serialize', user, done);
    
  })

  /*
  
    load the full user from redis based on the cookie id
    
  */
  app.passport.deserializeUser(function(id, done) {

    app.emit('user:deserialize', id, done);

  })

  mount(app, options);

  /*
  
    if they have given a digger database we will
    use it to record the user data
    
  */

  if(options.supplychain){
    setup_supplychain(app, options);
  }

  /*
  
    if they have given a redis config then automatically serialize there
    
  */
  if(options.redis){
    var redisconnection = redback.createClient();
    var redbackusercache = redisconnection.createCache(options.id + ':usercache');

    function serialize_user(user, done) {

      var id = user.id || user._id;
      redbackusercache.set(id, JSON.stringify(user), function(error){
        if(error){
          return done(error);
        }
        done(null, id);
      });
    }

    function deserialize_user(id, done) {
      redbackusercache.get(id, function(error, st){
        if(error){
          return done(error);
        }
        done(null, JSON.parse(st));
      })
    }

    app.on('user:serialize', serialize_user);
    app.on('user:deserialize', deserialize_user);
  }
  

}