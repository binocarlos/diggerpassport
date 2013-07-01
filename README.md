DiggerPassport
==============

A library to mount multiple passport OAuth handlers onto a diggerexpress app.


```js
var DiggerPassport = require('diggerpassport');
var DiggerExpress = require('diggerexpress');

var app = DiggerExpress();


DiggerPassport(app, {
	// used for namespacing
	id:'appid',

	// where to mount the routes onto the express app
	mountpath:'/auth',

	// if defined we will save the user session in redis
	redis:{
		port:6379,
		hostname:'127.0.0.1'
	},

	// if defined we will look after saving/loading users to the given digger supplychain
	supplychain:userdb,

	// the routes for HTTP redirection
	httproutes:{
		success:'/',
		failure:'/?loginmessage=incorrect details'
	},

	// what providers we want to use
	providers:{
		local:{
		},
		facebook:{
			key:'...',
			secret:'...'
		},
		twitter:{
			key:'...',
			secret:'...'
		}
	}
})

// setup the rest of the app here

```

##License

MIT