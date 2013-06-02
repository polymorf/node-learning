var express = require('express');
var path = require("path");
var uuid = require('node-uuid');

var ssl = require("./lib/ssl");
/*var db = require("./lib/database");*/

var app = express();


app.get('/api-1.0/keygen', function(req, res){
	var err = "";
	var size = req.query.size;
	var name = req.query.name;
	if ( ! name || ! size ) {
		res.send(JSON.stringify({error:1, error_msg:"missing param"}));
		res.end();
	}
	/* security */
	size = parseInt(size);
	name = path.basename(name);
	if ( isNaN(size) ) {
		res.send(JSON.stringify({error:1, error_msg:"Bad key size"}));
		res.end();
	}

	/* Generate an UUID for this key */
	var keyuuid = uuid.v4();

	/* Generating the Key */
	ssl.genPrivateKey(size,function(key) {
		if ( key.length == 0 ) {
			res.send(JSON.stringify({error:1, error_msg:"Key cannot be generated"}));
			res.end();
		}else{
			res.send(JSON.stringify({error:0, error_msg:"",name:name,uuid:keyuuid}));
			res.end();
		}
	});
});

app.listen(3000);
