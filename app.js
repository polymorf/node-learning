var express = require('express');
var path = require("path");

var ssl = require("./lib/ssl");
/*var db = require("./lib/database");*/

var app = express();


app.get('/api-1.0/keygen', function(req, res){
	var err = "";
	var size = req.query.size;
	var name = req.query.name;

	/* Generating the Key */
	ssl.genPrivateKey(name,size,function(data) {
		if ( data.error ) {
			res.send(JSON.stringify({error:1, error_msg:data.error}));
			res.end();
		}else{
			res.send(JSON.stringify({
				error:0, 
				error_msg:"",
				name:data.name,
				UUID:data.uuid,
			}));
			res.end();
		}
	});
});

app.listen(3000);
