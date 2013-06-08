var express = require('express');
var xrpc = require('xrpc');
var path = require("path");

var ssl = require("./lib/ssl");
var db = require("./lib/databases/pki");


var app = express();
app.configure(function () {
	app.use(xrpc.xmlRpc);
});



app.post('/api-1.0/RPC', xrpc.route({
	pki: {
		keygen: function(reqdata, callback) {
			ssl.genPrivateKey(reqdata.name,reqdata.size,function(key) {
				if ( key.error ) {
					return callback(key.error,null);
				}else{
					ssl.getModulus(key.key,function(modulus_err, modulus_data) {
						if ( modulus_err ) {
							return callback(modulus_err,null);
						}else{
							db.savePrivateKey(key.uuid,key.name,key.key,modulus_data.modulus, function(err){
								if ( err ) {
									callback(err,null);
								}else{
									callback(null, {
										error:0,
										error_msg:"",
										name:key.name,
										uuid:key.uuid
									});
								}
							});
						}
					});
				}
			});
		},
		getkeys: function(name, callback) {
			db.getPrivateKeys(name,function(err,keys) {
				if ( err ) {
					callback(err,null);
				}else{
					callback(null, keys);
				}
			});
		}
	}
}));

app.listen(3000);
