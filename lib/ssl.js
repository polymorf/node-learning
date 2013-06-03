var pem = require("pem");
var uuidgen = require('node-uuid');
var path = require('path');

function genPrivateKey(name, length, callback) {
	if ( typeof name == "undefined" || typeof length == "undefined" ) {
		var retdata={};
		retdata.error="Missing Parram";
		callback(retdata);
		return;
	}
	size = parseInt(length);
	name = path.basename(name);
	if ( isNaN(size) ) {
		var retdata={};
		retdata.error="Bad key size";
		callback(retdata);
		return;
	}
	pem.createPrivateKey(length, function (err, data) {

		if ( err ) {
			var retdata={};
			retdata.error="Key cannot be generated";
			callback(retdata);
			return;
		}else{
			var retdata={};
			var keyuuid = uuidgen.v4().toString();
			console.log("keyuuid = "+keyuuid);
			retdata.key = data.key;
			retdata.uuid = keyuuid;
			retdata.name = name;
			callback(retdata);
			return;
		}
	});
}

exports.genPrivateKey = genPrivateKey;
