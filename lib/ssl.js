var pem = require("pem");
var uuidgen = require('node-uuid');
var path = require('path');

function genPrivateKey(name, length, callback) {
	var retdata={};
	if ( typeof name == "undefined" || typeof length == "undefined" ) {
		retdata.error="Missing Parram";
		callback(retdata);
		return;
	}
	size = parseInt(length);
	name = path.basename(name);
	if ( isNaN(size) ) {
		retdata.error="Bad key size";
		callback(retdata);
		return;
	}
	pem.createPrivateKey(length, function (err, data) {
		if ( err ) {
			retdata.error="Key cannot be generated";
			callback(retdata);
			return;
		}else{
			var keyuuid = uuidgen.v4().toString();
			retdata.key = data.key;
			retdata.uuid = keyuuid;
			retdata.name = name;
			callback(retdata);
			return;
		}
	});
}

exports.genPrivateKey = genPrivateKey;
