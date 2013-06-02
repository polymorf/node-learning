var pem = require("pem");

function genPrivateKey(length, callback) {
	pem.createPrivateKey(length, function (err, data) {
		if ( err ) {
			callback();
		}else{
			callback(data.key);
		}
	});
}

exports.genPrivateKey = genPrivateKey;
