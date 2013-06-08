var pem = require("./pem");
var uuidgen = require('node-uuid');
var path = require('path');

function genPrivateKey(name, length, callback) {
	var retdata={};
	if ( typeof name == "undefined" || typeof length == "undefined" ) {
		retdata.error="Missing Parram";
		return callback(retdata);
	}
	size = parseInt(length);
	name = path.basename(name);
	if ( isNaN(size) ) {
		retdata.error="Bad key size";
		return callback(retdata);
	}
	pem.createPrivateKey(length, function (err, data) {
		if ( err ) {
			retdata.error="Key cannot be generated";
			return callback(retdata);
		}else{
			var keyuuid = uuidgen.v4().toString();
			retdata.key = data.key;
			retdata.uuid = keyuuid;
			retdata.name = name;
			return callback(retdata);
		}
	});
}

function genCertificateRequest(key, keylength, country, state, locality, organization, organizationUnit, commonName, emailAddress, callback) {
	var retdata={};
	pem.createCSR({
			clientKey: key,
			keyBitsize: keylength,
			country: country,
			state: state,
			locality: locality,
			organization: organization,
			organizationUnit: organizationUnit,
			commonName: commonName,
			emailAddress: emailAddress
		}, function( err, data) {
			if ( err ) {
				retdata.error="CSR cannot be generated";
				return callback(retdata);
			}else{
				retdata.csr=data.csr;
				console.log("key = "+data.clientKey);
				pem.getModulus(data.clientKey,function(error,data) {
					console.log("key modulus = "+data.modulus);
				});
				pem.getModulus(data.csr,function(error,data) {
					console.log("csr modulus = "+data.modulus);
				});
				return callback(retdata);
			}
		}
	);
}

exports.genPrivateKey = genPrivateKey;
exports.genCertificateRequest = genCertificateRequest;
