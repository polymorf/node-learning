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
			pem.getModulus(data.key, function(modulus_err, modulus_data) {
				if ( modulus_err ) {
					retdata.error=modulus_err;
					return callback(retdata);
				}else{
					var keyuuid = uuidgen.v4().toString();
					retdata.key = data.key;
					retdata.keymodulus = modulus_data.modulus;
					retdata.keyuuid = keyuuid;
					retdata.keyname = name;
					return callback(retdata);
				}
			});
		}
	});
}

function genCertificateRequest(keyBitsize, country, state, locality, organization, organizationUnit, commonName, emailAddress, callback) {
	var retdata={};
	pem.createCSR({
			keyBitsize: keyBitsize,
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
				pem.getModulus(data.clientKey, function(modulus_err, modulus_data) {
					if ( modulus_err ) {
						retdata.error=modulus_err;
						return callback(retdata);
					}else{
						var keyuuid = uuidgen.v4().toString();
						retdata.key = data.clientKey;
						retdata.keymodulus = modulus_data.modulus;
						retdata.keyuuid = keyuuid;
						retdata.keyname = "key for "+commonName;
						retdata.csr=data.csr;
						return callback(retdata);
					}
				});
			}
		}
	);
}

exports.genPrivateKey = genPrivateKey;
exports.genCertificateRequest = genCertificateRequest;
