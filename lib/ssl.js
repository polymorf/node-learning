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
		}
		pem.getModulus(data.key, function(modulus_err, modulus_data) {
			if ( modulus_err ) {
				retdata.error=modulus_err;
				return callback(retdata);
			}
			var keyuuid = uuidgen.v4().toString();
			retdata.key = data.key;
			retdata.keymodulus = modulus_data.modulus;
			retdata.keyuuid = keyuuid;
			retdata.keyname = name;
			return callback(retdata);
		});
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
			}
			pem.getModulus(data.clientKey, function(modulus_err, modulus_data) {
				if ( modulus_err ) {
					retdata.error=modulus_err;
					return callback(retdata);
				}
				var keyuuid = uuidgen.v4().toString();
				retdata.key = data.clientKey;
				retdata.keymodulus = modulus_data.modulus;
				retdata.keyuuid = keyuuid;
				retdata.keyname = "key for "+commonName;
				retdata.csr=data.csr;
				return callback(retdata);
			});
		}
	);
}

function genCertificate(keyBitsize, country, state, locality, organization, organizationUnit, commonName, emailAddress, days, callback) {
	var retdata={};
	pem.createCertificate({
			selfSigned: true,
			keyBitsize: keyBitsize,
			country: country,
			state: state,
			locality: locality,
			organization: organization,
			organizationUnit: organizationUnit,
			commonName: commonName,
			days: days,
			emailAddress: emailAddress
		}, function( err, data) {
			if ( err ) {
				retdata.error="CSR cannot be generated";
				return callback(retdata);
			}
			pem.getModulus(data.clientKey, function(keymodulus_err, keymodulus_data) {
				if ( keymodulus_err ) {
					retdata.error=keymodulus_err;
					return callback(retdata);
				}
				pem.getModulus(data.certificate, function(certmodulus_err, certmodulus_data) {
					if ( certmodulus_err ) {
						retdata.error=certmodulus_err;
						return callback(retdata);
					}
					/* the key */
					pem.readCertificateInfo(data.certificate, function(readerr, certinfo) {
						if ( readerr ) {
							retdata.error=readerr;
							return callback(retdata);
						}
						var keyuuid = uuidgen.v4().toString();
						retdata.keyuuid = keyuuid;
						retdata.key = data.clientKey;
						retdata.keymodulus = keymodulus_data.modulus;
						retdata.keyname = "key for "+commonName;
						/* the certificate */
						var certuuid = uuidgen.v4().toString();
						retdata.certuuid = certuuid;
						retdata.certificate=data.certificate;
						retdata.certmodulus=certmodulus_data.modulus;
						retdata.certvalidity=certinfo.validity;
						return callback(retdata);
					});
				});
			});
		}
	);
}

exports.genPrivateKey = genPrivateKey;
exports.genCertificateRequest = genCertificateRequest;
exports.genCertificate = genCertificate;
