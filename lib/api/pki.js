var ssl = require("../ssl");
var db = require("../databases/pki");

var api = {
	/*
	 * Generate a private Key
	 *
	 * @param {String} [reqdata.name] Name for the new key
	 * @param {Number} [reqdata.keysize] Size of the key
	 *
	 * @param {Function} callback Callback function with an error object and {name, uuid}
	 */
	genKey: function(reqdata, callback) {
		ssl.genPrivateKey(reqdata.name,reqdata.keysize,function(key) {
			if ( key.error ) {
				return callback(key.error,null);
			}
			db.savePrivateKey(key.keyuuid,key.keyname,reqdata.keysize,key.key,key.keymodulus, function(err){
				if ( err ) {
					callback(err,null);
				}
				callback(null, {
					name:key.keyname,
					uuid:key.keyuuid
				});
			});
		});
	},
	/*
	 * Get private Keys saved in database
	 *
	 * @param {String} [reqdata.name] Optional Name for the searched key
	 *
	 * @param {Function} callback Callback function with an error object and an array of keys {uuid,name,size}
	 */
	getKeys: function(name, callback) {
		db.getPrivateKeys(name,function(err,keys) {
			if ( err ) {
				return callback(err,null);
			}
			return callback(null, keys);
		});
	},
	/*
	 * Generate a certificate request
	 *
	 * @param {Number} [reqdata.keysize] Size of the private key
	 * @param {String} [reqdata.country] CSR country field
	 * @param {String} [reqdata.state] CSR state field
	 * @param {String} [reqdata.locality] CSR locality field
	 * @param {String} [reqdata.organization] CSR organization field
	 * @param {String} [reqdata.organizationUnit] CSR organizational unit field
	 * @param {String} [reqdata.commonName] CSR common name field
	 * @param {String} [reqdata.emailAddress] CSR email address field
	 *
	 * @param {Function} callback Callback function with an error object and {csr}
	 */
	genCSR: function(reqdata, callback) {
		ssl.genCertificateRequest(reqdata.keysize, reqdata.country, reqdata.state, reqdata.locality, reqdata.organization,
			          reqdata.organizationUnit, reqdata.commonName, reqdata.emailAddress, function(csr) {
			if ( csr.error ) {
				return callback(csr.error,null);
			}
			db.savePrivateKey(csr.keyuuid,csr.keyname,reqdata.keysize,csr.key,csr.keymodulus, function(err){
				if ( err ) {
					return callback(err,null);
				}
				return callback(null, {
					csr: csr.csr
				});
			});
		});
	},
	/*
	 * Generate a selfsigned certificate
	 *
	 * @param {Number} [reqdata.keysize] Size of the private key
	 * @param {String} [reqdata.country] CSR country field
	 * @param {String} [reqdata.state] CSR state field
	 * @param {String} [reqdata.locality] CSR locality field
	 * @param {String} [reqdata.organization] CSR organization field
	 * @param {String} [reqdata.organizationUnit] CSR organizational unit field
	 * @param {String} [reqdata.commonName] CSR common name field
	 * @param {String} [reqdata.emailAddress] CSR email address field
	 * @param {Number} [reqdata.days] Number of day for validity
	 *
	 * @param {Function} callback Callback function with an error object and {csr}
	 */
	genSelfSignedCertificate: function(reqdata, callback) {
		ssl.genCertificate(reqdata.keysize, reqdata.country, reqdata.state, reqdata.locality, reqdata.organization,
			          reqdata.organizationUnit, reqdata.commonName, reqdata.emailAddress, reqdata.days, function(crt) {
			if ( crt.error ) {
				return callback(crt.error,null);
			}
			db.savePrivateKey(crt.keyuuid,crt.keyname,reqdata.keysize,crt.key,crt.keymodulus, function(err){
				if ( err ) {
					return callback(err,null);
				}
				return callback(null, {
					certificate: crt.certificate,
					validity: crt.certvalidity
				});
			});
		});
	},
	/*
	 * Add a certificate to the store
	 *
	 * @param {String} [reqdata.certificate] New pem certificate
	 *
	 * @param {Function} callback Callback function with an error object
	 */
	addCertificate: function(reqdata, callback) {
		return callback("not implemeted");
	},
	/*
	 * Renew a certificate in the store
	 *
	 * @param {String} [reqdata.uuid] Old certificate UUID
	 * @param {String} [reqdata.certificate] New pem certificate
	 *
	 * @param {Function} callback Callback function with an error object
	 */
	renewCertificate: function(reqdata, callback) {
		return callback("not implemeted");
	},
	/*
	 * Remove a certificate from the store
	 *
	 * @param {String} [reqdata.uuid] UUID to delete
	 *
	 * @param {Function} callback Callback function with an error object
	 */
	removeCertificate: function(reqdata, callback) {
		return callback("not implemeted");
	},
	/*
	 * Add a intermediate certificate to the store
	 *
	 * @param {String} [reqdata.intermediate] New pem intermediate certificate
	 * @param {String} [reqdata.uuid] Certificate UUID for chaining
	 *
	 * @param {Function} callback Callback function with an error object
	 */
	addIntermediateCertificate: function(reqdata, callback) {
		return callback("not implemeted");
	},
	/*
	 * Remove a intermediate certificate from the store
	 *
	 * @param {String} [reqdata.uuid] Intermediate certificate UUID to remove
	 *
	 * @param {Function} callback Callback function with an error object
	 */
	removeIntermediateCertificate: function(reqdata, callback) {
		return callback("not implemeted");
	},
}

exports.api = api;
