var ssl = require("../ssl");
var db = require("../databases/pki");

var api = {
	genKey: function(reqdata, callback) {
		ssl.genPrivateKey(reqdata.name,reqdata.keysize,function(key) {
			if ( key.error ) {
				return callback(key.error,null);
			}else{
				db.savePrivateKey(key.keyuuid,key.keyname,reqdata.keysize,key.key,key.keymodulus, function(err){
					if ( err ) {
						callback(err,null);
					}else{
						callback(null, {
							error:0,
							error_msg:"",
							name:key.keyname,
							uuid:key.keyuuid
						});
					}
				});
			}
		});
	},
	getKeys: function(name, callback) {
		db.getPrivateKeys(name,function(err,keys) {
			if ( err ) {
				callback(err,null);
			}else{
				callback(null, keys);
			}
		});
	},
	genCSR: function(reqdata, callback) {
		ssl.genCertificateRequest(reqdata.keysize, reqdata.country, reqdata.state, reqdata.locality, reqdata.organization,
			          reqdata.organizationUnit, reqdata.commonName, reqdata.emailAddress, function(csr) {
			if ( csr.error ) {
				return callback(csr.error,null);
			}else{
				db.savePrivateKey(csr.keyuuid,csr.keyname,reqdata.keysize,csr.key,csr.keymodulus, function(err){
					if ( err ) {
						callback(err,null);
					}else{
						callback(null, {
							error:0,
							error_msg:"",
							csr: csr.csr
						});
					}
				});
			}
		});
	},
}

exports.api = api;
