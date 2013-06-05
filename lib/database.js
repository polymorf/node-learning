var sqlite3 = require("sqlite3").verbose();

var pki_db = new sqlite3.Database(':memory:');

pki_db.run("CREATE TABLE privatekeys (uuid TEXT PRIMARY KEY, name TEXT UNIQUE, size INTEGER NOT NULL, key BLOB NOT NULL);");
pki_db.run("CREATE TABLE certificates (uuid TEXT PRIMARY KEY, keyuuid TEXT NOT NULL, name TEXT UNIQUE, cert BLOB NOT NULL, FOREIGN KEY(keyuuid) REFERENCES privatekeys(uuid) );");
pki_db.run("CREATE TABLE intermediates (uuid TEXT PRIMARY KEY, name TEXT UNIQUE, cert BLOB NOT NULL );");
pki_db.run("CREATE TABLE cert_chains (cert_uuid TEXT, intermediate_uuid TEXT, FOREIGN KEY(cert_uuid) REFERENCES certificates(uuid), FOREIGN KEY(intermediate_uuid) REFERENCES intermediates(uuid));");

function savePrivateKey( uuid, name, key, callback) {
	var insert = pki_db.prepare("INSERT INTO privatekeys VALUES (?,?,?,?)");
	insert.run(uuid,name,size,key,function(err){
		callback(err);
	});
	insert.finalize();
}

function getPrivateKeys(name, callback) {
	var cond="";
	if ( name ) {
		cond="WHERE name='"+name+"'";
	}
	pki_db.all("SELECT uuid,name,size FROM privatekeys "+cond, function(err, rows) {
		callback(err, rows);
	});
}

function saveCertificate( uuid, name, keyuuid, cert, callback) {
	var insert = pki_db.prepare("INSERT INTO certificates VALUES (?,?,?,?)");
	insert.run(uuid,keyuuid,name,cert,function(err){
		callback(err);
	});
	insert.finalize();
}

function getCertificate( name, callback) {
	var cond="";
	if ( name ) {
		cond="WHERE name='"+name+"'";
	}
	pki_db.all("SELECT uuid, name, cert, keyuuid FROM certificates "+cond, function(err, rows) {
		callback(err, rows);
	});
}

function saveIntermediateCertificate( uuid, name, cert, cert_uuid, callback) {
	var insert = pki_db.prepare("INSERT INTO intermediates VALUES (?,?,?)");
	insert.run(uuid,name,cert,function(err){
		if ( err ) {
			callback(err);
		}else{
			var insert2 = pki_db.prepare("INSERT INTO cert_chains VALUES (?,?)");
			insert2.run(cert_uuid,uuid,function(err){
				callback(err);
			});
			insert2.finalize();
		}
	});
	insert.finalize();
}

function getIntermediateCertificate(name, callback) {
	var cond="";
	if ( name ) {
		cond="WHERE name='"+name+"'";
	}
	pki_db.all("SELECT uuid, name, cert FROM intermediates "+cond, function(err, rows) {
		callback(err, rows);
	});
}

exports.savePrivateKey = savePrivateKey;
exports.getPrivateKeys = getPrivateKeys;
exports.saveCertificate = saveCertificate;
exports.getCertificate = getCertificate;
exports.saveIntermediateCertificate = saveIntermediateCertificate;
exports.getIntermediateCertificate = getIntermediateCertificate;
