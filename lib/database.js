var sqlite3 = require("sqlite3").verbose();

var pki_db = new sqlite3.Database(':memory:');

pki_db.run("CREATE TABLE privatekeys (uuid TEXT, name TEXT, size INTEGER, key BLOB);");

function savePrivateKey( uuid, name, key ) {
	var insert = pki_db.prepare("INSERT INTO privatekeys VALUES (?,?,?,?)");
	insert.run(uuid,name,size,key);
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


exports.savePrivateKey = savePrivateKey;
exports.getPrivateKeys = getPrivateKeys;
