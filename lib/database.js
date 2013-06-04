var sqlite3 = require("sqlite3");

var pki_db = new sqlite3.Database(':memory:');

pki_db.run("CREATE TABLE privatekeys (uuid TEXT PRIMARY KEY, name TEXT UNIQUE, size INTEGER NOT NULL, key BLOB NOT NULL);");

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


exports.savePrivateKey = savePrivateKey;
exports.getPrivateKeys = getPrivateKeys;
