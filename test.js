var xmlrpc = require('xmlrpc');
var client = xmlrpc.createClient({ host: 'localhost', port: 3000, path: '/api-1.0/RPC'});
client.methodCall('pki.genKey', [ { name:"test2'", keysize: 256 } ], function (error, value) {
	if ( error ) {
		console.log('-- pki.keygen error : '+error);
	}else{
		console.log('-- pki.keygen : resp ok : uuid = ' + value.uuid);
	}
});

client.methodCall('pki.getKeys', [ null ], function (error, keys) {
	if ( error ) {
		console.log('-- pki.getkeys error : '+error);
	}else{
		console.log('-- pki.getkeys : resp ok');
		keys.forEach(function(key) {
			console.log("name="+key.name+" uuid="+key.uuid+" size="+key.size);
		});
	}
});

client.methodCall('pki.genCSR', [ { keysize: 2048, country: "FR", state: "Haute Garonne", locality: "Toulouse", organization: "polymorf Corp", organizationUnit: "informatique", commonName: "david.polymorf.fr", emailAddress: "david@nfrance.com" } ], function (error, csr) {
	if ( error ) {
		console.log('-- pki.genCSR error : '+error);
	}else{
		console.log('-- pki.genCSR : resp ok');
		console.log("csr = \n"+csr.csr);
	}
});
