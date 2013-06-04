var xmlrpc = require('xmlrpc');
var client = xmlrpc.createClient({ host: 'localhost', port: 3000, path: '/api-1.0/RPC'});
client.methodCall('pki.keygen', [ { name:"test2'", size: 256 } ], function (error, value) {
	if ( error ) {
		console.log('-- pki.keygen error : '+error);
	}else{
		console.log('-- pki.keygen : resp ok : uuid = ' + value.uuid);
	}
});

client.methodCall('pki.getkeys', [ null ], function (error, keys) {
	if ( error ) {
		console.log('-- pki.getkeys error : '+error);
	}else{
		console.log('-- pki.getkeys : resp ok');
		keys.forEach(function(key) {
			console.log("name="+key.name+" uuid="+key.uuid+" size="+key.size);
		});
	}
});
