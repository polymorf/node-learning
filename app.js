var express = require('express');
var xrpc = require('xrpc');

var pki = require("./lib/api/pki");

var app = express();
app.configure(function () {
	app.use(xrpc.xmlRpc);
});

app.post('/api-1.0/RPC', xrpc.route({
	pki: pki.api
}));

app.listen(3000);
