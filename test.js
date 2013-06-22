var nacl = require('./build/Release/nacl');

var n = new Buffer(nacl.box_NONCEBYTES);
var kp_send = nacl.box_keypair();
var kp_recv = nacl.box_keypair();

var m = new Buffer("Hello, world!");

var c = nacl.box(m, n, kp_recv[0], kp_send[1]);
var m2 = nacl.box_open(c, n, kp_send[0], kp_recv[1]);

console.log(m2.toString());
