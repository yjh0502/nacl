var async = require("async"),
    nacl = require("./build/Release/nacl");

var count = 2000;

var bench = function(func) {
    var start = new Date().getTime();
    var done = function() {
        var end = new Date().getTime();
        var diff = ((end - start) / 1000);
        console.log("Time: " + diff + " sec");
        console.log((0|(count / diff)) + "op/s");
    }
    func(done);
}

var data = new Buffer(100);
var nonce = new Buffer(nacl.box_NONCEBYTES);
var kp_send = nacl.box_keypair(),
    kp_recv = nacl.box_keypair();

var box = function(cb) {
    nacl.box(data, nonce, kp_recv[0], kp_send[1], cb);
}

var encrypted_public = nacl.box_sync(data, nonce, kp_recv[0], kp_send[1])
var box_open = function(cb) {
    nacl.box_open(encrypted_public, nonce, kp_send[0], kp_recv[1], cb);
}


var kp_sign = nacl.sign_keypair();
var sign = function(cb) {
    nacl.sign(data, kp_sign[1], cb);
}

var sign_boxed = nacl.sign_sync(data, kp_sign[1]);
var sign_open = function(cb) {
    nacl.sign_open(sign_boxed, kp_sign[0], cb);
}


var key_secret = new Buffer(nacl.secretbox_KEYBYTES);
var secretbox = function(cb) {
    nacl.secretbox(data, nonce, key_secret, cb);
}

var encrypted = nacl.secretbox_sync(data, nonce, key_secret);
var secretbox_open = function(cb) {
    nacl.secretbox_open(encrypted, nonce, key_secret, cb);
}

var run_bench_with = function(func) {
    var tasks = [];
    for(var i = 0; i < count; i++) {
        tasks.push(func);
    }

    return function(cb) {
        bench(function(done) {
            async.parallelLimit(tasks, 200, function(err, data) {
                if(err) {
                    console.log(err);
                }
                done();
                cb();
            });
        });
    };
};

async.series([
    run_bench_with(box),
    run_bench_with(box_open),
    run_bench_with(sign),
    run_bench_with(sign_open),
    run_bench_with(secretbox),
    run_bench_with(secretbox_open)]);
