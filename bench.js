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

var encrypt_public = function(cb) {
    nacl.box(data, nonce, kp_recv[0], kp_send[1], cb);
}

var encrypted_public = nacl.box_sync(data, nonce, kp_recv[0], kp_send[1])
var decrypt_public = function(cb) {
    nacl.box_open(encrypted_public, nonce, kp_send[0], kp_recv[1], cb);
}

var key = new Buffer(nacl.secretbox_KEYBYTES);
var encrypt_secret = function(cb) {
    nacl.secretbox(data, nonce, key, cb);
}

var encrypted = nacl.secretbox_sync(data, nonce, key);
var decrypt_secret = function(cb) {
    nacl.secretbox_open(encrypted, nonce, key, cb);
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
    run_bench_with(encrypt_public),
    run_bench_with(decrypt_public),
    run_bench_with(encrypt_secret),
    run_bench_with(decrypt_secret)]);
