var async = require("async"),
    nacl = require("./build/Release/nacl");

var hex = function(hex) {
    return new Buffer(hex, 'hex');
}

var kp = nacl.box_keypair();

var bench = function(func) {
    var start = new Date().getTime();
    var done = function() {
        var end = new Date().getTime();
        console.log("Time: " + ((end - start) / 1000) + " sec");
    }
    func(done);
}

var data = new Buffer(100);
var nunce = new Buffer(nacl.box_NONCEBYTES);

var encrypt = function(cb) {
    nacl.box(data, nunce, kp[0], kp[1], cb);
}

tasks = [];
for(var i = 0; i < 10000; i++) {
    tasks.push(encrypt);
}

bench(function(done) {
    async.parallelLimit(tasks, 200, function(err, data) {
        if(err) {
            console.log(err);
        }
        done();
    });
});
