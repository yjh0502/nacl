var nacl = require('./build/Release/nacl'),
    async = require('async');

console.log(nacl);

var buffer_equal = function(b1, b2) {
    if(b1 == null || b2 == null) {
        return false;
    }

    if(b1.length != b2.length) {
        return false;
    }

    for(var i = 0; i < b1.length; i++) {
        if(b1[i] != b2[i]) {
            return false;
        }
    }
    return true;
}

var test_public_box = function(cb) {
    var n = new Buffer(nacl.box_NONCEBYTES);
    var kp_send = nacl.box_keypair();
    var kp_recv = nacl.box_keypair();

    var m = new Buffer("Hello, world!");

    nacl.box(m, n, kp_recv[0], kp_send[1], function(err, c) {
        if(err) { cb(err); return; }

        var c_sync = nacl.box_sync(m, n, kp_recv[0], kp_send[1]);
        if(!buffer_equal(c, c_sync)) {
            cb(new Error("Output differs between sync & async: " +
                c + ", " + c_sync));
            return;
        }

        nacl.box_open(c, n, kp_send[0], kp_recv[1], function(err, m2) {
            if(err) { cb(err); return; }

            if(!buffer_equal(m, m2)) {
                cb(new Error("Values not equal: " + m + ", " + m2));
                return;
            }

            var m2_sync = nacl.box_open_sync(c, n, kp_send[0], kp_recv[1]);
            if(!buffer_equal(m2, m2_sync)) {
                cb(new Error("Output differs between sync & async: " +
                    m2 + ", " + m2_sync));
                return;
            }

            cb(null);
        });
    });
};

var test_private_box = function(cb) {
    var n = new Buffer(nacl.secretbox_NONCEBYTES);
    var pk = new Buffer(nacl.secretbox_KEYBYTES);

    var m = new Buffer("Hello, world!");

    nacl.secretbox(m, n, pk, function(err, c) {
        if(err) { cb(err); return; }
        nacl.secretbox_open(c, n, pk, function(err, m2) {
            if(err) { cb(err); return; }

            if(!buffer_equal(m, m2)) {
                cb(new Error("Values not equal: " + m + ", " + m2));
                return;
            }
            cb(null);
        });
    });
};

async.series([test_public_box, test_private_box], function(err, returns) {
    if(err) {
        console.log("Test failed: " + err);
    } else {
        console.log("Test success");
    }
});
