var assert = require('assert'),
    nacl = require('../build/Release/nacl');

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
};

describe("nacl", function() {
    describe("#box", function() {
        it("correctness", function(done) {
            var n = new Buffer(nacl.box_NONCEBYTES);
            var kp_send = nacl.box_keypair();
            var kp_recv = nacl.box_keypair();

            var m = new Buffer("Hello, world!");

            nacl.box(m, n, kp_recv[0], kp_send[1], function(err, c) {
                assert.equal(err, null);

                var c_sync = nacl.box_sync(m, n, kp_recv[0], kp_send[1]);
                assert(buffer_equal(c, c_sync));

                nacl.box_open(c, n, kp_send[0], kp_recv[1], function(err, m2) {
                    assert.equal(err, null);

                    assert(buffer_equal(m, m2));
                    var m2_sync = nacl.box_open_sync(c, n, kp_send[0], kp_recv[1]);
                    assert(buffer_equal(m2, m2_sync));

                    done();
                });
            });
        });
    });

    describe("#sign", function() {
        it("key-pair length", function() {
            var kp = nacl.sign_keypair();
            assert.equal(kp[0].length, nacl.sign_PUBLICKEYBYTES);
            assert.equal(kp[1].length, nacl.sign_SECRETKEYBYTES);
        });

        it("correctness", function(done) {
            var kp = nacl.sign_keypair();
            var m = new Buffer("Hello, world!");

            nacl.sign(m, kp[1], function(err, c) {
                assert.equal(err, null);
                nacl.sign_open(c, kp[0], function(err, m2) {
                    assert.equal(err, null);
                    assert(buffer_equal(m, m2));

                    done();
                });
            });
        });
    });

    describe("#secretbox", function() {
        it("correctness", function(done) {
            var n = new Buffer(nacl.secretbox_NONCEBYTES);
            var pk = new Buffer(nacl.secretbox_KEYBYTES);

            var m = new Buffer("Hello, world!");

            nacl.secretbox(m, n, pk, function(err, c) {
                assert.equal(err, null);
                nacl.secretbox_open(c, n, pk, function(err, m2) {
                    assert.equal(err, null);
                    assert(buffer_equal(m, m2));

                    done();
                });
            });
        });
    });
});
