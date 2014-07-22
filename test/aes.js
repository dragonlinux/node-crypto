/**
 * Created by coobong on 2014-07-21.
 */


var crypto  = require('../node_crypto');
var assert = require("assert");




exports.aes = {
    'AES ECB' : {
        'aes ecb 128bit': function () {

            var key = new Buffer("000102030405060708090A0B0C0D0E0F", 'hex');
            var plain = new Buffer("00112233445566778899AABBCCDDEEFF", 'hex');
            var cipher = new Buffer("69C4E0D86A7B0430D8CDB78070B4C55A", 'hex');

            var result = crypto.aes_ecb_encrypt(key, plain);
            assert(result.toString('hex') == cipher.toString('hex'));

            result = crypto.aes_ecb_decrypt(key, cipher);
            assert(result.toString('hex') == plain.toString('hex'));
        },
        'aes_ecb_encrypt': function () {

        }
    },
    'AES CBC' : {
        'aes_ecb_encrypt' : function() {

        },
        'aes_cbc_encrypt' : function() {

        }
    },

    'AES CRT' : function() {

    }


};