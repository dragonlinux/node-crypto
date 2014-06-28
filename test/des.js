/**
 * Created by coobong on 2014-06-25.
 */
var crypto  = require('../node_crypto');
var assert = require("assert");

var key1 = new Buffer("7CA110454A1A6E57", 'hex');
var key2 = new Buffer("0131D9619DC1376E", 'hex');
var key3 = new Buffer("9DC1376E0131D961", 'hex');

//7CA110454A1A6E570131D9619DC1376E9DC1376E0131D961
var plain;
var cipher;
var result;

// Create three single DES keys, a double DES key and a triple DES key
var deskey1 = key1;
var deskey2 = key2;
var deskey3 = key3;

var des2key = Buffer.concat([key1, key2]);
var des3key = Buffer.concat([key1, key2, key3]);

exports.des = {
    'single des' : {
        'Single DES ECB Encrypt' : function() {
            // Single DES ECB encrypt
            plain = new Buffer("01A1D6D039776742", 'hex');
            cipher = new Buffer("690F5B0D9A26939B", 'hex');
            result = crypto.des_ecb_encrypt(deskey1, plain);
            console.log('result: ' + result.toString('hex').toUpperCase());
            assert(result.toString('hex') ==  cipher.toString('hex'));
        },
        'Single DES ECB Descrypt' : function() {
            // Single DES ECB decrypt
            plain = new Buffer("01A1D6D039776742", 'hex');
            result = crypto.des_ecb_decrypt(deskey1, cipher);

            assert(result.toString('hex') == plain.toString('hex'));
        }
    }
};