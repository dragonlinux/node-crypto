/**
 * Created by coobong on 2014-06-25.
 */
var crypto  = require('../node_crypto');
var assert = require('assert');

var key1 = new Buffer('7CA110454A1A6E57', 'hex');
var key2 = new Buffer('0131D9619DC1376E', 'hex');
var key3 = new Buffer('9DC1376E0131D961', 'hex');

//7CA110454A1A6E570131D9619DC1376E9DC1376E0131D961
var plain;
var cipher;
var result;
var iv;

// Create three single DES keys, a double DES key and a triple DES key
var deskey1 = key1;
var deskey2 = key2;
var deskey3 = key3;

var des2key = Buffer.concat([key1, key2]);
var des3key = Buffer.concat([key1, key2, key3]);

exports.des = {
    'single des ecb mode' : {
        'Single DES ECB Encrypt' : function() {
            // Single DES ECB encrypt
            plain = new Buffer('01A1D6D039776742', 'hex');
            cipher = new Buffer('690F5B0D9A26939B', 'hex');
            result = crypto.des_ecb_encrypt(deskey1, plain);
            //console.log('result: ' + result.toString('hex').toUpperCase());
            assert(result.toString('hex') ==  cipher.toString('hex'));
        },
        'Single DES ECB Descrypt' : function() {
            // Single DES ECB decrypt
            plain = new Buffer('01A1D6D039776742', 'hex');
            result = crypto.des_ecb_decrypt(deskey1, cipher);

            assert(result.toString('hex') == plain.toString('hex'));
        }
    },
    'two key triple des ecb mode' : function() {
        plain = new Buffer('01A1D6D039776742', 'hex');
        cipher = plain;
        cipher = crypto.des_ecb_encrypt(deskey1, cipher);
        cipher = crypto.des_ecb_decrypt(deskey2, cipher);
        cipher = crypto.des_ecb_encrypt(deskey1, cipher);

        result = crypto.des_ecb_encrypt(des2key, plain);
        assert(result.toString('hex') ==  cipher.toString('hex'));
    },
    'two key triple des ecb mode 2' : function() {

        var key = new Buffer('505152535455565758595A5B5C5D5E5F', 'hex');
        var key1 = new Buffer('5051525354555657', 'hex');
        var key2 = new Buffer('58595A5B5C5D5E5F', 'hex');
        plain = new Buffer('20141027', 'ascii');
        //console.log(plain.toString('hex'));
        cipher = plain;

        cipher = crypto.des_ecb_encrypt(key1, cipher);
        cipher = crypto.des_ecb_decrypt(key2, cipher);
        cipher = crypto.des_ecb_encrypt(key1, cipher);

        result = crypto.des_ecb_encrypt(key, plain);

        //console.log('result: ' + result.toString('hex'));
        //console.log('  cipher: ' + cipher.toString('hex'));


        assert(result.toString('hex') ==  cipher.toString('hex'));

    },
    'three key triple des ecb mode' : function() {
        plain = new Buffer('01A1D6D039776742', 'hex');
        cipher = plain;
        cipher = crypto.des_ecb_encrypt(deskey1, cipher);
        cipher = crypto.des_ecb_decrypt(deskey2, cipher);
        cipher = crypto.des_ecb_encrypt(deskey3, cipher);

        result = crypto.des_ecb_encrypt(des3key, plain);
        assert(result.toString('hex') ==  cipher.toString('hex'));
    },
    'single des cbc encrypt 1' : function() {
        // Single DES CBC encrypt
        plain = new Buffer('01A1D6D0397767423977674201A1D6D0', 'hex');
        iv = new Buffer('59D9839733B8455D', 'hex');

        cipher = new Buffer('3A5A2EEFE27ACE7B038F50F35BD7678E', 'hex');

        result = crypto.des_cbc_encrypt(deskey1, plain, iv);
        assert(result.toString('hex') == cipher.toString('hex'));
    },
    'single des cbc encrypt 2' : function() {
        // Single DES CBC encrypt
        plain = new Buffer('01A1D6D0397767423977674201A1D6D0', 'hex');
        iv = new Buffer('59D9839733B8455D', 'hex');
        var v;

        v = plain.slice(0, 8);
        v = crypto.xor(v, iv);
        v = crypto.des_ecb_encrypt(deskey1, v);
        cipher = v;

        v = plain.slice(8, 16);
        v = crypto.xor(cipher, v);
        v = crypto.des_ecb_encrypt(deskey1, v);

        cipher = Buffer.concat([cipher, v]);

        result = crypto.des_cbc_encrypt(deskey1, plain, iv);
        assert(result.toString('hex') == cipher.toString('hex'));
        //console.log(result.toString('hex').toUpperCase());

        result = crypto.des_cbc_decrypt(deskey1, cipher, iv);
        assert(result.toString('hex') == plain.toString('hex'));
    },
    'single des cbc descrypt': function() {
        plain = new Buffer('01A1D6D0397767423977674201A1D6D0', 'hex');
        iv = new Buffer('59D9839733B8455D', 'hex');

    },
    'des mac' : function() {
        //test 1
        var key = new Buffer('21F347F04A223FEFEAC7857E057EA42A', 'hex');
        var plain = new Buffer('8482000010CA5225B746F24411', 'hex');
        var desmac = new Buffer('D75C127C2959176C', 'hex');

        var result = crypto.des_mac(key, plain);
        assert(result.toString('hex') == desmac.toString('hex'));

        key = new Buffer('404142434445464748494A4B4C4D4E4F', 'hex');
        plain = new Buffer('00010203040506074041424344454647', 'hex');
        var iv   = new Buffer('0000000000000000', 'hex');

        //test 2
        var plain_padd = crypto.des_padding(plain);
        var cipher = crypto.des_cbc_encrypt(key, plain_padd, iv);
        cipher = cipher.slice(cipher.length-8, cipher.length);

        result = crypto.des_mac(key, plain);
        assert(result.toString('hex') == cipher.toString('hex'));

        // test 3
        key = new Buffer('404142434445464748494A4B4C4D4E4F', 'hex');
        var host_challenge = new Buffer('0001020304050607', 'hex');
        var card_challege = new Buffer('08090A0B0C0D0E0F', 'hex');

        cipher = new Buffer('D0AEF0167D590E74', 'hex');
        plain = Buffer.concat([host_challenge, card_challege]);

        result = crypto.des_mac(key, plain);
        assert(result.toString('hex') == cipher.toString('hex'));
    },
    ' Retail MAC' : function() {
        var plain = new Buffer('Hello World !!!!', 'ascii');
        var iv = new Buffer('0000000000000000', 'hex');

        var result = crypto.des_mac_emv(des2key, plain);


        var block1 = plain.slice(0, 8);
        var block2 = plain.slice(plain.length - 8, plain.length);


        var cipher = crypto.des_cbc_encrypt(deskey1, plain, iv);
        cipher = crypto.xor(cipher, block2);
        cipher = crypto.des_ecb_encrypt(des2key, cipher);
        //FIXME check this assert mac api changed padding is default
        //assert(result.toString('hex') == cipher.toString('hex'));

        cipher = crypto.des_ecb_encrypt(deskey1, block1);
        cipher = crypto.xor(cipher, block2);

        cipher = crypto.des_ecb_encrypt(deskey1, cipher);
        cipher = crypto.des_ecb_decrypt(deskey2, cipher);
        cipher = crypto.des_ecb_encrypt(deskey1, cipher);

        //FIXME check this assert mac api changed padding is default
        //assert(result.toString('hex') == cipher.toString('hex'));
    }
};