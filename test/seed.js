/**
 * Created by coolbong on 2014-12-29.
 */

var crypto  = require('../node_crypto');
var assert = require('assert');

var key;
var message;
var answer;
var result;
var iv;

exports.seed = {
    'seed': {
        'seed ecb encrypt': function () {
            message = new Buffer('000102030405060708090A0B0C0D0E0F', 'hex');
            answer  = new Buffer('5EBAC6E0054E166819AFF1CC6D346CDB', 'hex');
            key     = new Buffer('00000000000000000000000000000000', 'hex');
            //result = crypto.hash('sha1', message);
            result = crypto.seed_ecb_encrypt(key, message);
            assert(answer.toString('hex') == result.toString('hex'));
        },
        'seed ecb decrypt' : function() {
            message = new Buffer('5EBAC6E0054E166819AFF1CC6D346CDB', 'hex');
            answer  = new Buffer('000102030405060708090A0B0C0D0E0F', 'hex');
            key     = new Buffer('00000000000000000000000000000000', 'hex');
            result = crypto.seed_ecb_decrypt(key, message);
            //console.log(result.toString('hex').toUpperCase());
            assert(answer.toString('hex') == result.toString('hex'));
        },
        'seed cbc encrypt': function() {
            message = new Buffer('000102030405060708090A0B0C0D0E0F', 'hex');
            iv      = new Buffer('268D66A735A81A816FBAD9FA36162501', 'hex');
            key     = new Buffer('88E34F8F081779F1E9F394370AD40589', 'hex');

            answer = new Buffer('75DDA4B065FF86427D448C5403D35A07', 'hex');

            //message = crypto.ISO9797Method_1(message, 16);
            //message = crypto.ISO9797Method_2(message, 16);
            result = crypto.seed_cbc_encrypt(key, message, iv);
            console.log(result.toString('hex'));
            assert(answer.toString('hex') == result.toString('hex'));
        },
        'seed cbc decrypt' : function() {
            message = new Buffer('75DDA4B065FF86427D448C5403D35A07', 'hex');
            iv      = new Buffer('268D66A735A81A816FBAD9FA36162501', 'hex');
            key     = new Buffer('88E34F8F081779F1E9F394370AD40589', 'hex');

            answer = new Buffer('000102030405060708090A0B0C0D0E0F', 'hex');

            result = crypto.seed_cbc_decrypt(key, message, iv);
            console.log(result.toString('hex'));
            assert(answer.toString('hex') == result.toString('hex'));
        }

    }
};

