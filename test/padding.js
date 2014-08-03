/**
 * Created by coolbong on 2014. 8. 3..
 */

var crypto  = require('../node_crypto');
var assert = require("assert");


exports.padding = {
    'ISO9797Method_1' : function() {
        var buffer = new Buffer('Now is the time for all ', 'ascii');
        var result = crypto.ISO9797Method_1(buffer, 8);
        assert.equal(result.toString('hex').toUpperCase(), '4E6F77206973207468652074696D6520666F7220616C6C20');
    },
    'ISO9797Method_2' : function() {
        var buffer = new Buffer('Now is the time for all ', 'ascii');
        var result = crypto.ISO9797Method_1(buffer, 8);
        assert.equal(result.toString('hex').toUpperCase(), '4E6F77206973207468652074696D6520666F7220616C6C20');
    }
};
