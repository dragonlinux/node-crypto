/**
 * Created by coolbong on 2014-05-26.
 */

var crypto = require('crypto');



/*
 openssl encryption description
 - https://www.openssl.org/docs/apps/enc.html
 */


/**
 *
 * @return []
 */
function getSupportedHashes() {
    return crypto.getHashes();
}

/**
 *
 * @returns []
 */
function getSupportedCipher() {
    return crypto.getCiphers();
}


//----------------------------------------------------------------------------------------------------------------------
// hash
//----------------------------------------------------------------------------------------------------------------------

/**
 *
 * @param {String} hash
 * @param {buffer} buff
 * @returns {buffer}
 */
function hash( /* Buffer */ hash, /* Buffer */buff) {
    return crypto.createHash(hash).update(buff).digest();
}

//----------------------------------------------------------------------------------------------------------------------
// random
//----------------------------------------------------------------------------------------------------------------------

/**
 *
 * @param {number} length
 * @returns {buffer}
 */
function random(/*number*/length) {
    return crypto.randomBytes(length);
}

/**
 *
 * @param {number} length
 * @returns {buffer}
 */
function pseudoRandom(/*number*/ length) {
    return crypto.pseudoRandomBytes(length);
}
//----------------------------------------------------------------------------------------------------------------------
// des - ecb
//----------------------------------------------------------------------------------------------------------------------
/**
 *
 * @param {buffer} key
 * @param {buffer} input
 * @returns {buffer}
 */
function des_ecb_encrypt(key, input) {
    var cipherType = '';
    if( key.length == 8) {
        //one key des ecb
        cipherType = 'des-ecb';
    } else if( key.length == 16) {
        // Two key triple des ecb
        cipherType = 'des-ede';
    } else if (key.length == 24) {
        //Three key triple des ecb
        cipherType = 'des-ede3'
    } else {
        console.log('key length is invalid. must set to be 8, 16, 24');
        return null;
    }

    var cipher = crypto.createCipheriv(cipherType, key, '');
    cipher.setAutoPadding(false);
    return cipher.update(input);
}

/**
 *
 * @param {buffer} key
 * @param {buffer} input
 * @returns {buffer}
 */
function des_ecb_decrypt(key, input) {
    var cipherType = '';
    if (key.length == 8) {
        //one key des ecb
        cipherType = 'des-ecb';
    } else if (key.length == 16) {
        // Two key triple des ecb
        cipherType = 'des-ede';
    } else if (key.length == 24) {
        //Three key triple des ecb
        cipherType = 'des-ede3'
    } else {
        console.log('key length is invalid. must set to be 8, 16, 24');
        return null;
    }
    var decipher = crypto.createDecipheriv(cipherType, key, '');
    decipher.setAutoPadding(false);
    return decipher.update(input);
}

//----------------------------------------------------------------------------------------------------------------------
// des - cbc
//----------------------------------------------------------------------------------------------------------------------
/**
 *
 * @param {buffer} key
 * @param {buffer} input
 * @param {buffer} iv
 * @returns {buffer}
 */
function des_cbc_encrypt(key, input, iv) {
    //FXME try catch
    var cipherType = '';
    if( key.length == 8) {
        //one key des cbc
        cipherType = 'des-cbc';
    } else if( key.length == 16) {
        // Two key triple des cbc
        cipherType = 'des-ede-cbc';
    } else if (key.length == 24) {
        //Three key triple des cbc
        cipherType = 'des-ede3-cbc'
    } else {
        console.log('key length is invalid. must set to be 8, 16, 24');
        return null;
    }

    if(iv === undefined) {
        iv = new Buffer(8);
        iv.fill(0);
    }

    var cipher = crypto.createCipheriv(cipherType, key, iv);
    cipher.setAutoPadding(false);
    return cipher.update(input);
}

/**
 *
 * @param {buffer} key
 * @param {buffer} input
 * @param {buffer} iv
 * @returns {buffer}
 */
function des_cbc_decrypt(key, input, iv) {
    var cipherType = '';
    if( key.length == 8) {
        //one key triple des cbc
        cipherType = 'des-cbc';
    } else if( key.length == 16) {
        // Two key triple des cbc
        cipherType = 'des-ede-cbc';
    } else if (key.length == 24) {
        //Three key triple des cbc
        cipherType = 'des-ede3-cbc'
    } else {
        console.log('key length is invalid. must set to be 8, 16, 24');
        return null;
    }

    if(iv === undefined){
        iv = new Buffer(8);
        iv.fill(0);
    }

    var decipher = crypto.createDecipheriv(cipherType, key, iv);
    decipher.setAutoPadding(false);
    return decipher.update(input);
}

//----------------------------------------------------------------------------------------------------------------------
// aes-ecb
//----------------------------------------------------------------------------------------------------------------------
/**
 *
 * @param {buffer} key
 * @param {buffer} input
 * @returns {buffer}
 */
function aes_ecb_encrypt(key, input) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit ecb mode
        cipherType = 'aes-128-ecb';
    } else if( key.length == 24) {
        //192 bit ecb mode
        cipherType = 'aes-192-ecb';
    } else if (key.length == 32) {
        //256 bit ecb mode
        cipherType = 'aes-256-ecb';
    } else {
        console.log('key length is invalid. must set to be 16, 24, 32');
        return null;
    }

    var cipher = crypto.createCipheriv(cipherType, key, '');
    cipher.setAutoPadding(false);
    return cipher.update(input);
}

/**
 *
 * @param {buffer} key
 * @param {buffer} input
 * @returns {buffer}
 */
function aes_ecb_decrypt(key, input) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit ecb mode
        cipherType = 'aes-128-ecb';
    } else if( key.length == 24) {
        //192 bit ecb mode
        cipherType = 'aes-192-ecb';
    } else if (key.length == 32) {
        //256 bit ecb mode
        cipherType = 'aes-256-ecb';
    } else {
        console.log('key length is invalid. must set to be 16, 24, 32');
        return null;
    }
    var decipher = crypto.createDecipheriv(cipherType, key, '');
    decipher.setAutoPadding(false);
    return decipher.update(input);
}

//----------------------------------------------------------------------------------------------------------------------
// aes-cbc
//----------------------------------------------------------------------------------------------------------------------
/**
 *
 * @param {buffer} key
 * @param {buffer} input
 * @param {buffer} iv
 * @returns {buffer}
 */
function aes_cbc_encrypt(key, input, iv) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit cbc mode
        cipherType = 'aes-128-cbc';
    } else if( key.length == 24) {
        //192 bit cbc mode
        cipherType = 'aes-192-cbc';
    } else if (key.length == 32) {
        //256 bit cbc mode
        cipherType = 'aes-256-cbc';
    } else {
        console.log('key length is invalid. must set to be 16, 24, 32');
        return null;
    }

    if(iv === undefined){
        iv = new Buffer(16);
        iv.fill(0);
    }

    var cipher = crypto.createCipheriv(cipherType, key, iv);
    cipher.setAutoPadding(false);
    return cipher.update(input);
}

/**
 *
 * @param {buffer} key
 * @param {buffer} input
 * @param {buffer} iv
 * @returns {buffer}
 */
function aes_cbc_decrypt(key, input,iv) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit ecb mode
        cipherType = 'aes-128-cbc';
    } else if( key.length == 24) {
        //192 bit cbc mode
        cipherType = 'aes-192-cbc';
    } else if (key.length == 32) {
        //256 bit cbc mode
        cipherType = 'aes-256-cbc';
    } else {
        console.log('key length is invalid. must set to be 16, 24, 32');
        return null;
    }
    if(iv === undefined){
        iv = new Buffer(16);
        iv.fill(0);
    }
    var decipher = crypto.createDecipheriv(cipherType, key, iv);
    decipher.setAutoPadding(false);
    return decipher.update(input);
}

//----------------------------------------------------------------------------------------------------------------------
// aes-ctr
//----------------------------------------------------------------------------------------------------------------------
/**
 *
 * @param {buffer} key
 * @param {buffer} input
 * @param {buffer} iv
 * @returns {buffer}
 */
function aes_ctr_encrypt(key, input, iv) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit ctr mode
        cipherType = 'aes-128-ctr';
    } else if( key.length == 24) {
        //192 bit ctr mode
        cipherType = 'aes-192-ctr';
    } else if (key.length == 32) {
        //256 bit ctr mode
        cipherType = 'aes-256-ctr'
    } else {
        console.log('key length is invalid. must set to be 16, 24, 32');
        return null;
    }

    var cipher = crypto.createCipheriv(cipherType, key, iv);
    cipher.setAutoPadding(false);
    return cipher.update(input);
}
/**
 *
 * @param {buffer} key
 * @param {buffer} input
 * @param {buffer} iv
 * @returns {buffer}
 */
function aes_ctr_decrypt(key, input, iv) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit ctr mode
        cipherType = 'aes-128-ctr';
    } else if( key.length == 24) {
        //192 bit ctr mode
        cipherType = 'aes-192-ctr';
    } else if (key.length == 32) {
        //256 bit ctr mode
        cipherType = 'aes-256-ctr';
    } else {
        console.log('key length is invalid. must set to be 16, 24. 32');
        return null;
    }

    var decipher = crypto.createDecipheriv(cipherType, key, iv);
    decipher.setAutoPadding(false);
    return decipher.update(input);
}

//----------------------------------------------------------------------------------------------------------------------
// mac
//----------------------------------------------------------------------------------------------------------------------
/**
 *
 * @param {String} type 'sha1', 'sha256', 'md5'
 * @param key 'key'
 * @param data
 * @returns {buffer}
 */
function hmac(type, key, data) {
    return crypto.createHmac(type, key).update(data).digest();
}



/**
 * Full Triple Des MAC
 * FIPS PUB 113 Computer Data Authentication is a (now obsolete) U.S. government standard that specified the CBC-MAC algorithm using DES as the block cipher.
 * The CBC-MAC algorithm is equivalent to ISO/IEC 9797-1 MAC Algorithm 1.
 * http://en.wikipedia.org/wiki/CBC-MAC
 * http://www.freesoft.org/CIE/RFC/1510/83.htm
 *
 * @param key
 * @param data
 * @return {buffer}
 */
function des_mac(key, data) {
    data = des_padding(data);
    var iv = new Buffer(8);
    iv.fill(0);
    var result = des_cbc_encrypt(key, data, iv);
    return result.slice(result.length-8, result.length);
}

/**
 * Single DES Plus Final Triple DES with the C-MAC
 * This is also known as the Retail MAC. It is as defined in [ISO 9797-1] as MAC Algorithm 3 with output
 * transformation 3, without truncation, and with DES taking the place of the block cipher.
 */
function des_mac_emv(key, data, needpadding){
    if(needpadding !== undefined || needpadding == true) {
        data = des_padding(data);
    }

    var key1 = key.slice(0, 8); // for single des key
    var iv = new Buffer(8);
    iv.fill(0);

    var singledes = des_cbc_encrypt(key1, data, iv);
    var block = data.slice(data.length-8, data.length);
    var cipher = xor(singledes, block);

    return des_ecb_encrypt(key, cipher);
}


/**
 * \
 * @param key
 * @param data
 */
function aes_mac(key, data) {
    //http://en.wikipedia.org/wiki/CMAC
    var result = aes_cbc_encrypt(key, data);
    return result.slice(result.length-16, result.length);
}


///AES CMAC

function MSB(buf) {
    return (buf[0] & 0x80) ? 1 : 0;
}

function shift_left(buf, cnt) {

}

function generate_subkey(K) {

    //var const_zero = new Buffer(16);
    //const_zero.fill(0);

    var const_zero = new Buffer('00000000000000000000000000000000', 'hex');
    var const_Rb   = new Buffer('00000000000000000000000000000087', 'hex');

    //Step 1. L = aes-128(K, consta_zero)
    var L = aes_cbc_encrypt(K, const_zero);

    //Step 2. if MSB(L) == 0
    //        then K1 = L << 1
    //        else K1 = (L << 1) XOR const Rb
    var K1;
    if(MSB(L) == 0) {
        K1 = L << 1;
    }



    //Step 3. if MSB(K1) == 0
    //        then K2 = K1 << 1
    //        else K2 = (K1 << 1) XOR const Rb

    //Step 4. return k1, k2
}



function aes_cmac(key, data) {
    //RFC 4493 http://www.ietf.org/rfc/rfc4493.txt
    //NIST SP 800-38B http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
    //FIXME plz implement me
    var result = new Buffer(16);
    result.fill(0);
    return result;
}

/**
 *
 * @param {buffer} buff
 * @return {buffer}
 */
function des_padding(buff) {
    var target_len  = (8 - ((buff.length + 1) % 8)) + 1;
    var extra_buf = new Buffer(target_len);
    extra_buf.fill(0);
    var pad_buf = Buffer.concat([buff, extra_buf]);
    pad_buf[buff.length] = 0x80;
    //console.log('des_padding: ' + pad_buf.toString('hex'));
    return pad_buf;
}

/**
 *
 * @param {buffer} buff
 * @return {buffer}
 */
function aes_padding(buff) {
    var target_len  = (16 - ((buff.length + 1) % 16)) + 1;
    var extra_buf = new Buffer(target_len);
    extra_buf.fill(0);
    var data_with_padding = Buffer.concat([buff, extra_buf]);
    data_with_padding[buff.length] = 0x80;
    return data_with_padding;

}

/**
 *
 * @param {buffer} arr1
 * @param {buffer} arr2
 * @returns {buffer}
 */
function xor(arr1, arr2) {
    var ret = [];
    var len = (arr1.length > arr2.length) ? (arr2.length) : (arr1.length);
    for (var i = 0; i < len; i++) {
        ret.push(arr1[i] ^ arr2[i]);
    }

    return new Buffer(ret);
}


module.exports  = {
    getSupportedHashes: getSupportedHashes,
    getSupportedCipher: getSupportedCipher,
    //hash
    hash: hash,

    //random
    random: random,
    pseudoRandom: pseudoRandom,

    //des
    des_ecb_encrypt: des_ecb_encrypt,
    des_ecb_decrypt: des_ecb_decrypt,
    des_cbc_encrypt: des_cbc_encrypt,
    des_cbc_decrypt: des_cbc_decrypt,


    //aes
    aes_ecb_encrypt: aes_ecb_encrypt,
    aes_ecb_decrypt: aes_ecb_decrypt,
    aes_cbc_encrypt: aes_cbc_encrypt,
    aes_cbc_decrypt: aes_cbc_decrypt,
    aes_ctr_encrypt: aes_ctr_encrypt,
    aes_ctr_decrypt: aes_ctr_decrypt,

    //mac
    hmac: hmac,
    des_mac: des_mac,
    des_mac_emv: des_mac_emv,
    aes_mac: aes_mac,
    aes_cmac: aes_cmac,

    //padding
    des_padding: des_padding,
    aes_padding: aes_padding,


    //util
    xor: xor
};