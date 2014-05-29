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
 * @param {Buffer} buff
 * @returns {Buffer}
 */
function hash( /* Buffer */ hash, /* Buffer */buff) {
    return crypto.createHash(hash).update(buff).digest();
}

//----------------------------------------------------------------------------------------------------------------------
// random
//----------------------------------------------------------------------------------------------------------------------

/**
 *
 * @param length
 * @returns {Buffer}
 */
function random(/*number*/length) {
    return crypto.randomBytes(length);
}
//----------------------------------------------------------------------------------------------------------------------
// des - ecb
//----------------------------------------------------------------------------------------------------------------------
/**
 *
 * @param {Buffer} key
 * @param {Buffer} input
 * @returns {Buffer}
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
    return cipher.update(input, '');
}

/**
 *
 * @param {Buffer} key
 * @param {Buffer} input
 * @returns {Buffer}
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
    return decipher.update(input, '');
}

//----------------------------------------------------------------------------------------------------------------------
// des - cbc
//----------------------------------------------------------------------------------------------------------------------
/**
 *
 * @param {Buffer} key
 * @param {Buffer} input
 * @param {Buffer} iv
 * @returns {Buffer}
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

    var cipher = crypto.createCipheriv(cipherType, key, iv);
    //cipher.setAutoPadding(false);
    cipher.setAutoPadding(true);
    return cipher.update(input, '');
}

/**
 *
 * @param {Buffer} key
 * @param {Buffer} input
 * @param {Buffer} iv
 * @returns {Buffer}
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
    var decipher = crypto.createDecipheriv(cipherType, key, iv);
    decipher.setAutoPadding(false);
    return decipher.update(input, '');
}

//----------------------------------------------------------------------------------------------------------------------
// aes-ecb
//----------------------------------------------------------------------------------------------------------------------
/**
 *
 * @param {Buffer} key
 * @param {Buffer} input
 * @returns {Buffer}
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
    return cipher.update(input, '');
}

/**
 *
 * @param {Buffer} key
 * @param {Buffer} input
 * @returns {Buffer}
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
    return decipher.update(input, '');
}

//----------------------------------------------------------------------------------------------------------------------
// aes-cbc
//----------------------------------------------------------------------------------------------------------------------
/**
 *
 * @param {Buffer} key
 * @param {Buffer} input
 * @returns {Buffer}
 */
function aes_cbc_encrypt(key, input) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit cbc mode
        cipherType = 'des-cbc';
    } else if( key.length == 24) {
        //192 bit cbc mode
        cipherType = 'des-ede-cbc';
    } else if (key.length == 32) {
        //256 bit cbc mode
        cipherType = 'des-ede3-cbc'
    } else {
        console.log('key length is invalid. must set to be 16, 24, 32');
        return null;
    }

    var cipher = crypto.createCipheriv(cipherType, key, '');
    cipher.setAutoPadding(false);
    return cipher.update(input, '');
}

/**
 *
 * @param {Buffer} key
 * @param {Buffer} input
 * @returns {Buffer}
 */
function aes_cbc_decrypt(key, input) {
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
    var decipher = crypto.createDecipheriv(cipherType, key, '');
    decipher.setAutoPadding(false);
    return decipher.update(input, '');
}

//----------------------------------------------------------------------------------------------------------------------
// aes-ctr
//----------------------------------------------------------------------------------------------------------------------
/**
 *
 * @param {Buffer} key
 * @param {Buffer} input
 * @param {Buffer} iv
 * @returns {Buffer}
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
    return cipher.update(input, '');
}
/**
 *
 * @param {Buffer} key
 * @param {Buffer} input
 * @param {Buffer} iv
 * @returns {Buffer}
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
    return decipher.update(input, '');
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
 * FIPS PUB 113 Computer Data Authentication is a (now obsolete) U.S. government standard that specified the CBC-MAC algorithm using DES as the block cipher.
 * The CBC-MAC algorithm is equivalent to ISO/IEC 9797-1 MAC Algorithm 1.
 * http://en.wikipedia.org/wiki/CBC-MAC
 * http://www.freesoft.org/CIE/RFC/1510/83.htm
 *
 * @param key
 * @param data
 * @return {Buffer}
 */
function des_mac(key, data) {
    data = des_padding(data);
    var iv = new Buffer(8);
    iv.fill(0);
    var result = des_cbc_encrypt(key, data, iv);
    return result.slice(8, 16);
}

/**
 * Single DES Plus Final Triple DES with the C-MAC
 * This is also known as the Retail MAC. It is as defined in [ISO 9797-1] as MAC Algorithm 3 with output
 * transformation 3, without truncation, and with DES taking the place of the block cipher.
 */
function des_mac_emv(key, data){
    var key1 = key.slice(0, 8); // for single des key
    var iv = new Buffer(8);
    iv.fill(0);

    var singledes = des_cbc_encrypt(key1, data, iv);
    var block = data.slice(data.length-8, data.length);
    var cipher = xor(singledes, block);

    return des_ecb_encrypt(key, cipher);
}

/**
 *
 * @param buff
 */
function des_padding(buff) {
    var targetlen  = 8 - (buff.length % 8);
    var extra_buf = new Buffer(targetlen);
    extra_buf.fill(0);
    var pad_buf = Buffer.concat([buff, extra_buf]);
    pad_buf[buff.length] = 0x80;
    return pad_buf;
}

/**
 *
 * @param {Buffer} arr1
 * @param {Buffer} arr2
 * @returns {Buffer}
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
};