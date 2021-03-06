/**
 * DES
 *  - des, triple des, des ecb, des cbc
 *
 * AES
 *  aes 16, 24, 32 long key
 *
 *
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
 * @param {number} length
 * @returns {Buffer}
 */
function random(/*number*/length) {
    return crypto.randomBytes(length);
}

/**
 *
 * @param {number} length
 * @returns {Buffer}
 */
function pseudoRandom(/*number*/ length) {
    return crypto.pseudoRandomBytes(length);
}
//----------------------------------------------------------------------------------------------------------------------
// des - ecb
//----------------------------------------------------------------------------------------------------------------------
/**
 * DES.
 *
 * @param {Buffer} key key value
 * @param {Buffer} input message
 * @returns {Buffer} des encrypted data
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

    /*
    var update = cipher.update(input, 'binary', 'hex');
    var final = cipher.final('hex');

    console.log('des cipher: update', update);
    console.log('des cipher: final', final);

    //var ret = cipher.update(input, 'binary', 'hex');
    //console.log(" ecb encrypt(update) : " + ret);
    //ret += cipher.final('hex');
    //console.log(" ecb encrypt(final) : " + ret);
    //return ret;

    return new Buffer(update + final, 'hex');
    */
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
    return decipher.update(input);
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
 * @param {Buffer} key
 * @param {Buffer} input
 * @param {Buffer} iv
 * @returns {Buffer}
 */
function des_cbc_decrypt(key, input, iv) {
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
 * @param {Buffer} key
 * @param {Buffer} input
 * @returns {Buffer}
 */
function aes_ecb_encrypt(key, input) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit key aes ecb mode
        cipherType = 'aes-128-ecb';
    } else if( key.length == 24) {
        //192 bit key aes ecb mode
        cipherType = 'aes-192-ecb';
    } else if (key.length == 32) {
        //256 bit key aes ecb mode
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
 * @param {Buffer} key
 * @param {Buffer} input
 * @returns {Buffer}
 */
function aes_ecb_decrypt(key, input) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit key aes ecb mode
        cipherType = 'aes-128-ecb';
    } else if( key.length == 24) {
        //192 bit key aes ecb mode
        cipherType = 'aes-192-ecb';
    } else if (key.length == 32) {
        //256 bit key aes ecb mode
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
 * @param {Buffer} key
 * @param {Buffer} input
 * @param {Buffer} iv
 * @returns {Buffer}
 */
function aes_cbc_encrypt(key, input, iv) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit key aes cbc mode
        cipherType = 'aes-128-cbc';
    } else if( key.length == 24) {
        //192 bit key aes cbc mode
        cipherType = 'aes-192-cbc';
    } else if (key.length == 32) {
        //256 bit key aes cbc mode
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
 * @param {Buffer} key
 * @param {Buffer} input
 * @param {Buffer} iv
 * @returns {Buffer}
 */
function aes_cbc_decrypt(key, input,iv) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit key aes ecb mode
        cipherType = 'aes-128-cbc';
    } else if( key.length == 24) {
        //192 bit key aes cbc mode
        cipherType = 'aes-192-cbc';
    } else if (key.length == 32) {
        //256 bit key aes cbc mode
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
 * @param {Buffer} key
 * @param {Buffer} input
 * @param {Buffer} iv
 * @returns {Buffer}
 */
function aes_ctr_encrypt(key, input, iv) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit key aes ctr mode
        cipherType = 'aes-128-ctr';
    } else if( key.length == 24) {
        //192 bit key aes ctr mode
        cipherType = 'aes-192-ctr';
    } else if (key.length == 32) {
        //256 bit key aes ctr mode
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
 * @param {Buffer} key
 * @param {Buffer} input
 * @param {Buffer} iv
 * @returns {Buffer}
 */
function aes_ctr_decrypt(key, input, iv) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit key aes ctr mode
        cipherType = 'aes-128-ctr';
    } else if( key.length == 24) {
        //192 bit key aes ctr mode
        cipherType = 'aes-192-ctr';
    } else if (key.length == 32) {
        //256 bit key aes ctr mode
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
// seed
//----------------------------------------------------------------------------------------------------------------------
function seed_ecb_encrypt(key, input) {
    var cipher = crypto.createCipheriv('seed-ecb', key, '');
    cipher.setAutoPadding(false);
    return cipher.update(input);
}

function seed_ecb_decrypt(key, input) {
    var decipher = crypto.createDecipheriv('seed-ecb', key, '');
    decipher.setAutoPadding(false);
    return decipher.update(input);
}

function seed_cbc_encrypt(key, input, iv) {
    if(iv === undefined){
        iv = new Buffer(16);
        iv.fill(0);
    }
    var cipher = crypto.createCipheriv('seed-cbc', key, iv);
    cipher.setAutoPadding(false);
    return cipher.update(input);
}

function seed_cbc_decrypt(key, input, iv) {
    if(iv === undefined){
        iv = new Buffer(16);
        iv.fill(0);
    }
    var decipher = crypto.createDecipheriv('seed-cbc', key, iv);
    decipher.setAutoPadding(false);
    return decipher.update(input);
}


//----------------------------------------------------------------------------------------------------------------------
// mac
//----------------------------------------------------------------------------------------------------------------------
/**
 *
 * @param {String} type 'sha1', 'sha256', 'md5'
 * @param {Buffer} key 'key'
 * @param {Buffer} data
 * @returns {Buffer}
 */
function hmac(type, key, data) {
    return crypto.createHmac(type, key).update(data).digest();
}

/**
 *
 * @param {Buffer} key
 * @param {Buffer} data
 */
function hmac_sha1(key, data) {
    return crypto.createHmac('sha1', key).update(data).digest();
}



/**
 * Full Triple Des MAC
 * FIPS PUB 113 Computer Data Authentication is a (now obsolete) U.S. government standard that specified the CBC-MAC algorithm using DES as the block cipher.
 * The CBC-MAC algorithm is equivalent to ISO/IEC 9797-1 MAC Algorithm 1.
 * http://en.wikipedia.org/wiki/CBC-MAC
 * http://www.freesoft.org/CIE/RFC/1510/83.htm
 *
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Buffer}
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
 *
 * @param {Buffer} key
 * @param {Buffer} data
 */
function des_mac_emv(key, data){
    var key1 = key.slice(0, 8); // for single des key
    var iv = new Buffer(8);
    iv.fill(0);

    data = des_padding(data);

    var singledes = des_cbc_encrypt(key1, data, iv);
    var block = data.slice(data.length-8, data.length);
    var cipher = xor(singledes, block);

    return des_ecb_encrypt(key, cipher);
}


/**
 * http://en.wikipedia.org/wiki/CMAC
 * https://code.google.com/p/impacket/source/browse/trunk/impacket/crypto.py?r=707
 *
 * @param {Buffer} key
 * @param {Buffer} data
 */
function aes_mac(key, data) {
    //http://en.wikipedia.org/wiki/CMAC
    data = aes_padding(data);
    var result = aes_cbc_encrypt(key, data);
    return result.slice(result.length-16, result.length);
}


///AES CMAC
function MSB(buf) {
    var tmp ;
    if(buf instanceof Buffer || buf instanceof Array) {
        tmp = buf[0];
    } else {
        tmp = buf;
    }
    return  (tmp & 0x80) ? 1 : 0;
}

function shift_left_1(buf) {
    var len = buf.length;
    var ret = new Buffer(len);

    for(var i=0; i< len; i++) {
        ret[i]  = buf[i] << 1;
        if( i+1 < buf.length && (MSB(buf[i+1]) != 0)) {
            ret[i] |= 0x01;
        }
    }
    return ret;
}



function generate_subkey(K) {

    var const_zero = new Buffer(16);
    const_zero.fill(0);
    var const_Rb = 0x87;
    //var const_zero = new Buffer('00000000000000000000000000000000', 'hex');
    //var const_Rb   = new Buffer('00000000000000000000000000000087', 'hex');

    //Step 1. L = aes-128(K, consta_zero)
    var L = aes_cbc_encrypt(K, const_zero);

    //Step 2. if MSB(L) == 0
    //        then K1 = L << 1
    //        else K1 = (L << 1) XOR const Rb
    var K1 = shift_left_1(L);
    if(MSB(L) == 1) {
        K1[K1.length-1] ^= const_Rb;
    }

    //Step 3. if MSB(K1) == 0
    //        then K2 = K1 << 1
    //        else K2 = (K1 << 1) XOR const Rb
    var K2 = shift_left_1(K1);
    if(MSB(K1) == 1) {
        K2[K2.length-1] ^= const_Rb;
    }

    //Step 4. return k1, k2
    return {
        K1: K1,
        K2: K2
    };
}


/**
 *
 * @param key
 * @param data
 * @returns {Buffer}
 */
function aes_cmac(key, data) {
    //RFC 4493 The AES-CMAC algorithm http://www.ietf.org/rfc/rfc4493.txt
    //NIST SP 800-38B The CMAC Mode for Authentication http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
    var const_Bsize = 16;
    //var const_zero = new Buffer(16).fill(0);
    var const_zero = new Buffer(16);
    const_zero.fill(0);

    //Step 1. [K1, K2] = generate_subkey(key)
    var keys = generate_subkey(key);
    var K1 = keys['K1'];
    var K2 = keys['K2'];

    //Step 2. n = ceil(len/const_Bsize)
    var M = data; //new Buffer(data.length).fill(0);
    var len = M.length;
    var n = Math.ceil(len/const_Bsize);

    //Step 3. if n = 0
    //        then  n = 1; falg = false;
    //        else
    //            if len mod const_Bsize == 0
    //            then flag = true
    //            else flag = false
    var flag; // complete block flag
    if ( n == 0 ){
        n = 1;
        flag = false;
    } else {
        if( len % const_Bsize == 0) {
            flag = true;
        } else {
            //n += 1;
            flag = false
        }
    }

    //Step 4. if flag is true
    //        then M_last = M_n xor K1;
    //        else M_last = aes_padding(M_n) xor K2;
    var offset = (n-1) * const_Bsize;
    var M_n = M.slice(offset);

    var M_last;
    if (flag == true) {
        M_last = xor(M_n, K1);
    } else {
        M_last = xor(aes_padding(M_n), K2);
    }

    //Step 5. X = const_zero
    var X= const_zero;

    var Y;

    //Step 6. for (i=1 i<n-1; i++)
    //            Y = X xor M_i
    //            X = aes-128(K, Y)
    //        Y = M_last xor X
    //        T = AES-128(K, Y)
    var M_i;
    for(var i=0; i<n-1; i++) {
        M_i = M.slice(i * const_Bsize);
        Y = xor(X, M_i);
        X = aes_cbc_encrypt(key, Y);
    }
    Y = xor(M_last, X);
    //Step 7. return T
    return aes_cbc_encrypt(key, Y);
}

/**
 *
 * @param {Buffer} buff
 * @param {number} block_size
 * @returns {Buffer}
 */
function ISO9797Method_1(buff, block_size) {

    var padd_len = block_size - (buff.length % block_size);
    if(padd_len == block_size) {
        return new Buffer(buff);
    }
    var pad = new Buffer(padd_len);
    pad.fill(0);

    return Buffer.concat([buff, pad]);
}

/**
 *
 * @param {Buffer} buff
 * @param {number} block_size
 * @returns {Buffer}
 */
function ISO9797Method_2(buff, block_size) {

    var padd_len = block_size - (buff.length % block_size);

    var pad = new Buffer(padd_len);
    pad.fill(0);
    pad[0] = 0x80;

    return Buffer.concat([buff, pad]);

    /*
    var padd_len  = (block_size - ((buff.length + 1) % block_size)) + 1;
    var pad = new Buffer(padd_len);
    pad.fill(0);
    pad[0] = 0x80;

    return  Buffer.concat([buff, pad]);
    */
}


/**
 *
 * @param {Buffer} data
 * @return {Buffer}
 */
function des_padding(data) {
    return ISO9797Method_2(data, 8);
}

/**
 *
 * @param {Buffer} data
 * @return {Buffer}
 */
function aes_padding(data) {
    return ISO9797Method_2(data, 16);
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
        ret[i] = arr1[i] ^ arr2[i];
    }

    return new Buffer(ret);
}

/**
 * int to hexa string.
 *
 * @param {Number} num
 * @returns {string}
 */
function toHex(num) {
    return ('0' + (Number(num).toString(16))).slice(-2).toUpperCase();
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

    //seed
    seed_ecb_encrypt: seed_ecb_encrypt,
    seed_ecb_decrypt: seed_ecb_decrypt,
    seed_cbc_encrypt: seed_cbc_encrypt,
    seed_cbc_decrypt: seed_cbc_decrypt,

    //mac
    hmac: hmac,
    hmac_sha1: hmac_sha1,
    des_mac: des_mac,
    des_mac_emv: des_mac_emv,
    aes_mac: aes_mac,
    aes_cmac: aes_cmac,

    //padding
    ISO9797Method_1: ISO9797Method_1,
    ISO9797Method_2: ISO9797Method_2,
    des_padding: des_padding,
    aes_padding: aes_padding,


    //util
    xor: xor,
    toHex : toHex,

    shift_left_1: shift_left_1
};