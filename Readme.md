#Nodejs Crypto Example

nodejs crypto example
- hash
- des
- aes


#Run
<code>node crypto_example.js</code>

## TODO
- make it lib

- CRC16/CRC32

- hmac-sha1
- hmac-sha1-160

- RSA
- RSACRT

- Sign
  - 

#Examples  and test
 - you can find some examples in test directory.
  - test/hash.js
  - test/des.js
  - test/aes.js
  - test/padding.js
 - you can test using [mocha](http://visionmedia.github.io/mocha/)

```
_mocha --ui exports ./test
```




## Hash Example

- hash wrapper API

```
/**
 *
 * @param {String} hash  supported hash  'sha1', 'md5', 
 * @param {Buffer} buff
 * @returns {Buffer}
 */
function hash( /* Buffer */ hash, /* Buffer */buff) {
	return crypto.createHash(hash).update(buff).digest();
}
```

- nodejs sha1 hash example

```
// sha1 hash
message = new Buffer('', 'hex');
answer = new Buffer('DA39A3EE5E6B4B0D3255BFEF95601890AFD80709', 'hex');
result = hash('sha1', message);
assert(answer.toString('hex') == result.toString('hex'));
```

```
// sha1 hash
message = new Buffer('hello world', 'hex');
answer = new Buffer('DA39A3EE5E6B4B0D3255BFEF95601890AFD80709', 'hex');
result = hash('sha1', message);
assert(answer.toString('hex') == result.toString('hex'));
```
 
- nodejs sha1 hash example

```
// sha224 hash
message = new Buffer('616263', 'hex');
answer = new Buffer('23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7', 'hex');
result = hash('sha224', message);
assert(answer.toString('hex') == result.toString('hex'));
```


- nodejs md5 hash example
```
message = new Buffer('', 'hex');
answer = new Buffer('D41D8CD98F00B204E9800998ECF8427E', 'hex');
result = hash('md5', message);
assert(answer.toString('hex') == result.toString('hex'));
```


## DES Example

- DES wrapper API

```
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
}
```


- nodejs single DES ECB example

```
// Single des ecb example
key1 = new Buffer('7CA110454A1A6E57', 'hex');
plain = new Buffer('01A1D6D039776742', 'hex');
cipher = new Buffer('690F5B0D9A26939B', 'hex');

result = des_ecb_encrypt(key1, plain);

assert(result.toString('hex') ==  cipher.toString('hex'));
```

##history
- added test framework : [mocha](http://visionmedia.github.io/mocha/)

##其实可以node直接运行看到结果

