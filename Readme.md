#Nodejs Crypto Example

nodejs crypto example
- hash
- des
- aes


#Run
<code>node crypto_example.js</code>

## TODO
- make it lib

- hmac-sha1
- hmac-sha1-160

- RSA Public Key
- RSA Private Key

#Examples  and test
 - you can find some example in test directory.
  - test/hash.js
  - test/des.js
  - test/aes.js
  - test/padding.js
 - you can test using [mocha](http://visionmedia.github.io/mocha/)

```
_mocha --ui exports ./test
```




## Hash Example

- hash wrapper

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


##history
- added test framework : [mocha](http://visionmedia.github.io/mocha/)

