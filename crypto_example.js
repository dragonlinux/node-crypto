/**
 * Created by coolbong on 2014-05-27.
 */

var assert = require('assert');
var crypto = require('./node_crypto');

var log_flag = true;

function xor(arr1, arr2) {
    var ret = [];
    var len = (arr1.length > arr2.length) ? (arr2.length) : (arr1.length);
    for (var i = 0; i < len; i++) {
        ret.push(arr1[i] ^ arr2[i]);
    }

    return new Buffer(ret);
}


function logging(str) {
    if(log_flag)
        console.log(str);
}

//----------------------------------------------------------------------------------------------------------------------
// cipher list
//----------------------------------------------------------------------------------------------------------------------
logging(crypto.getSupportedCipher());

//----------------------------------------------------------------------------------------------------------------------
// hash list
//----------------------------------------------------------------------------------------------------------------------
logging(crypto.getSupportedHashes());

//----------------------------------------------------------------------------------------------------------------------
// hash
//----------------------------------------------------------------------------------------------------------------------

logging('hash sha1 ---------------------------------------------------------------------------------------------------');
message = new Buffer("");
ref = new Buffer("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", 'hex');
hash = crypto.hash('sha1', message);
logging(hash.toString('hex'));
assert(hash.toString('hex') == ref.toString('hex'));


message = new Buffer("61", 'hex');
ref = new Buffer("86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8", 'hex');
hash = crypto.hash('sha1', message);
logging(hash.toString('hex'));
assert(hash.toString('hex') == ref.toString('hex'));


message = new Buffer("616263", 'hex');
ref = new Buffer("A9993E364706816ABA3E25717850C26C9CD0D89D", 'hex');
hash = crypto.hash('sha1', message);
logging(hash.toString('hex'));
assert(hash.toString('hex') == ref.toString('hex'));


message = new Buffer("6162636465666768696A6B6C6D6E6F707172737475767778797A", 'hex');
ref = new Buffer("32D10C7B8CF96570CA04CE37F2A19D84240D3A89", 'hex');
hash = crypto.hash('sha1', message);
logging(hash.toString('hex'));
assert(hash.toString('hex') == ref.toString('hex'));
logging('-------------------------------------------------------------------------------------------------------------');


logging('hash sha224 -------------------------------------------------------------------------------------------------');
message = new Buffer("616263", 'hex');
ref = new Buffer("23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7", 'hex');

hash = crypto.hash('sha224', message);
logging(hash.toString('hex'));
assert(hash.toString('hex') == ref.toString('hex'));
logging('-------------------------------------------------------------------------------------------------------------');


logging('hash sha256 -------------------------------------------------------------------------------------------------');
message = new Buffer("616263", 'hex');
ref = new Buffer("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", 'hex');
hash = crypto.hash('sha256', message);
logging(hash.toString('hex'));
assert(hash.toString('hex') == ref.toString('hex'));
logging('-------------------------------------------------------------------------------------------------------------');


logging('hash sha384 -------------------------------------------------------------------------------------------------');
message = new Buffer("616263", 'hex');
ref = new Buffer("CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7", 'hex');
hash = crypto.hash('sha384', message);
logging(hash.toString('hex'));
assert(hash.toString('hex') == ref.toString('hex'));
logging('-------------------------------------------------------------------------------------------------------------');



logging('hash sha512 -------------------------------------------------------------------------------------------------');
message = new Buffer("616263", 'hex');
ref = new Buffer("DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F", 'hex');
hash = crypto.hash('sha512', message);
logging(hash.toString('hex'));
assert(hash.toString('hex') == ref.toString('hex'));
logging('-------------------------------------------------------------------------------------------------------------');


logging('hash md5 ----------------------------------------------------------------------------------------------------');
message = new Buffer("", 'hex');
ref = new Buffer("D41D8CD98F00B204E9800998ECF8427E", 'hex');
hash = crypto.hash('md5', message);
logging(hash.toString('hex'));
assert(hash.toString('hex') == ref.toString('hex'));

message = new Buffer("61", 'hex');
ref = new Buffer("0CC175B9C0F1B6A831C399E269772661", 'hex');
hash = crypto.hash('md5', message);
logging(hash.toString('hex'));
assert(hash.toString('hex') == ref.toString('hex'));

message = new Buffer("616263", 'hex');
ref = new Buffer("900150983CD24FB0D6963F7D28E17F72", 'hex');
hash = crypto.hash('md5', message);
logging(hash.toString('hex'));
assert(hash.toString('hex') == ref.toString('hex'));

message = new Buffer("6162636465666768696A6B6C6D6E6F707172737475767778797A", 'hex');
ref = new Buffer("C3FCD3D76192E4007DFB496CCA67E13B", 'hex');
hash = crypto.hash('md5', message);
logging(hash.toString('hex'));
assert(hash.toString('hex') == ref.toString('hex'));
logging('-------------------------------------------------------------------------------------------------------------');


//----------------------------------------------------------------------------------------------------------------------
// des - ecb
//----------------------------------------------------------------------------------------------------------------------
// Define 3 different single DES key values
var key1 = new Buffer("7CA110454A1A6E57", 'hex');
var key2 = new Buffer("0131D9619DC1376E", 'hex');
var key3 = new Buffer("9DC1376E0131D961", 'hex');

//7CA110454A1A6E570131D9619DC1376E9DC1376E0131D961
var plain = new Buffer("01A1D6D039776742", 'hex');
var cipher;
var result;

// Create three single DES keys, a double DES key and a triple DES key
var deskey1 = key1;
var deskey2 = key2;
var deskey3 = key3;

var des2key = Buffer.concat([key1, key2]);
var des3key = Buffer.concat([key1, key2, key3]);


logging('des_ecb_encrypt(single des)------------------------------------------------------------------------------');
// Single DES ECB encrypt
cipher = new Buffer("690F5B0D9A26939B", 'hex');
result = crypto.des_ecb_encrypt(deskey1, plain);
logging(result.toString('hex'));
logging(cipher.toString('hex'));
assert(result.toString('hex') ==  cipher.toString('hex'));

// Single DES ECB decrypt
result = crypto.des_ecb_decrypt(deskey1, cipher);
logging(plain.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == plain.toString('hex'));
logging('---------------------------------------------------------------------------------------------------------');

logging('des_ecb_encrypt(two key triple des)----------------------------------------------------------------------');
// Double DES ECB encrypt (Two key triple DES EDE in ECB mode)
cipher = plain;

cipher = crypto.des_ecb_encrypt(deskey1, cipher);
cipher = crypto.des_ecb_decrypt(deskey2, cipher);
cipher = crypto.des_ecb_encrypt(deskey1, cipher);

result = crypto.des_ecb_encrypt(des2key, plain);
logging(result.toString('hex'));
logging(cipher.toString('hex'));
assert(result.toString('hex') ==  cipher.toString('hex'));

// Double DES ECB decrypt (Two key triple DES EDE in ECB mode)
result = crypto.des_ecb_decrypt(des2key, cipher);
logging(plain.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == plain.toString('hex'));
logging('---------------------------------------------------------------------------------------------------------');

logging('des_ecb_encrypt(three key triple des)--------------------------------------------------------------------');
// Triple DES ECB encrypt (Three key triple DES EDE in ECB mode)
cipher = plain;

cipher = crypto.des_ecb_encrypt(deskey1, cipher);
cipher = crypto.des_ecb_decrypt(deskey2,  cipher);
cipher = crypto.des_ecb_encrypt(deskey3, cipher);

result = crypto.des_ecb_encrypt(des3key, plain);
logging(result.toString('hex'));
logging(cipher.toString('hex'));
assert(result.toString('hex') ==  cipher.toString('hex'));

// Triple DES ECB decrypt (Three key triple DES EDE in ECB mode)
result = crypto.des_ecb_decrypt(des3key, cipher);
logging(plain.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == plain.toString('hex'));
logging('--------------------------------------------------------------------------------------------------------');




//----------------------------------------------------------------------------------------------------------------------
// des - cbc
//----------------------------------------------------------------------------------------------------------------------
logging('des_cbc_encrypt------------------------------------------------------------------------------------------');


//Single DES CBC encrypt
plain = new Buffer("01A1D6D0397767423977674201A1D6D0", 'hex');
iv = new Buffer("59D9839733B8455D", 'hex');

v = plain.slice(0, 8);
v = xor(v, iv);
v = crypto.des_ecb_encrypt(deskey1, v);
cipher = v;
logging("des ecb 1: " + v.toString('hex'));

v = plain.slice(8, 16);
v = xor(cipher, v);
v = crypto.des_ecb_encrypt(deskey1, v);
logging("des ecb 2: " + v.toString('hex'));

cipher = Buffer.concat([cipher, v]);

result = crypto.des_cbc_encrypt(deskey1, plain, iv);
logging(cipher.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == cipher.toString('hex'));
logging('---------------------------------------------------------------------------------------------------------');


logging('des_cbc_decrypt------------------------------------------------------------------------------------------');
// Single DES CBC decrypt
result = crypto.des_cbc_decrypt(deskey1, cipher, iv);
logging(cipher.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == plain.toString('hex'));
logging('---------------------------------------------------------------------------------------------------------');

//----------------------------------------------------------------------------------------------------------------------
// aes-ecb
//----------------------------------------------------------------------------------------------------------------------
logging('aes_ecb_encrypt  128bit aes key--------------------------------------------------------------------------');
key = new Buffer("000102030405060708090A0B0C0D0E0F", 'hex');
plain = new Buffer("00112233445566778899AABBCCDDEEFF", 'hex');
cipher = new Buffer("69C4E0D86A7B0430D8CDB78070B4C55A", 'hex');

result = crypto.aes_ecb_encrypt(key, plain);
logging(cipher.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == cipher.toString('hex'));

result = crypto.aes_ecb_decrypt(key, cipher);
logging(plain.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == plain.toString('hex'));
logging('---------------------------------------------------------------------------------------------------------');


logging('aes_ecb_encrypt  192bit aes key--------------------------------------------------------------------------');
key = new Buffer("000102030405060708090A0B0C0D0E0F1011121314151617", 'hex');
plain = new Buffer("00112233445566778899AABBCCDDEEFF", 'hex');
cipher = new Buffer("DDA97CA4864CDFE06EAF70A0EC0D7191", 'hex');

result = crypto.aes_ecb_encrypt(key, plain);
logging(cipher.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == cipher.toString('hex'));

result = crypto.aes_ecb_decrypt(key, cipher);
logging(plain.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == plain.toString('hex'));
logging('-------------------------------------------------------------------------------------------------------------');


logging('aes_ecb_encrypt  256bit aes key--------------------------------------------------------------------------');
key = new Buffer("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", 'hex');
plain = new Buffer("00112233445566778899AABBCCDDEEFF", 'hex');
cipher = new Buffer("8EA2B7CA516745BFEAFC49904B496089", 'hex');

result = crypto.aes_ecb_encrypt(key, plain);
logging(cipher.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == cipher.toString('hex'));

result = crypto.aes_ecb_decrypt(key, cipher);
logging(plain.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == plain.toString('hex'));
logging('-------------------------------------------------------------------------------------------------------------');


//----------------------------------------------------------------------------------------------------------------------
// aes-cbc
//----------------------------------------------------------------------------------------------------------------------
logging('aes_cbc_encrypt  --------------------------------------------------------------------------------------------');
key = new Buffer("AB94FDECF2674FDFB9B391F85D7F76F2", 'hex');
plain = new Buffer("781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B", 'hex');
cipher = new Buffer("0E5C908F68BA1B2C2DCAFD5D8D6B23E5CC262CBBE26BBD4478580C8DF7EC8D48", 'hex');

result = crypto.aes_cbc_encrypt(key, plain);
logging(cipher.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == cipher.toString('hex'));

result = crypto.aes_cbc_decrypt(key, cipher);
logging(plain.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == plain.toString('hex'));
logging('---------------------------------------------------------------------------------------------------------');




logging('aes_ctr -----------------------------------------------------------------------------------------------------');
key = new Buffer("2B7E151628AED2A6ABF7158809CF4F3C", 'hex');
plain = new Buffer("6BC1BEE22E409F96E93D7E117393172A", 'hex');
cipher = new Buffer("874D6191B620E3261BEF6864990DB6CE", 'hex');
iv = new Buffer("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", 'hex');

result = crypto.aes_ctr_encrypt(key, plain, iv);
logging(cipher.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == cipher.toString('hex'));

result = crypto.aes_ctr_decrypt(key, cipher, iv);
logging(plain.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == plain.toString('hex'));

// Decrypt and encrypt same in CTR mode
result = crypto.aes_ctr_encrypt(key, cipher, iv);
logging(plain.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == plain.toString('hex'));
logging('-------------------------------------------------------------------------------------------------------------');


logging('des mac------------------------------------------------------------------------------------------------------');
key = new Buffer("21F347F04A223FEFEAC7857E057EA42A", 'hex');
plain = new Buffer("8482000010CA5225B746F24411", 'hex');
cmac = new Buffer("D75C127C2959176C", 'hex');

result = crypto.des_mac(key, plain);
logging(result.toString('hex'));
logging(cmac.toString('hex'));
assert(result.toString('hex') == cmac.toString('hex'));


key = new Buffer("404142434445464748494A4B4C4D4E4F", 'hex');
plain = new Buffer("00010203040506074041424344454647", 'hex');
iv    = new Buffer("0000000000000000", 'hex');

plain_padd = crypto.des_padding(plain);
cipher = crypto.des_cbc_encrypt(key, plain_padd, iv);
cipher = cipher.slice(cipher.length-8, cipher.length);

result = crypto.des_mac(key, plain);
logging(cipher.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == cipher.toString('hex'));



/*
plain = new Buffer("Hello World !!!!", 'ascii');

block1 = plain.slice(0, 8);
block2 = plain.slice(8, 16);

cipher = crypto.des_ecb_encrypt(des3key, block1);
cipher = xor(block2, cipher);
cipher = crypto.des_ecb_encrypt(des3key, cipher);

result = crypto.des_mac(des3key, plain);
logging(cipher.toString('hex'));
logging(result.toString('hex'));
assert(result.toString('hex') == cipher.toString('hex'));
*/


//"000102030405060708090A0B0C0D0E0F8000000000000000"
key = new Buffer("404142434445464748494A4B4C4D4E4F", 'hex');
host_challenge = new Buffer("0001020304050607", 'hex');
card_challege = new Buffer("08090A0B0C0D0E0F", 'hex');

//cipher = new Buffer("E1F68FB810397A2F", 'hex');
cipher = new Buffer("D0AEF0167D590E74", 'hex');
plain = Buffer.concat([host_challenge, card_challege]);

result = crypto.des_mac(key, plain);
logging(cipher.toString('hex'));
logging(result.toString('hex'));
//assert(result.toString('hex') == cipher.toString('hex'));

logging('-------------------------------------------------------------------------------------------------------------');


logging('des mac emv--------------------------------------------------------------------------------------------------');
//Retail MAC
plain = new Buffer("Hello World !!!!", 'ascii');
iv = new Buffer("0000000000000000", 'hex');


result = crypto.des_mac_emv(des2key, plain);


block1 = plain.slice(0, 8);
block2 = plain.slice(plain.length - 8, plain.length);


cipher = crypto.des_cbc_encrypt(deskey1, plain, iv);
cipher = xor(cipher, block2);
cipher = crypto.des_ecb_encrypt(des2key, cipher);
//FIXME check this assert mac api changed padding is default
//assert(result.toString('hex') == cipher.toString('hex'));


cipher = crypto.des_ecb_encrypt(deskey1, block1);
cipher = xor(cipher, block2);

cipher = crypto.des_ecb_encrypt(deskey1, cipher);
cipher = crypto.des_ecb_decrypt(deskey2, cipher);
cipher = crypto.des_ecb_encrypt(deskey1, cipher);

//logging(cipher.toString('hex'));
//logging(result.toString('hex'));
//FIXME check this assert mac api changed padding is default
//assert(result.toString('hex') == cipher.toString('hex'));

logging('-------------------------------------------------------------------------------------------------------------');


logging('aes mac    --------------------------------------------------------------------------------------------------');
// AES MAC Make key a 128 bit AES key
key = new Buffer("000102030405060708090A0B0C0D0E0F", 'hex');
plain = new Buffer("01234567890123456789012345678901", 'ascii');

plain_front = plain.slice(0, 16);
plain_end = plain.slice(16, plain.length);

cipher = crypto.aes_ecb_encrypt(key, plain_front);
cipher = crypto.xor(cipher, plain_end);
cipher = crypto.aes_ecb_encrypt(key, cipher);

result = crypto.aes_mac(key, plain);

logging(cipher.toString('hex'));
logging(result.toString('hex'));
//assert(result.toString('hex') == cipher.toString('hex'));
logging('-------------------------------------------------------------------------------------------------------------');

logging('aes cmac    -------------------------------------------------------------------------------------------------');
//AES CMAC
//Make key a 128 bit AES key
key = new Buffer('2B7E151628AED2A6ABF7158809CF4F3C', 'hex');
plain = new Buffer("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411", 'hex');
cipher = new Buffer("DFA66747DE9AE63030CA32611497C827", 'hex');

result = crypto.aes_cmac(key, plain);

logging(cipher.toString('hex'));
logging(result.toString('hex'));
//assert(result.toString('hex') == cipher.toString('hex'));

key = new Buffer("404142434445464748494A4B4C4D4E4F", 'hex');
plain = new Buffer("000000000000000000000006000080010000000000000000B53CA38AD92EEFE5", 'hex');

cipher = new Buffer('ADFC43E1BFD7F3048987695748F56D99', 'hex');
result = crypto.aes_cmac(key, plain);

logging(cipher.toString('hex'));
logging(result.toString('hex'));
//assert(result.toString('hex') == cipher.toString('hex'));

logging('-------------------------------------------------------------------------------------------------------------');


//console.log(crypto.getSupportedCipher());
logging('seed cbc    -------------------------------------------------------------------------------------------------');

//plain = new Buffer('000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff', 'hex');
//key = new Buffer('00000001', 'hex');

//result = crypto.seed_cbc_encrypt(key, plain, iv);
//console.log(result.toString('hex'));

logging('-------------------------------------------------------------------------------------------------------------');



logging('padding    --------------------------------------------------------------------------------------------------');
//ISO/IEC 97971:2011 Annex B Examples
plain = new Buffer('Now is the time for all ', 'ascii');
result = crypto.ISO9797Method_1(plain, 8);
logging(result.toString('hex'));

result = crypto.ISO9797Method_2(plain, 8);
logging(result.toString('hex'));

plain = new Buffer('Now is the time for it', 'ascii');
result = crypto.ISO9797Method_1(plain, 8);
logging(result.toString('hex'));

result = crypto.ISO9797Method_2(plain, 8);
logging(result.toString('hex'));

plain = new Buffer('Now is the time for all ', 'ascii');
result = crypto.ISO9797Method_1(plain, 16);
logging(result.toString('hex'));

result = crypto.ISO9797Method_2(plain, 16);
logging(result.toString('hex'));

plain = new Buffer('Now is the time for it', 'ascii');
result = crypto.ISO9797Method_1(plain, 16);
logging(result.toString('hex'));

result = crypto.ISO9797Method_2(plain, 16);
logging(result.toString('hex'));


logging('-------------------------------------------------------------------------------------------------------------');
