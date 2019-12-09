"use strict"

var _hc256_P = new Uint8Array();
var _hc256_Q = new Uint8Array();
var _hc256_i = 0;

function ror(i, n) { return (i >>> n) | (i << (32-n)); }

function _f1(x) { return ror(x, 7) ^ ror(x, 18) ^ ror(x, 3); }

function _f2(x) { return ror(x, 17) ^ ror(x, 19) ^ ror(x, 10); }

function text_to_byte_arr(text) {
	var result = [];

	for (var i in text) result.push(text.charCodeAt(i));

	return result;
}

// With init_value of 32 this will basically pad the array with spaces
// That way it is compatible with BlitzMax implementation of HC-256
function arr_extend(array, tgt_len, init_value = 32) {
	for (var i=array.length; i < tgt_len; i++) array.push(init_value);

	return array;
}

function initialize_from_text(key, salt) {
	key = text_to_byte_arr(key);
	salt = text_to_byte_arr(salt);

	if (key.length < 8) key = arr_extend(key, 8);
	if (salt.length < 8) salt = arr_extend(salt, 8);

	var k = [8], iv = [8];

	var l = key.length;
	for (var i=0; i < l; i++) {
		k[i & 7] = key[i] + _f1( key[(i+3) % l] ) + _f2( key[(i+5) % l] );
	}

	l = salt.length;
	for (var i=0; i < l; i++) {
		iv[i & 7] = salt[i] + _f1( salt[(i+3) % l] ) + _f2( salt[(i+5) % l] );
	}

	initialize(k, iv);
}

function _g1(x, y) { return (ror(x, 10) ^ ror(y, 23)) + _hc256_Q[(x ^ y) & 1023]; }

function _g2(x, y) { return (ror(x, 10) ^ ror(y, 23)) + _hc256_P[(x ^ y) & 1023]; }

function initialize(k, iv) {
	if (k.length != 8 || iv.length != 8)
		Error("K and IV must have length of 8");

	var W = [].concat(k).concat(iv);

	for (var i=16; i <= 2559; i++) {
		W[i] = (_f2(W[i-2]) + W[i-7] + _f1(W[i-15]) + W[i-16] + i) >> 0;
		// >> 0 will prevent the operation from outputting a float
		// >>> 0 will help too, but it will also lose the signedness
		// >>> 0 is like casting to unsigned int basically
	}

	_hc256_P = W.slice(512, 1536);
	_hc256_Q = W.slice(1536);

	if (_hc256_P.length != 1024 || _hc256_Q.length != 1024)
		Error("Error in the length of S-boxes");

	var j = 0;
	for (var i=0; i < 4096; i++) {
		j = i & 1023;
		if ((i & 2047) < 1024) {
			_hc256_P[j] = (_hc256_P[j] + (_hc256_P[(j-10) & 1023] + _g1( _hc256_P[(j-3) & 1023], _hc256_P[(j-1023 & 1023)]))) >> 0;
		} else {
			_hc256_Q[j] = (_hc256_Q[j] + (_hc256_Q[(j-10) & 1023] + _g2( _hc256_Q[(j-3) & 1023], _hc256_Q[(j-1023 & 1023)]))) >> 0;
		}
	}

	_hc256_i = 0;
}

function _h1(x) {
	var b = [x & 0xFF, (x >>> 8) & 0xFF, (x >>> 16) & 0xFF, (x >>> 24) & 0xFF];
	return (_hc256_Q[ b[0] ] + _hc256_Q[ 256 + b[1] ] + _hc256_Q[ 512 + b[2] ] + _hc256_Q[ 768 + b[3] ]) >> 0;
}

function _h2(x) {
	var b = [x & 0xFF, (x >>> 8) & 0xFF, (x >>> 16) & 0xFF, (x >>> 24) & 0xFF];
	return (_hc256_P[ b[0] ] + _hc256_P[ 256 + b[1] ] + _hc256_P[ 512 + b[2] ] + _hc256_P[ 768 + b[3] ]) >> 0;
}

function output() {
	var j = _hc256_i & 1023;
	if ((_hc256_i & 2047) < 1024) {
		_hc256_i++;
		_hc256_P[j] = (_hc256_P[j] + (_hc256_P[(j-10) & 1023] + _g1( _hc256_P[(j-3) & 1023], _hc256_P[(j-1023 & 1023)]))) >> 0;
		return (_h1( _hc256_P[(j-12) & 1023] ) ^ _hc256_P[j]) >> 0;
	} else {
		_hc256_i++;
		_hc256_Q[j] = (_hc256_Q[j] + (_hc256_Q[(j-10) & 1023] + _g2( _hc256_Q[(j-3) & 1023], _hc256_Q[(j-1023 & 1023)]))) >> 0;
		return (_h2( _hc256_Q[(j-12) & 1023] ) ^ _hc256_Q[j]) >> 0;
	}
}

function encrypt_string(str) {
	var len = (str.length ^ output()) >> 0; // This length is in unicode codepoints
	var encoded = {len: 0, str: ""};
	var out = 0;

	str = new TextEncoder().encode(str);

	var l = str.length;
	for (var i=0; i < l; i += 4) {
		out = output();
		for (var j=0; j < 4; j++) {
			if ((i+j) >= l) break;
			encoded.str += String.fromCodePoint(str[i+j] ^ (out & 0xFF));
			out >>>= 8;
		}
	}

	encoded.len = len;

	return encoded;
}

function decrypt_string(enc_str_obj) {
	var len = (enc_str_obj.len ^ output()) >> 0;
	var decoded_str = "";
	var str = enc_str_obj.str
	var out = 0;

	if (len > 16777216) {
		console.log("Encountered a very large length. That usually happens when the key is incorrect. Or the string really is that large. Aborting just in case.");
		return 0;
	}

	var l = str.length;
	var decoded_arr = new Uint8Array(l);
	for (var i=0; i < l; i += 4) {
		out = output();

		for (var j=0; j < 4; j++) {
			if ((i+j) >= l) break;
			decoded_arr[i+j] = str.charCodeAt(i+j) ^ (out & 0xFF);
			out >>>= 8;
		}

	}

	decoded_str = new TextDecoder().decode(decoded_arr);
	if (decoded_str.length != len) console.log("String length mismatch; expected", len, "but have", decoded_str.length);

	return decoded_str;
}

initialize_from_text("test1234", "salt5678");
var test = encrypt_string("The encryption/decryption is working, with emojis too! 😊");

initialize_from_text("test1234", "salt5678");
console.log(decrypt_string(test));
