;(function ($) {
	'use strict';
	var delta = 0x9E3779B9;

	function RandByte(){
		return parseInt(Math.random() * 0x100);
	}

	function Hex2Bin(data){
		var i, l = data.length;
		var h4, l4, ret = [];
		if(l % 2 != 0)
			return '';
		l >>= 1;
		for(i=0; i<l; i++)
		{
			h4 = data.charCodeAt(i << 1);
			l4 = data.charCodeAt((i << 1) + 1);
			if(h4 >= 48 && h4 <= 57)
				h4 -= 48;
			else if(h4 >= 97 && h4 <= 102)
				h4 -= 87;
			else if(h4 >= 65 && h4 <= 70)
				h4 -= 55;
			else
				return '';
			if(l4 >= 48 && l4 <= 57)
				l4 -= 48;
			else if(l4 >= 97 && l4 <= 102)
				l4 -= 87;
			else if(l4 >= 65 && l4 <= 70)
				l4 -= 55;
			else
				return '';
			ret[i] = String.fromCharCode((h4<<4) | l4);
		}
		return ret.join('');
	}

	function Bin2Hex(data){
		var tb = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
		var i, ch, l = data.length;
		var ret = [];
		for(i=0; i<l; i++)
		{
			ch = data.charCodeAt(i);
			ret[i << 1] = tb[ch >> 4];
			ret[(i << 1) + 1] = tb[ch & 0x0F];
		}
		return ret.join('');
	}

	function BinXor(a, b)
	{
		var i, l = a.length, ret = [];
		for(i=0; i<l; i++)
			ret[i] = String.fromCharCode(a.charCodeAt(i) ^ b.charCodeAt(i));
		return ret.join('');
	}

	function stringToLongArray(string) {
		var result = [];

		for (var i = 0, length = string.length; i < length; i += 4) {
			result.push((
				string.charCodeAt(i + 0) << 24 |
				string.charCodeAt(i + 1) << 16 |
				string.charCodeAt(i + 2) << 8 |
				string.charCodeAt(i + 3))
			);
		}

		return result;
	}

	function longArrayToString(data) {
		for (var i = 0, length = data.length; i < length; i++) {
			data[i] = String.fromCharCode(
				data[i] >>> 24 & 0xff,
				data[i] >>> 16 & 0xff,
				data[i] >>> 8 & 0xff,
				data[i] & 0xff
			);
		}
		return data.join('');
	}

	//TEA加密。v被加密的数据16字节；key长度为4的整型数组
	function encipher(v, key){
		var sum = delta, n = 0x10;//16轮加密
		var data = stringToLongArray(v);

		while(n-- > 0){
			data[0] += ((data[1] << 4 & 0xFFFFFFF0) + key[0]) ^ (data[1] + sum) ^ ((data[1] >> 5 & 0x07ffffff) + key[1]);
			data[1] += ((data[0] << 4 & 0xFFFFFFF0) + key[2]) ^ (data[0] + sum) ^ ((data[0] >> 5 & 0x07ffffff) + key[3]);
			sum += delta;
		}
		return longArrayToString(data);
	}

	//TEA解密。v被解密的数据16字节；key长度为4的整型数组
	function decipher(v, key){
		var sum = (delta << 4) & 0xffffffff, n = 0x10;//16轮解密
		var data = stringToLongArray(v);

		while(n-- > 0){
			data[1] -= (((data[0] << 4 & 0xFFFFFFF0) + key[2]) ^ (data[0] + sum) ^ ((data[0] >> 5 & 0x07ffffff) + key[3]));
			data[1] &= 0xffffffff;
			data[0] -= (((data[1] << 4 & 0xFFFFFFF0) + key[0]) ^ (data[1] + sum) ^ ((data[1] >> 5 & 0x07ffffff) + key[1]));
			data[0] &= 0xffffffff;
			sum -= delta;
		}
		return longArrayToString(data);
	}

	function Encrypt(data, key){
		var i, ret = [], l = data.length;
		if(l <= 0)
			return '';
		var filln = (8 - ((l + 10) & 0x07)) & 0x07; //填充的长度
		var arr = new Array(1 + filln + 2);
		key = stringToLongArray(key);
		arr[0] = String.fromCharCode(RandByte() & 0xF8 | filln);
		var ch = String.fromCharCode(RandByte());
		for(i=1; i<=filln; i++)
			arr[i] = ch;
		filln += 2;
		for(; i<=filln; i++)
			arr[i] = String.fromCharCode(RandByte());
		arr[i++] = data;
		arr[i] = "\x00\x00\x00\x00\x00\x00\x00";//尾部填充的 7 字节的 \0
		//data = arr.join("") + data + "\x00\x00\x00\x00\x00\x00\x00";//尾部填充的 7 字节的 \0
		data = arr.join("");
		l = data.length;
		var crypt = '\x00\x00\x00\x00\x00\x00\x00\x00', prePlain = crypt, temp;

		for(i=0; i<l ; i += 8){
			temp = BinXor(data.substr(i, 8), crypt);
			crypt = BinXor(encipher(temp, key), prePlain);
			prePlain = temp;
			ret.push(crypt);
		}

		return ret.join('');
	}

	function Decrypt(data, key){
		var i, plain, ret = [], l = data.length;
		if(l < 16 || (l & 0x07) != 0)
			return '';
		var preCrypt = data.substr(0, 8);
		key = stringToLongArray(key);
		var prePlain = decipher(preCrypt, key);
		var filln = prePlain.charCodeAt(0) & 0x7;
		var pos = 1 + filln + 2;
		//校验头部填充是否正确
		var ch = prePlain.charCodeAt(1);
		for(i=2; i<=filln; i++)
			if(prePlain.charCodeAt(i) != ch)
				return '';
		ret.push(prePlain);
		for(i=8; i<l; i+=8){
			plain = BinXor(decipher(BinXor(data.substr(i, 8), prePlain), key), preCrypt);
			prePlain = BinXor(plain, preCrypt);
			preCrypt = data.substr(i, 8);
			ret.push(plain);
		}
		ret = ret.join('');
		//校验尾部填充7字节是否都为0
		l = ret.length;
		for(i=l-7; i<l; i++)
			if(ret.charCodeAt(i) != 0x00)
				return '';

		return ret.substr(pos, l - 7 - pos);
	}
	
	function EncryptStr(str, key, raw){
		var data = Encrypt(unescape(encodeURIComponent(str)), key);
		if(!raw)
			data = Bin2Hex(data);
		return data;
	}
	
	function DecryptStr(str, key, raw){
		var data = Decrypt(Hex2Bin(str), key);
		if(!raw)
			data = decodeURIComponent(escape(data));
		return data;
	}
	
	$.QQTea = {encrypt: Encrypt, encryptstr: EncryptStr, decrypt: Decrypt, 
		decryptstr: DecryptStr, hex2bin: Hex2Bin, bin2hex: Bin2Hex};
}(this))