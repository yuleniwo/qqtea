#include <stdlib.h>
#include <string.h>
#include "tea.h"

uint16 h2ns(uint16 usHost)
{
	const uint16 us = 0x1234;
	return ((uint8 *)&us)[0] == 0x12 ? usHost : ((usHost>>8) | (usHost<<8));
}

uint32 h2nl(uint32 ulHost)
{
	const uint16 us = 0x1234;
	return ((uint8 *)&us)[0] == 0x12 ? ulHost : (((ulHost>>8) & 0xFF00) | 
		((ulHost<<8) & 0xFF0000) | (ulHost<<24) | (ulHost>>24));
}

//uint16 n2hs(uint16 usNet)
//{
//	return h2ns(usNet);
//}
//
//uint32 n2hl(uint32 ulHost)
//{
//	return h2nl(ulHost);
//}

#ifdef _WIN_VER_
int rand_r(unsigned int *seed)
{
	unsigned int next = *seed;
	int result;
	next *= 1103515245;
	next += 12345;
	result = (unsigned int) (next / 65536) % 2048;
	next *= 1103515245;
	next += 12345;
	result <<= 10;
	result ^= (unsigned int) (next / 65536) % 1024;
	next *= 1103515245;
	next += 12345;
	result <<= 10;
	result ^= (unsigned int) (next / 65536) % 1024;
	*seed = next;
	return result;
}
#endif

static uint32 Random(TEACTX *pCtx)
{
	return rand_r(&pCtx->uRandSeed);
}

//TEA加密。v明文8字节。k密钥16字节。w密文输出8字节。 
static void encipher(const uint32 *const v, const uint32 *const k, uint32 *const w)
{
	register uint32 
		y     = h2nl(v[0]),
		z     = h2nl(v[1]),
		a     = h2nl(k[0]),
		b     = h2nl(k[1]),
		c     = h2nl(k[2]),
		d     = h2nl(k[3]),
		n     = 0x10,       /* do encrypt 16 (0x10) times */
		sum   = 0,
		delta = 0x9E3779B9; /*  0x9E3779B9 - 0x100000000 = -0x61C88647 */

	while (n-- > 0)
	{
		sum += delta;
		y += ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
		z += ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
	}

	w[0] = n2hl(y);
	w[1] = n2hl(z);
}

//TEA解密。v密文8字节。k密钥16字节。w明文输出8字节。 
static void decipher(const uint32 *const v, const uint32 *const k, uint32 *const w)
{
	register uint32
		y     = h2nl(v[0]),
		z     = h2nl(v[1]),
		a     = h2nl(k[0]),
		b     = h2nl(k[1]),
		c     = h2nl(k[2]),
		d     = h2nl(k[3]),
		n     = 0x10,
		sum   = 0xE3779B90, 
		/* why this ? must be related with n value*/
		delta = 0x9E3779B9;

	/* sum = delta<<5, in general sum = delta * n */
	while (n-- > 0)
	{
		z -= ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
		y -= ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
		sum -= delta;
	}

	w[0] = n2hl(y);
	w[1] = n2hl(z);
}

void STDCALL TeaInitRandSeed(TEACTX *pCtx, uint32 uRandSeed)
{
	pCtx->uRandSeed = uRandSeed;
}

uint32 STDCALL TeaEncNeedLen(uint32 nLen)
{
	return 1 + ((8 - ((nLen + 10) & 0x07)) & 0x07) + 2 + nLen + 7;
}

//每次8字节加密
static void EncryptEach8Bytes(TEACTX *pCtx)
{
#ifdef CRYPT_ONE_BYTE
	uint8 *pPlain8, *pPlainPre8, *pCrypt8, *pCryptPre8;
	uint32 i;
	pPlain8 = (uint8 *)pCtx->buf;
	pPlainPre8 = (uint8 *)pCtx->bufPre;
	pCrypt8 = (uint8 *)pCtx->pCrypt;
	pCryptPre8 = (uint8 *)pCtx->pCryptPre;
	//本轮明文与上一轮的密文异或 
	for(i=0; i<8; i++)
		pPlain8[i] ^= pCryptPre8[i];
	//再对异或后的明文加密 
	encipher((uint32 *)pPlain8, (uint32 *)pCtx->pKey, (uint32 *)pCrypt8);
	//将加密后的密文与上一轮的明文(其实是上一轮明文与上上轮密文异或结果)异或
	for(i=0; i<8; i++)
		pCrypt8[i] ^= pPlainPre8[i];
	//
	for(i=0; i<8; i++)
		pPlainPre8[i] = pPlain8[i];
#else
	((uint32 *)pCtx->buf)[0] ^= ((uint32 *)pCtx->pCryptPre)[0];
	((uint32 *)pCtx->buf)[1] ^= ((uint32 *)pCtx->pCryptPre)[1];
	encipher((uint32 *)pCtx->buf, (const uint32 *)pCtx->pKey, (uint32 *)pCtx->pCrypt);
	((uint32 *)pCtx->pCrypt)[0] ^= ((uint32 *)pCtx->bufPre)[0];
	((uint32 *)pCtx->pCrypt)[1] ^= ((uint32 *)pCtx->bufPre)[1];
	((uint32 *)pCtx->bufPre)[0] = ((uint32 *)pCtx->buf)[0];
	((uint32 *)pCtx->bufPre)[1] = ((uint32 *)pCtx->buf)[1];
#endif
	pCtx->pCryptPre = pCtx->pCrypt;
	pCtx->pCrypt += 8;
}

int32 STDCALL TeaEncrypt(TEACTX *pCtx, const void *pPlain, uint32 uPlainLen, const uint8 *pKey, void *pOut, uint32 *pOutLen)
{
	const uint8 *p;
	uint32 uOutLen;
	uint8 uPadLen, uPos;
	if(NULL == pPlain || 0 == uPlainLen || NULL == pKey || NULL == pOutLen)
		goto ENCRYPT_FAIL;
	//计算需填充数据内容相同的字节数
	uPadLen = (8 - ((uPlainLen + 1 + 2 + 7) & 0x07)) & 0x07;
	//计算加密后的长度
	uOutLen = 1 + uPadLen + 2 + uPlainLen + 7;
	if(NULL == pOut || *pOutLen < uOutLen)
		goto BUF_TOO_SMALL;
	memset(pCtx->bufPre, 0, sizeof(pCtx->bufPre));
	pCtx->pCrypt = (uint8 *)pOut;
	pCtx->pCryptPre = pCtx->bufPre;
	pCtx->pKey = (const uint8 *)pKey;
	pCtx->buf[0] = (uint8)((Random(pCtx) & 0xF8) | uPadLen);
	memset(pCtx->buf + 1, (uint8)Random(pCtx), uPadLen++);
	uPos = uPadLen;
	for(uPadLen=0; uPadLen<2; uPadLen++)
	{
		if(8 == uPos)
		{
			EncryptEach8Bytes(pCtx);
			uPos = 0;
		}
		pCtx->buf[uPos++] = (uint8)Random(pCtx);
	}
	p = (const uint8 *)pPlain;
	while(uPlainLen > 0)
	{
		if(uPos == 8)
		{
			EncryptEach8Bytes(pCtx);
			uPos = 0;
		}
		pCtx->buf[uPos++] = *(p++);
		uPlainLen--;
	}
	//末尾再添加7字节0后加密，在解密过程的时候可以用来判断key是否正确。 
	uPadLen = pCtx->buf[0];
	((uint32 *)pCtx->buf)[0] = 0;
	((uint32 *)pCtx->buf)[1] = 0;
	pCtx->buf[0] = uPadLen;
	EncryptEach8Bytes(pCtx);
	*pOutLen = uOutLen;
	return (int32)uOutLen;

BUF_TOO_SMALL:
	*pOutLen = uOutLen;
	return 0;
ENCRYPT_FAIL:
	return -1;
}

//每次8字节进行解密 
static void DecryptEach8Bytes(TEACTX *pCtx)
{
#ifdef CRYPT_ONE_BYTE
	uint8 *pBuf8, *pBufPre8, *pCrypt8, *pCryptPre8;
	uint8 bufTemp[8];
	uint32 i;
	pBuf8 = (uint8 *)pCtx->buf;
	pBufPre8 = (uint8 *)pCtx->bufPre;
	pCrypt8 = (uint8 *)pCtx->pCrypt;
	pCryptPre8 = (uint8 *)pCtx->pCryptPre;
	//当前的密文与前一轮明文(实际是前一轮明文与前前轮密文异或结果)异或 
	for(i=0; i<8; i++)
		bufTemp[i] = pCrypt8[i] ^ pBufPre8[i];
	//异或后的结果再解密(解密后得到当前名文与前一轮密文异或的结果，并非真正明文)
	decipher((uint32 *)bufTemp, (uint32 *)pCtx->pKey, (uint32 *)pBufPre8);
	//解密后的结果与前一轮的密文异或，得到真正的明文 
	for(i=0; i<8; i++)
		pBuf8[i] = pBufPre8[i] ^ pCryptPre8[i];
#else
	((uint32 *)pCtx->buf)[0] = ((uint32 *)pCtx->pCrypt)[0] ^ ((uint32 *)pCtx->bufPre)[0];
	((uint32 *)pCtx->buf)[1] = ((uint32 *)pCtx->pCrypt)[1] ^ ((uint32 *)pCtx->bufPre)[1];
	decipher((uint32 *)pCtx->buf, (const uint32 *)pCtx->pKey, (uint32 *)pCtx->bufPre);
	((uint32 *)pCtx->buf)[0] = ((uint32 *)pCtx->bufPre)[0] ^ ((uint32 *)pCtx->pCryptPre)[0];
	((uint32 *)pCtx->buf)[1] = ((uint32 *)pCtx->bufPre)[1] ^ ((uint32 *)pCtx->pCryptPre)[1];
#endif
	pCtx->pCryptPre = pCtx->pCrypt;
	pCtx->pCrypt += 8;
}

int32 STDCALL TeaDecrypt(TEACTX *pCtx, const void *pCipher, uint32 uCipherLen, const uint8 *pKey, void *pOut, uint32 *pOutLen)
{
	uint32 uOutLen, u;
	uint8 uPos, uPadLen;
	// 待解密的数据长度最少16字节，并且长度满足是8的整数倍。
	if(NULL == pCipher || NULL == pKey || NULL == pOutLen || uCipherLen < 16 || (uCipherLen & 0x07) != 0)
		goto DECRYPT_FAIL;
	pCtx->pKey = pKey;
	// 先解密头8字节，以便获取第一轮加密时填充的长度。
	decipher((const uint32 *)pCipher, (const uint32 *)pKey, (uint32 *)pCtx->bufPre);
	for(u=0; u<8; u++)
		pCtx->buf[u] = pCtx->bufPre[u];
	uPadLen = pCtx->buf[0] & 0x07; //第一轮加密时填充的长度
	if(uPadLen > 1)
	{
		for(u=2; u<=uPadLen; u++)
		{
			if(pCtx->buf[1] != pCtx->buf[u])
				goto DECRYPT_FAIL;
		}
	}
	uOutLen = uCipherLen - 1 - uPadLen - 2 - 7;
	if(1U + uPadLen + 2 + 7 > uCipherLen)
		goto DECRYPT_FAIL;
	else if(NULL == pOut || *pOutLen < uOutLen)
		goto BUF_TOO_SMALL;
	pCtx->pCryptPre = (uint8 *)pCipher;
	pCtx->pCrypt = (uint8 *)pCipher + 8;
	uPos = uPadLen + 1;
	for(uPadLen=0; uPadLen<2; uPadLen++)
	{
		if(8 == uPos)
		{
			DecryptEach8Bytes(pCtx);
			uPos = 0;
		}
		uPos++;
	}
	for(u=0; u<uOutLen; u++)
	{
		if(uPos == 8)
		{
			DecryptEach8Bytes(pCtx);
			uPos = 0;
		}
		((uint8 *)pOut)[u] = pCtx->buf[uPos];
		uPos++;
	}
	pCtx->buf[0] = 0;
	if(((uint32 *)pCtx->buf)[0] != 0 || ((uint32 *)pCtx->buf)[1] != 0)
		goto DECRYPT_FAIL;
	*pOutLen = uOutLen;
	return (int32)uOutLen;

BUF_TOO_SMALL:
	*pOutLen = uOutLen;
	return 0;
DECRYPT_FAIL:
	return -1;
}