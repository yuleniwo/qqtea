#ifndef _TEA_H_
#define _TEA_H_

#include "defs.h"

typedef struct
{
	uint8 buf[8];
	uint8 bufPre[8];
	const uint8 *pKey;
	uint8 *pCrypt;
	uint8 *pCryptPre;
	uint32 uRandSeed;	//随机数种子
} TEACTX, *LPTEACTX;

uint16 h2ns(uint16 usHost);
uint32 h2nl(uint32 ulHost);
//uint16 n2hs(uint16 usNet);
//uint32 n2hl(uint32 ulHost);
#define n2hs h2ns
#define n2hl h2nl

//TEA初始化随机数种子
void STDCALL TeaInitRandSeed(TEACTX *pCtx, uint32 uRandSeed);

//计算加密nLen字节所需的缓冲区大小。
uint32 STDCALL TeaEncNeedLen(uint32 nLen);

//TEA加密。pPlain指向待加密的明文。uPlainLen明文长度。pKey密钥16字节。
//pOut指向密文输出缓冲区。pOutLen输入输出参数，指示输出缓冲区长度(密文长度)。
//返回值：-1加密失败；0输出缓冲区太小；其他值代表加密成功。
int32 STDCALL TeaEncrypt(TEACTX *pCtx, const void *pPlain, uint32 uPlainLen, const uint8 *pKey, void *pOut, uint32 *pOutLen);

//TEA解密。pCipher指向待解密密文。uCipherLen密文长度。pKey密钥16字节。
//pOut指向明文输出缓冲区。pOutLen输入输出参数，指示输出缓冲区长度(明文长度)。
//返回值：-1解密失败；0输出缓冲区太小；其他值代表解密成功。 
int32 STDCALL TeaDecrypt(TEACTX *pCtx, const void *pCipher, uint32 uCipherLen, const uint8 *pKey, void *pOut, uint32 *pOutLen);

#endif //_TEA_H_
