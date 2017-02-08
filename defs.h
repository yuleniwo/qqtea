#ifndef _DEFS_H_
#define _DEFS_H_

typedef char int8;
typedef unsigned char uint8;
typedef uint8 byte;
typedef short int16;
typedef unsigned short uint16;
typedef int int32;
typedef unsigned int uint32;

#if defined(_WIN32) || defined(_WIN64) ||defined(_WIN32_WINNT)
#define _WIN_VER_
#endif

#ifdef _WIN_VER_
	typedef __int64 int64;
	typedef unsigned __int64 uint64;
	#ifdef _WIN64
		typedef uint64 uaddr;
	#else
		typedef uint32 uaddr;
	#endif
	#define STDCALL	__stdcall

	#if defined(_MSC_VER) && !defined(__cplusplus)
		#define inline
	#endif
#else
	typedef long long int64;
	typedef unsigned long long uint64;
	#if __SIZEOF_POINTER__ == 4
		typedef uint32 uaddr;
		#define STDCALL __attribute__((stdcall))
	#elif __SIZEOF_POINTER__ == 8
		typedef uint64 uaddr;
		#define STDCALL
	#endif
#endif

typedef struct
{
	int32 iYear;
	uint8 btMonth;			//从1开始，1~12
	uint8 btDay;			//从1开始
	uint8 btDayOfWeek;		//星期日0，星期一1，星期二2，...，星期六6。其他值无效忽略。
	uint8 btHour;			//0~23
	uint8 btMinute;			//0~59
	uint8 btSecond;			//0~59
	uint16 wMillisecond;	//0~999
} SYSTIME, *LPSYSTIME;

#endif //_DEFS_H_
