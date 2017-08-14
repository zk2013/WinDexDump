#ifndef __TYPE_DEFS_H__
#define __TYPE_DEFS_H__

#include<assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

# define SWAP2(_value)      (_value)
# define SWAP4(_value)      (_value)
# define SWAP8(_value)      (_value)

typedef unsigned char u1;
typedef unsigned int u4;
typedef unsigned short u2;
typedef unsigned long uLong;
typedef unsigned long long u8;
typedef int s4;
typedef long long s8;
typedef short s2;
typedef char s1;

#include "DexFile.h"



#define ALOGW(...) printf("W/" __VA_ARGS__)
#define ALOGE(...) printf("E/" __VA_ARGS__)
#define ALOGV(...) printf("V/" __VA_ARGS__)

/* DEX file magic number */
#define DEX_MAGIC       "dex\n"

/* current version, encoded in 4 bytes of ASCII */
#define DEX_MAGIC_VERS  "036\0"

#define DEX_MAGIC_VERS_API_13  "035\0"

/* same, but for optimized DEX header */
#define DEX_OPT_MAGIC   "dey\n"
#define DEX_OPT_MAGIC_VERS  "036\0"

#define DEX_DEP_MAGIC   "deps"

struct MemMapping {
	void*   addr;           /* start of data */
	size_t  length;         /* length of data */

	void*   baseAddr;       /* page-aligned base address */
	size_t  baseLength;     /* length of mapping */
};
 
struct DexDataMap {
	u4 count;    /* number of items currently in the map */
	u4 max;      /* maximum number of items that may be held */
	u4* offsets; /* array of item offsets */
	u2* types;   /* corresponding array of item types */
};

void dexDataMapFree(DexDataMap* map);

struct CheckState {
	const DexHeader*  pHeader;
	const u1*         fileStart;
	const u1*         fileEnd;      // points to fileStart + fileLen
	u4                fileLen;
	DexDataMap*       pDataMap;     // set after map verification
	const DexFile*    pDexFile;     // set after intraitem verification

									/*
									* bitmap of type_id indices that have been used to define classes;
									* initialized immediately before class_def cross-verification, and
									* freed immediately after it
									*/
	u4*               pDefinedClassBits;

	const void*       previousItem; // set during section iteration
};

#endif
