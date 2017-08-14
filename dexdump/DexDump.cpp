#include <stdio.h>
#include <Windows.h>
#include "TypeDefs.h"
#include "adler32.h"
#include "DexClass.h"
#include "DexProto.h"
#include "InstrUtils.h"

static bool swapDexHeader(const CheckState* state, DexHeader* pHeader)
{
	if (pHeader->endianTag != kDexEndianConstant) {
		ALOGE("Unexpected endian_tag: %#x", pHeader->endianTag);
		return false;
	}

	return true;
}
static bool isDataSectionType(int mapType) {
	switch (mapType) {
	case kDexTypeHeaderItem:
	case kDexTypeStringIdItem:
	case kDexTypeTypeIdItem:
	case kDexTypeProtoIdItem:
	case kDexTypeFieldIdItem:
	case kDexTypeMethodIdItem:
	case kDexTypeClassDefItem: {
		return false;
	}
	}

	return true;
}
static u4 mapTypeToBitMask(int mapType) {
	switch (mapType) {
	case kDexTypeHeaderItem:               return 1 << 0;
	case kDexTypeStringIdItem:             return 1 << 1;
	case kDexTypeTypeIdItem:               return 1 << 2;
	case kDexTypeProtoIdItem:              return 1 << 3;
	case kDexTypeFieldIdItem:              return 1 << 4;
	case kDexTypeMethodIdItem:             return 1 << 5;
	case kDexTypeClassDefItem:             return 1 << 6;
	case kDexTypeMapList:                  return 1 << 7;
	case kDexTypeTypeList:                 return 1 << 8;
	case kDexTypeAnnotationSetRefList:     return 1 << 9;
	case kDexTypeAnnotationSetItem:        return 1 << 10;
	case kDexTypeClassDataItem:            return 1 << 11;
	case kDexTypeCodeItem:                 return 1 << 12;
	case kDexTypeStringDataItem:           return 1 << 13;
	case kDexTypeDebugInfoItem:            return 1 << 14;
	case kDexTypeAnnotationItem:           return 1 << 15;
	case kDexTypeEncodedArrayItem:         return 1 << 16;
	case kDexTypeAnnotationsDirectoryItem: return 1 << 17;
	default: {
		ALOGE("Unknown map item type %04x", mapType);
		return 0;
	}
	}
}

int safe_mul(size_t* pResult, int a, int b) {
	*pResult = a*b;
	return 1;
}

int safe_add(size_t* pResult, int a, int b) {
	*pResult = a + b;
	return 1;
}

DexDataMap* dexDataMapAlloc(u4 maxCount) {
	/*
	* Allocate a single chunk for the DexDataMap per se as well as the
	* two arrays.
	*/
	size_t size = 0;
	DexDataMap* map = NULL;

	/*
	* Avoiding pulling in safe_iop for safe_iopf.
	*/
	if (!safe_mul(&size, maxCount, sizeof(u4) + sizeof(u2)) ||
		!safe_add(&size, size, sizeof(DexDataMap))) {
		return NULL;
	}

	map = (DexDataMap*)malloc(size);

	if (map == NULL) {
		return NULL;
	}

	map->count = 0;
	map->max = maxCount;
	map->offsets = (u4*)(map + 1);
	map->types = (u2*)(map->offsets + maxCount);

	return map;
}

static bool swapMap(CheckState* state, DexMapList* pMap)
{
	DexMapItem* item = pMap->list;
	u4 count;
	u4 dataItemCount = 0; // Total count of items in the data section.
	u4 dataItemsLeft = state->pHeader->dataSize; // See use below.
	u4 usedBits = 0;      // Bit set: one bit per section
	bool first = true;
	u4 lastOffset = 0;

	count = pMap->size;

	while (count--) {
		if (first) {
			first = false;
		}
		else if (lastOffset >= item->offset) {
			ALOGE("Out-of-order map item: %#x then %#x",
				lastOffset, item->offset);
			return false;
		}

		if (item->offset >= state->pHeader->fileSize) {
			ALOGE("Map item after end of file: %x, size %#x",
				item->offset, state->pHeader->fileSize);
			return false;
		}

		if (isDataSectionType(item->type)) {
			u4 icount = item->size;

			/*
			* This sanity check on the data section items ensures that
			* there are no more items than the number of bytes in
			* the data section.
			*/
			if (icount > dataItemsLeft) {
				ALOGE("Unrealistically many items in the data section: "
					"at least %d", dataItemCount + icount);
				return false;
			}
			// 为什么最后dataItemsLeft不是0？
			dataItemsLeft -= icount;
			dataItemCount += icount;
		}

		u4 bit = mapTypeToBitMask(item->type);

		if (bit == 0) {
			return false;
		}

		if ((usedBits & bit) != 0) {
			ALOGE("Duplicate map section of type %#x", item->type);
			return false;
		}

		usedBits |= bit;
		lastOffset = item->offset;
		item++;
	}

	if ((usedBits & mapTypeToBitMask(kDexTypeHeaderItem)) == 0) {
		ALOGE("Map is missing header entry");
		return false;
	}

	if ((usedBits & mapTypeToBitMask(kDexTypeMapList)) == 0) {
		ALOGE("Map is missing map_list entry");
		return false;
	}

	if (((usedBits & mapTypeToBitMask(kDexTypeStringIdItem)) == 0)
		&& ((state->pHeader->stringIdsOff != 0)
			|| (state->pHeader->stringIdsSize != 0))) {
		ALOGE("Map is missing string_ids entry");
		return false;
	}

	if (((usedBits & mapTypeToBitMask(kDexTypeTypeIdItem)) == 0)
		&& ((state->pHeader->typeIdsOff != 0)
			|| (state->pHeader->typeIdsSize != 0))) {
		ALOGE("Map is missing type_ids entry");
		return false;
	}

	if (((usedBits & mapTypeToBitMask(kDexTypeProtoIdItem)) == 0)
		&& ((state->pHeader->protoIdsOff != 0)
			|| (state->pHeader->protoIdsSize != 0))) {
		ALOGE("Map is missing proto_ids entry");
		return false;
	}

	if (((usedBits & mapTypeToBitMask(kDexTypeFieldIdItem)) == 0)
		&& ((state->pHeader->fieldIdsOff != 0)
			|| (state->pHeader->fieldIdsSize != 0))) {
		ALOGE("Map is missing field_ids entry");
		return false;
	}

	if (((usedBits & mapTypeToBitMask(kDexTypeMethodIdItem)) == 0)
		&& ((state->pHeader->methodIdsOff != 0)
			|| (state->pHeader->methodIdsSize != 0))) {
		ALOGE("Map is missing method_ids entry");
		return false;
	}

	if (((usedBits & mapTypeToBitMask(kDexTypeClassDefItem)) == 0)
		&& ((state->pHeader->classDefsOff != 0)
			|| (state->pHeader->classDefsSize != 0))) {
		ALOGE("Map is missing class_defs entry");
		return false;
	}

	state->pDataMap = dexDataMapAlloc(dataItemCount);
	if (state->pDataMap == NULL) {
		ALOGE("Unable to allocate data map (size %#x)", dataItemCount);
		return false;
	}

	return true;
}

int dexSwapAndVerify(u1* addr, int len) {
	int result = 0;

	DexHeader* pHeader;
	CheckState state;
	bool okay = true;

	memset(&state, 0, sizeof(state));
	ALOGV("+++ swapping and verifying");

	pHeader = (DexHeader*)addr;

	if (!dexHasValidMagic(pHeader)) {
		okay = false;
	}

	if (okay) {
		int expectedLen = (int)SWAP4(pHeader->fileSize);
		if (len < expectedLen) {
			ALOGE("ERROR: Bad length: expected %d, got %d", expectedLen, len);
			okay = false;
		}
		else if (len != expectedLen) {
			ALOGW("WARNING: Odd length: expected %d, got %d", expectedLen,
				len);
			// keep going
		}
	}

	if (okay) {
		/*
		* Compute the adler32 checksum and compare it to what's stored in
		* the file.  This isn't free, but chances are good that we just
		* unpacked this from a jar file and have all of the pages sitting
		* in memory, so it's pretty quick.
		*
		* This might be a big-endian system, so we need to do this before
		* we byte-swap the header.
		*/
		uLong adler = adler32(0, NULL, 0);
		const int nonSum = sizeof(pHeader->magic) + sizeof(pHeader->checksum);
		u4 storedFileSize = SWAP4(pHeader->fileSize);
		u4 expectedChecksum = SWAP4(pHeader->checksum);

		adler = adler32(adler, ((const u1*)pHeader) + nonSum,
			storedFileSize - nonSum);
		/*
		if (adler != expectedChecksum) {
			ALOGE("ERROR: bad checksum (%08lx, expected %08x)",
				adler, expectedChecksum);
			okay = false;
		}*/
	}
	size_t xx = sizeof(DexMapList);

	if (okay) {
		state.fileStart = addr;
		state.fileEnd = addr + len;
		state.fileLen = len;
		state.pDexFile = NULL;
		state.pDataMap = NULL;
		state.pDefinedClassBits = NULL;
		state.previousItem = NULL;
		okay = swapDexHeader(&state, pHeader);
	}

	if (okay) {
		state.pHeader = pHeader;

		if (pHeader->headerSize < sizeof(DexHeader)) {
			ALOGE("ERROR: Small header size %d, struct %d",
				pHeader->headerSize, (int) sizeof(DexHeader));
			okay = false;
		}
		else if (pHeader->headerSize > sizeof(DexHeader)) {
			ALOGW("WARNING: Large header size %d, struct %d",
				pHeader->headerSize, (int) sizeof(DexHeader));
			// keep going?
		}
	}

	if (okay) {
		/*
		* Look for the map. Swap it and then use it to find and swap
		* everything else.
		*/
		if (pHeader->mapOff != 0) {
			DexFile dexFile;
			DexMapList* pDexMap = (DexMapList*)(addr + pHeader->mapOff);
			okay = okay && swapMap(&state, pDexMap);
			//  okay = okay && swapEverythingButHeaderAndMap(&state, pDexMap);
			dexFileSetupBasicPointers(&dexFile, addr);
			state.pDexFile = &dexFile;

			//okay = okay && crossVerifyEverything(&state, pDexMap);
		}
		else {
			ALOGE("ERROR: No map found; impossible to byte-swap and verify");
			okay = false;
		}
	}
	if (!okay) {
		ALOGE("ERROR: Byte swap + verify failed");
	}

	if (state.pDataMap != NULL) {
		dexDataMapFree(state.pDataMap);
	}

	return !okay;
}

int dexSwapAndVerifyIfNecessary(u1* addr, int len)
{
	if (memcmp(addr, DEX_OPT_MAGIC, 4) == 0) {
		// It is an optimized dex file.
		return 0;
	}

	if (memcmp(addr, DEX_MAGIC, 4) == 0) {
		// It is an unoptimized dex file.
		return dexSwapAndVerify(addr, len);
	}

	ALOGE("ERROR: Bad magic number (0x%02x %02x %02x %02x)",
		addr[0], addr[1], addr[2], addr[3]);

	return 1;
}

int dexOpenAndMap(const char* fileName,
	MemMapping* pMap, bool quiet) {

	int retsult = -1;

	HANDLE hFile = ::CreateFile(fileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile) {
		goto bail;
	}

	HANDLE hFileMapping = ::CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (NULL == hFileMapping) {
		CloseHandle(hFile);
		goto bail;
	}

	LPVOID lpFileContentBuf = ::MapViewOfFile(hFileMapping, FILE_MAP_COPY, 0, 0, 0);
	if (NULL == lpFileContentBuf) {
		CloseHandle(hFile);
		CloseHandle(hFileMapping);
		goto bail;
	}

	pMap->baseAddr = pMap->addr = lpFileContentBuf;
	pMap->baseLength = pMap->length = GetFileSize(hFile, NULL);
	CloseHandle(hFile);

	if (dexSwapAndVerifyIfNecessary((u1*)pMap->addr, pMap->length)) {
		CloseHandle(hFile);
		CloseHandle(hFileMapping);
		goto bail;
	}

	retsult = 0;
bail:
	return retsult;
}
void sysReleaseShmem(MemMapping* pMap) {

}

enum AccessFor {
	kAccessForClass = 0, kAccessForMethod = 1, kAccessForField = 2,
	kAccessForMAX
};

/*
* Dump the contents of the register map area.
*
* These are only present in optimized DEX files, and the structure is
* not really exposed to other parts of the VM itself.  We're going to
* dig through them here, but this is pretty fragile.  DO NOT rely on
* this or derive other code from it.
*/
void dumpRegisterMaps(DexFile* pDexFile)
{
	const u1* pClassPool = (const u1*)pDexFile->pRegisterMapPool;
	const u4* classOffsets;
	const u1* ptr;
	u4 numClasses;
	int baseFileOffset = (u1*)pClassPool - (u1*)pDexFile->pOptHeader;
	int idx;

	if (pClassPool == NULL) {
		printf("No register maps found\n");
		return;
	}
	
	/*ptr = pClassPool;
	numClasses = get4LE(ptr);
	ptr += sizeof(u4);
	classOffsets = (const u4*)ptr;

	printf("RMAP begins at offset 0x%07x\n", baseFileOffset);
	printf("Maps for %d classes\n", numClasses);
	for (idx = 0; idx < (int)numClasses; idx++) {
		const DexClassDef* pClassDef;
		const char* classDescriptor;

		pClassDef = dexGetClassDef(pDexFile, idx);
		classDescriptor = dexStringByTypeIdx(pDexFile, pClassDef->classIdx);

		printf("%4d: +%d (0x%08x) %s\n", idx, classOffsets[idx],
			baseFileOffset + classOffsets[idx], classDescriptor);

		if (classOffsets[idx] == 0)
			continue;*/

		/*
		* What follows is a series of RegisterMap entries, one for every
		* direct method, then one for every virtual method.
		*/
	//	DexClassData* pClassData;
	//	const u1* pEncodedData;
	//	const u1* data = (u1*)pClassPool + classOffsets[idx];
	//	u2 methodCount;
	//	int i;

	//	pEncodedData = dexGetClassData(pDexFile, pClassDef);
	//	pClassData = dexReadAndVerifyClassData(&pEncodedData, NULL);
	//	if (pClassData == NULL) {
	//		fprintf(stderr, "Trouble reading class data\n");
	//		continue;
	//	}

	//	methodCount = *data++;
	//	methodCount |= (*data++) << 8;
	//	data += 2;      /* two pad bytes follow methodCount */
	//	if (methodCount != pClassData->header.directMethodsSize
	//		+ pClassData->header.virtualMethodsSize)
	//	{
	//		printf("NOTE: method count discrepancy (%d != %d + %d)\n",
	//			methodCount, pClassData->header.directMethodsSize,
	//			pClassData->header.virtualMethodsSize);
	//		/* this is bad, but keep going anyway */
	//	}

	//	printf("    direct methods: %d\n",
	//		pClassData->header.directMethodsSize);
	//	for (i = 0; i < (int)pClassData->header.directMethodsSize; i++) {
	//		dumpMethodMap(pDexFile, &pClassData->directMethods[i], i, &data);
	//	}

	//	printf("    virtual methods: %d\n",
	//		pClassData->header.virtualMethodsSize);
	//	for (i = 0; i < (int)pClassData->header.virtualMethodsSize; i++) {
	//		dumpMethodMap(pDexFile, &pClassData->virtualMethods[i], i, &data);
	//	}

	//	free(pClassData);
	//}
}

static int countOnes(u4 val)
{
	int count = 0;

	val = val - ((val >> 1) & 0x55555555);
	val = (val & 0x33333333) + ((val >> 2) & 0x33333333);
	count = (((val + (val >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;

	return count;
}

static char* createAccessFlagStr(u4 flags, AccessFor forWhat)
{
#define NUM_FLAGS   18
	static const char* kAccessStrings[kAccessForMAX][NUM_FLAGS] = {
		{
			/* class, inner class */
			"PUBLIC",           /* 0x0001 */
			"PRIVATE",          /* 0x0002 */
		"PROTECTED",        /* 0x0004 */
		"STATIC",           /* 0x0008 */
		"FINAL",            /* 0x0010 */
		"?",                /* 0x0020 */
		"?",                /* 0x0040 */
		"?",                /* 0x0080 */
		"?",                /* 0x0100 */
		"INTERFACE",        /* 0x0200 */
		"ABSTRACT",         /* 0x0400 */
		"?",                /* 0x0800 */
		"SYNTHETIC",        /* 0x1000 */
		"ANNOTATION",       /* 0x2000 */
		"ENUM",             /* 0x4000 */
		"?",                /* 0x8000 */
		"VERIFIED",         /* 0x10000 */
		"OPTIMIZED",        /* 0x20000 */
		},
		{
			/* method */
			"PUBLIC",           /* 0x0001 */
			"PRIVATE",          /* 0x0002 */
		"PROTECTED",        /* 0x0004 */
		"STATIC",           /* 0x0008 */
		"FINAL",            /* 0x0010 */
		"SYNCHRONIZED",     /* 0x0020 */
		"BRIDGE",           /* 0x0040 */
		"VARARGS",          /* 0x0080 */
		"NATIVE",           /* 0x0100 */
		"?",                /* 0x0200 */
		"ABSTRACT",         /* 0x0400 */
		"STRICT",           /* 0x0800 */
		"SYNTHETIC",        /* 0x1000 */
		"?",                /* 0x2000 */
		"?",                /* 0x4000 */
		"MIRANDA",          /* 0x8000 */
		"CONSTRUCTOR",      /* 0x10000 */
		"DECLARED_SYNCHRONIZED", /* 0x20000 */
		},
		{
			/* field */
			"PUBLIC",           /* 0x0001 */
			"PRIVATE",          /* 0x0002 */
		"PROTECTED",        /* 0x0004 */
		"STATIC",           /* 0x0008 */
		"FINAL",            /* 0x0010 */
		"?",                /* 0x0020 */
		"VOLATILE",         /* 0x0040 */
		"TRANSIENT",        /* 0x0080 */
		"?",                /* 0x0100 */
		"?",                /* 0x0200 */
		"?",                /* 0x0400 */
		"?",                /* 0x0800 */
		"SYNTHETIC",        /* 0x1000 */
		"?",                /* 0x2000 */
		"ENUM",             /* 0x4000 */
		"?",                /* 0x8000 */
		"?",                /* 0x10000 */
		"?",                /* 0x20000 */
		},
	};
	const int kLongest = 21;        /* strlen of longest string above */
	int i, count;
	char* str;
	char* cp;

	/*
	* Allocate enough storage to hold the expected number of strings,
	* plus a space between each.  We over-allocate, using the longest
	* string above as the base metric.
	*/
	count = countOnes(flags);
	cp = str = (char*)malloc(count * (kLongest + 1) + 1);

	for (i = 0; i < NUM_FLAGS; i++) {
		if (flags & 0x01) {
			const char* accessStr = kAccessStrings[forWhat][i];
			int len = strlen(accessStr);
			if (cp != str)
				*cp++ = ' ';

			memcpy(cp, accessStr, len);
			cp += len;
		}
		flags >>= 1;
	}
	*cp = '\0';

	return str;
}

static void asciify(char* out, const unsigned char* data, size_t len)
{
	while (len--) {
		if (*data < 0x20) {
			/* could do more here, but we don't need them yet */
			switch (*data) {
			case '\0':
				*out++ = '\\';
				*out++ = '0';
				break;
			case '\n':
				*out++ = '\\';
				*out++ = 'n';
				break;
			default:
				*out++ = '.';
				break;
			}
		}
		else if (*data >= 0x80) {
			*out++ = '?';
		}
		else {
			*out++ = *data;
		}
		data++;
	}
	*out = '\0';
}

void dumpFileHeader(const DexFile* pDexFile)
{
	const DexOptHeader* pOptHeader = pDexFile->pOptHeader;
	const DexHeader* pHeader = pDexFile->pHeader;
	char sanitized[sizeof(pHeader->magic) * 2 + 1];

	assert(sizeof(pHeader->magic) == sizeof(pOptHeader->magic));

	if (pOptHeader != NULL) {
		printf("Optimized DEX file header:\n");

		asciify(sanitized, pOptHeader->magic, sizeof(pOptHeader->magic));
		printf("magic               : '%s'\n", sanitized);
		printf("dex_offset          : %d (0x%06x)\n",
			pOptHeader->dexOffset, pOptHeader->dexOffset);
		printf("dex_length          : %d\n", pOptHeader->dexLength);
		printf("deps_offset         : %d (0x%06x)\n",
			pOptHeader->depsOffset, pOptHeader->depsOffset);
		printf("deps_length         : %d\n", pOptHeader->depsLength);
		printf("opt_offset          : %d (0x%06x)\n",
			pOptHeader->optOffset, pOptHeader->optOffset);
		printf("opt_length          : %d\n", pOptHeader->optLength);
		printf("flags               : %08x\n", pOptHeader->flags);
		printf("checksum            : %08x\n", pOptHeader->checksum);
		printf("\n");
	}

	printf("DEX file header:\n");
	asciify(sanitized, pHeader->magic, sizeof(pHeader->magic));
	printf("magic               : '%s'\n", sanitized);
	printf("checksum            : %08x\n", pHeader->checksum);
	printf("signature           : %02x%02x...%02x%02x\n",
		pHeader->signature[0], pHeader->signature[1],
		pHeader->signature[kSHA1DigestLen - 2],
		pHeader->signature[kSHA1DigestLen - 1]);
	printf("file_size           : %d\n", pHeader->fileSize);
	printf("header_size         : %d\n", pHeader->headerSize);
	printf("link_size           : %d\n", pHeader->linkSize);
	printf("link_off            : %d (0x%06x)\n",
		pHeader->linkOff, pHeader->linkOff);
	printf("string_ids_size     : %d\n", pHeader->stringIdsSize);
	printf("string_ids_off      : %d (0x%06x)\n",
		pHeader->stringIdsOff, pHeader->stringIdsOff);
	printf("type_ids_size       : %d\n", pHeader->typeIdsSize);
	printf("type_ids_off        : %d (0x%06x)\n",
		pHeader->typeIdsOff, pHeader->typeIdsOff);
	printf("proto_ids_size       : %d\n", pHeader->protoIdsSize);
	printf("proto_ids_off        : %d (0x%06x)\n",
		pHeader->protoIdsOff, pHeader->protoIdsOff);
	printf("field_ids_size      : %d\n", pHeader->fieldIdsSize);
	printf("field_ids_off       : %d (0x%06x)\n",
		pHeader->fieldIdsOff, pHeader->fieldIdsOff);
	printf("method_ids_size     : %d\n", pHeader->methodIdsSize);
	printf("method_ids_off      : %d (0x%06x)\n",
		pHeader->methodIdsOff, pHeader->methodIdsOff);
	printf("class_defs_size     : %d\n", pHeader->classDefsSize);
	printf("class_defs_off      : %d (0x%06x)\n",
		pHeader->classDefsOff, pHeader->classDefsOff);
	printf("data_size           : %d\n", pHeader->dataSize);
	printf("data_off            : %d (0x%06x)\n",
		pHeader->dataOff, pHeader->dataOff);
	printf("\n");
}
void dumpOptDirectory(const DexFile* pDexFile) {
	// TODO later implement.
}

void dumpClassDef(DexFile* pDexFile, int idx)
{
	const DexClassDef* pClassDef;
	const u1* pEncodedData;
	DexClassData* pClassData;

	pClassDef = dexGetClassDef(pDexFile, idx);
	pEncodedData = dexGetClassData(pDexFile, pClassDef);
	pClassData = dexReadAndVerifyClassData(&pEncodedData, NULL);
	if (pClassData == NULL) {
		fprintf(stderr, "Trouble reading class data\n");
		return;
	}
	printf("Class #%d header:\n", idx);
	printf("class_idx           : %d\n", pClassDef->classIdx);
	printf("access_flags        : %d (0x%04x)\n",
		pClassDef->accessFlags, pClassDef->accessFlags);
	printf("superclass_idx      : %d\n", pClassDef->superclassIdx);
	printf("interfaces_off      : %d (0x%06x)\n",
		pClassDef->interfacesOff, pClassDef->interfacesOff);
	printf("source_file_idx     : %d\n", pClassDef->sourceFileIdx);
	printf("annotations_off     : %d (0x%06x)\n",
		pClassDef->annotationsOff, pClassDef->annotationsOff);
	printf("class_data_off      : %d (0x%06x)\n",
		pClassDef->classDataOff, pClassDef->classDataOff);
	printf("static_fields_size  : %d\n", pClassData->header.staticFieldsSize);
	printf("instance_fields_size: %d\n",
		pClassData->header.instanceFieldsSize);
	printf("direct_methods_size : %d\n", pClassData->header.directMethodsSize);
	printf("virtual_methods_size: %d\n",
		pClassData->header.virtualMethodsSize);
	printf("\n");

	free(pClassData);
}

void dumpInterface(const DexFile* pDexFile, const DexTypeItem* pTypeItem,
	int i)
{
	const char* interfaceName =
		dexStringByTypeIdx(pDexFile, pTypeItem->typeIdx);
	printf("    #%d              : '%s'\n", i, interfaceName);
}
void dumpSField(const DexFile* pDexFile, const DexField* pSField, int i)
{
	const DexFieldId* pFieldId;
	const char* backDescriptor;
	const char* name;
	const char* typeDescriptor;
	char* accessStr;

	pFieldId = dexGetFieldId(pDexFile, pSField->fieldIdx);
	name = dexStringById(pDexFile, pFieldId->nameIdx);
	typeDescriptor = dexStringByTypeIdx(pDexFile, pFieldId->typeIdx);
	backDescriptor = dexStringByTypeIdx(pDexFile, pFieldId->classIdx);

	accessStr = createAccessFlagStr(pSField->accessFlags, kAccessForField);
	printf("    #%d              : (in %s)\n", i, backDescriptor);
	printf("      name          : '%s'\n", name);
	printf("      type          : '%s'\n", typeDescriptor);
	printf("      access        : 0x%04x (%s)\n",
		pSField->accessFlags, accessStr);
	free(accessStr);
}
void dumpIField(const DexFile* pDexFile, const DexField* pIField, int i)
{
	dumpSField(pDexFile, pIField, i);
}


struct FieldMethodInfo {
	const char* classDescriptor;
	const char* name;
	const char* signature;
};

bool getMethodInfo(DexFile* pDexFile, u4 methodIdx, FieldMethodInfo* pMethInfo)
{
	const DexMethodId* pMethodId;

	if (methodIdx >= pDexFile->pHeader->methodIdsSize)
		return false;

	pMethodId = dexGetMethodId(pDexFile, methodIdx);
	pMethInfo->name = dexStringById(pDexFile, pMethodId->nameIdx);
	pMethInfo->signature = dexCopyDescriptorFromMethodId(pDexFile, pMethodId);

	pMethInfo->classDescriptor =
		dexStringByTypeIdx(pDexFile, pMethodId->classIdx);
	return true;
}

static const char* primitiveTypeLabel(char typeChar)
{
	switch (typeChar) {
	case 'B':   return "byte";
	case 'C':   return "char";
	case 'D':   return "double";
	case 'F':   return "float";
	case 'I':   return "int";
	case 'J':   return "long";
	case 'S':   return "short";
	case 'V':   return "void";
	case 'Z':   return "boolean";
	default:
		return "UNKNOWN";
	}
}

static inline u2 get2LE(unsigned char const* pSrc)
{
	return pSrc[0] | (pSrc[1] << 8);
}

/*
* Get 4 little-endian bytes.
*/
static inline u4 get4LE(unsigned char const* pSrc)
{
	return pSrc[0] | (pSrc[1] << 8) | (pSrc[2] << 16) | (pSrc[3] << 24);
}

static char* descriptorToDot(const char* str)
{
	int targetLen = strlen(str);
	int offset = 0;
	int arrayDepth = 0;
	char* newStr;

	/* strip leading [s; will be added to end */
	while (targetLen > 1 && str[offset] == '[') {
		offset++;
		targetLen--;
	}
	arrayDepth = offset;

	if (targetLen == 1) {
		/* primitive type */
		str = primitiveTypeLabel(str[offset]);
		offset = 0;
		targetLen = strlen(str);
	}
	else {
		/* account for leading 'L' and trailing ';' */
		if (targetLen >= 2 && str[offset] == 'L' &&
			str[offset + targetLen - 1] == ';')
		{
			targetLen -= 2;
			offset++;
		}
	}

	newStr = (char*)malloc(targetLen + arrayDepth * 2 + 1);

	/* copy class name over */
	int i;
	for (i = 0; i < targetLen; i++) {
		char ch = str[offset + i];
		newStr[i] = (ch == '/' || ch == '$') ? '.' : ch;
	}

	/* add the appropriate number of brackets for arrays */
	while (arrayDepth-- > 0) {
		newStr[i++] = '[';
		newStr[i++] = ']';
	}
	newStr[i] = '\0';
	//assert(i == targetLen + arrayDepth * 2);

	return newStr;
}

bool getFieldInfo(DexFile* pDexFile, u4 fieldIdx, FieldMethodInfo* pFieldInfo)
{
	const DexFieldId* pFieldId;

	if (fieldIdx >= pDexFile->pHeader->fieldIdsSize)
		return false;

	pFieldId = dexGetFieldId(pDexFile, fieldIdx);
	pFieldInfo->name = dexStringById(pDexFile, pFieldId->nameIdx);
	pFieldInfo->signature = dexStringByTypeIdx(pDexFile, pFieldId->typeIdx);
	pFieldInfo->classDescriptor =
		dexStringByTypeIdx(pDexFile, pFieldId->classIdx);
	return true;
}
const char* getClassDescriptor(DexFile* pDexFile, u4 classIdx)
{
	return dexStringByTypeIdx(pDexFile, classIdx);
}

static char* indexString(DexFile* pDexFile,
	const DecodedInstruction* pDecInsn, char* buf, size_t bufSize)
{
	int outSize;
	u4 index;
	u4 width;

	/* TODO: Make the index *always* be in field B, to simplify this code. */
	switch (dexGetFormatFromOpcode(pDecInsn->opcode)) {
	case kFmt20bc:
	case kFmt21c:
	case kFmt35c:
	case kFmt35ms:
	case kFmt3rc:
	case kFmt3rms:
	case kFmt35mi:
	case kFmt3rmi:
		index = pDecInsn->vB;
		width = 4;
		break;
	case kFmt31c:
		index = pDecInsn->vB;
		width = 8;
		break;
	case kFmt22c:
	case kFmt22cs:
		index = pDecInsn->vC;
		width = 4;
		break;
	default:
		index = 0;
		width = 4;
		break;
	}

	switch (pDecInsn->indexType) {
	case kIndexUnknown:
		/*
		* This function shouldn't ever get called for this type, but do
		* something sensible here, just to help with debugging.
		*/
		outSize = snprintf(buf, bufSize, "<unknown-index>");
		break;
	case kIndexNone:
		/*
		* This function shouldn't ever get called for this type, but do
		* something sensible here, just to help with debugging.
		*/
		outSize = snprintf(buf, bufSize, "<no-index>");
		break;
	case kIndexVaries:
		/*
		* This one should never show up in a dexdump, so no need to try
		* to get fancy here.
		*/
		outSize = snprintf(buf, bufSize, "<index-varies> // thing@%0*x",
			width, index);
		break;
	case kIndexTypeRef:
		if (index < pDexFile->pHeader->typeIdsSize) {
			outSize = snprintf(buf, bufSize, "%s // type@%0*x",
				getClassDescriptor(pDexFile, index), width, index);
		}
		else {
			outSize = snprintf(buf, bufSize, "<type?> // type@%0*x", width, index);
		}
		break;
	case kIndexStringRef:
		if (index < pDexFile->pHeader->stringIdsSize) {
			outSize = snprintf(buf, bufSize, "\"%s\" // string@%0*x",
				dexStringById(pDexFile, index), width, index);
		}
		else {
			outSize = snprintf(buf, bufSize, "<string?> // string@%0*x",
				width, index);
		}
		break;
	case kIndexMethodRef:
	{
		FieldMethodInfo methInfo;
		if (getMethodInfo(pDexFile, index, &methInfo)) {
			outSize = snprintf(buf, bufSize, "%s.%s:%s // method@%0*x",
				methInfo.classDescriptor, methInfo.name,
				methInfo.signature, width, index);
			free((void *)methInfo.signature);
		}
		else {
			outSize = snprintf(buf, bufSize, "<method?> // method@%0*x",
				width, index);
		}
	}
	break;
	case kIndexFieldRef:
	{
		FieldMethodInfo fieldInfo;
		if (getFieldInfo(pDexFile, index, &fieldInfo)) {
			outSize = snprintf(buf, bufSize, "%s.%s:%s // field@%0*x",
				fieldInfo.classDescriptor, fieldInfo.name,
				fieldInfo.signature, width, index);
		}
		else {
			outSize = snprintf(buf, bufSize, "<field?> // field@%0*x",
				width, index);
		}
	}
	break;
	case kIndexInlineMethod:
		outSize = snprintf(buf, bufSize, "[%0*x] // inline #%0*x",
			width, index, width, index);
		break;
	case kIndexVtableOffset:
		outSize = snprintf(buf, bufSize, "[%0*x] // vtable #%0*x",
			width, index, width, index);
		break;
	case kIndexFieldOffset:
		outSize = snprintf(buf, bufSize, "[obj+%0*x]", width, index);
		break;
	default:
		outSize = snprintf(buf, bufSize, "<?>");
		break;
	}

	if (outSize >= (int)bufSize) {
		/*
		* The buffer wasn't big enough; allocate and retry. Note:
		* snprintf() doesn't count the '\0' as part of its returned
		* size, so we add explicit space for it here.
		*/
		outSize++;
		buf = (char*)malloc(outSize);
		if (buf == NULL) {
			return NULL;
		}
		return indexString(pDexFile, pDecInsn, buf, outSize);
	}
	else {
		return buf;
	}
}

void dumpInstruction(DexFile* pDexFile, const DexCode* pCode, int insnIdx,
	int insnWidth, const DecodedInstruction* pDecInsn)
{
	char indexBufChars[200];
	char *indexBuf = indexBufChars;
	const u2* insns = pCode->insns;
	int i;

	printf("%06x:", ((u1*)insns - pDexFile->baseAddr) + insnIdx * 2);
	for (i = 0; i < 8; i++) {
		if (i < insnWidth) {
			if (i == 7) {
				printf(" ... ");
			}
			else {
				/* print 16-bit value in little-endian order */
				const u1* bytePtr = (const u1*)&insns[insnIdx + i];
				printf(" %02x%02x", bytePtr[0], bytePtr[1]);
			}
		}
		else {
			fputs("     ", stdout);
		}
	}

	if (pDecInsn->opcode == OP_NOP) {
		u2 instr = get2LE((const u1*)&insns[insnIdx]);
		if (instr == kPackedSwitchSignature) {
			printf("|%04x: packed-switch-data (%d units)",
				insnIdx, insnWidth);
		}
		else if (instr == kSparseSwitchSignature) {
			printf("|%04x: sparse-switch-data (%d units)",
				insnIdx, insnWidth);
		}
		else if (instr == kArrayDataSignature) {
			printf("|%04x: array-data (%d units)",
				insnIdx, insnWidth);
		}
		else {
			printf("|%04x: nop // spacer", insnIdx);
		}
	}
	else {
		printf("|%04x: %s", insnIdx, dexGetOpcodeName(pDecInsn->opcode));
	}

	if (pDecInsn->indexType != kIndexNone) {
		indexBuf = indexString(pDexFile, pDecInsn,
			indexBufChars, sizeof(indexBufChars));
	}

	switch (dexGetFormatFromOpcode(pDecInsn->opcode)) {
	case kFmt10x:        // op
		break;
	case kFmt12x:        // op vA, vB
		printf(" v%d, v%d", pDecInsn->vA, pDecInsn->vB);
		break;
	case kFmt11n:        // op vA, #+B
		printf(" v%d, #int %d // #%x",
			pDecInsn->vA, (s4)pDecInsn->vB, (u1)pDecInsn->vB);
		break;
	case kFmt11x:        // op vAA
		printf(" v%d", pDecInsn->vA);
		break;
	case kFmt10t:        // op +AA
	case kFmt20t:        // op +AAAA
	{
		s4 targ = (s4)pDecInsn->vA;
		printf(" %04x // %c%04x",
			insnIdx + targ,
			(targ < 0) ? '-' : '+',
			(targ < 0) ? -targ : targ);
	}
	break;
	case kFmt22x:        // op vAA, vBBBB
		printf(" v%d, v%d", pDecInsn->vA, pDecInsn->vB);
		break;
	case kFmt21t:        // op vAA, +BBBB
	{
		s4 targ = (s4)pDecInsn->vB;
		printf(" v%d, %04x // %c%04x", pDecInsn->vA,
			insnIdx + targ,
			(targ < 0) ? '-' : '+',
			(targ < 0) ? -targ : targ);
	}
	break;
	case kFmt21s:        // op vAA, #+BBBB
		printf(" v%d, #int %d // #%x",
			pDecInsn->vA, (s4)pDecInsn->vB, (u2)pDecInsn->vB);
		break;
	case kFmt21h:        // op vAA, #+BBBB0000[00000000]
						 // The printed format varies a bit based on the actual opcode.
		if (pDecInsn->opcode == OP_CONST_HIGH16) {
			s4 value = pDecInsn->vB << 16;
			printf(" v%d, #int %d // #%x",
				pDecInsn->vA, value, (u2)pDecInsn->vB);
		}
		else {
			s8 value = ((s8)pDecInsn->vB) << 48;
			printf(" v%d, #long %lld // #%x",
				pDecInsn->vA, value, (u2)pDecInsn->vB);
		}
		break;
	case kFmt21c:        // op vAA, thing@BBBB
	case kFmt31c:        // op vAA, thing@BBBBBBBB
		printf(" v%d, %s", pDecInsn->vA, indexBuf);
		break;
	case kFmt23x:        // op vAA, vBB, vCC
		printf(" v%d, v%d, v%d", pDecInsn->vA, pDecInsn->vB, pDecInsn->vC);
		break;
	case kFmt22b:        // op vAA, vBB, #+CC
		printf(" v%d, v%d, #int %d // #%02x",
			pDecInsn->vA, pDecInsn->vB, (s4)pDecInsn->vC, (u1)pDecInsn->vC);
		break;
	case kFmt22t:        // op vA, vB, +CCCC
	{
		s4 targ = (s4)pDecInsn->vC;
		printf(" v%d, v%d, %04x // %c%04x", pDecInsn->vA, pDecInsn->vB,
			insnIdx + targ,
			(targ < 0) ? '-' : '+',
			(targ < 0) ? -targ : targ);
	}
	break;
	case kFmt22s:        // op vA, vB, #+CCCC
		printf(" v%d, v%d, #int %d // #%04x",
			pDecInsn->vA, pDecInsn->vB, (s4)pDecInsn->vC, (u2)pDecInsn->vC);
		break;
	case kFmt22c:        // op vA, vB, thing@CCCC
	case kFmt22cs:       // [opt] op vA, vB, field offset CCCC
		printf(" v%d, v%d, %s", pDecInsn->vA, pDecInsn->vB, indexBuf);
		break;
	case kFmt30t:
		printf(" #%08x", pDecInsn->vA);
		break;
	case kFmt31i:        // op vAA, #+BBBBBBBB
	{
		/* this is often, but not always, a float */
		union {
			float f;
			u4 i;
		} conv;
		conv.i = pDecInsn->vB;
		printf(" v%d, #float %f // #%08x",
			pDecInsn->vA, conv.f, pDecInsn->vB);
	}
	break;
	case kFmt31t:       // op vAA, offset +BBBBBBBB
		printf(" v%d, %08x // +%08x",
			pDecInsn->vA, insnIdx + pDecInsn->vB, pDecInsn->vB);
		break;
	case kFmt32x:        // op vAAAA, vBBBB
		printf(" v%d, v%d", pDecInsn->vA, pDecInsn->vB);
		break;
	case kFmt35c:        // op {vC, vD, vE, vF, vG}, thing@BBBB
	case kFmt35ms:       // [opt] invoke-virtual+super
	case kFmt35mi:       // [opt] inline invoke
	{
		fputs(" {", stdout);
		for (i = 0; i < (int)pDecInsn->vA; i++) {
			if (i == 0)
				printf("v%d", pDecInsn->arg[i]);
			else
				printf(", v%d", pDecInsn->arg[i]);
		}
		printf("}, %s", indexBuf);
	}
	break;
	case kFmt3rc:        // op {vCCCC .. v(CCCC+AA-1)}, thing@BBBB
	case kFmt3rms:       // [opt] invoke-virtual+super/range
	case kFmt3rmi:       // [opt] execute-inline/range
	{
		/*
		* This doesn't match the "dx" output when some of the args are
		* 64-bit values -- dx only shows the first register.
		*/
		fputs(" {", stdout);
		for (i = 0; i < (int)pDecInsn->vA; i++) {
			if (i == 0)
				printf("v%d", pDecInsn->vC + i);
			else
				printf(", v%d", pDecInsn->vC + i);
		}
		printf("}, %s", indexBuf);
	}
	break;
	case kFmt51l:        // op vAA, #+BBBBBBBBBBBBBBBB
	{
		/* this is often, but not always, a double */
		union {
			double d;
			u8 j;
		} conv;
		conv.j = pDecInsn->vB_wide;
		printf(" v%d, #double %f // #%016llx",
			pDecInsn->vA, conv.d, pDecInsn->vB_wide);
	}
	break;
	case kFmt00x:        // unknown op or breakpoint
		break;
	default:
		printf(" ???");
		break;
	}

	putchar('\n');

	if (indexBuf != indexBufChars) {
		free(indexBuf);
	}
}

void dumpBytecodes(DexFile* pDexFile, const DexMethod* pDexMethod)
{
	const DexCode* pCode = dexGetCode(pDexFile, pDexMethod);
	const u2* insns;
	int insnIdx;
	FieldMethodInfo methInfo;
	int startAddr;
	char* className = NULL;

	assert(pCode->insnsSize > 0);
	insns = pCode->insns;

	getMethodInfo(pDexFile, pDexMethod->methodIdx, &methInfo);
	startAddr = ((u1*)pCode - pDexFile->baseAddr);
	className = descriptorToDot(methInfo.classDescriptor);

	printf("%06x:                                        |[%06x] %s.%s:%s\n",
		startAddr, startAddr,
		className, methInfo.name, methInfo.signature);
	free((void *)methInfo.signature);

	insnIdx = 0;
	while (insnIdx < (int)pCode->insnsSize) {
		int insnWidth;
		DecodedInstruction decInsn;
		u2 instr;

		/*
		* Note: This code parallels the function
		* dexGetWidthFromInstruction() in InstrUtils.c, but this version
		* can deal with data in either endianness.
		*
		* TODO: Figure out if this really matters, and possibly change
		* this to just use dexGetWidthFromInstruction().
		*/
		instr = get2LE((const u1*)insns);
		if (instr == kPackedSwitchSignature) {
			insnWidth = 4 + get2LE((const u1*)(insns + 1)) * 2;
		}
		else if (instr == kSparseSwitchSignature) {
			insnWidth = 2 + get2LE((const u1*)(insns + 1)) * 4;
		}
		else if (instr == kArrayDataSignature) {
			int width = get2LE((const u1*)(insns + 1));
			int size = get2LE((const u1*)(insns + 2)) |
				(get2LE((const u1*)(insns + 3)) << 16);
			// The plus 1 is to round up for odd size and width.
			insnWidth = 4 + ((size * width) + 1) / 2;
		}
		else {
			Opcode opcode = dexOpcodeFromCodeUnit(instr);
			insnWidth = dexGetWidthFromOpcode(opcode);
			if (insnWidth == 0) {
				fprintf(stderr,
					"GLITCH: zero-width instruction at idx=0x%04x\n", insnIdx);
				break;
			}
		}

		dexDecodeInstruction(insns, &decInsn);
		dumpInstruction(pDexFile, pCode, insnIdx, insnWidth, &decInsn);

		insns += insnWidth;
		insnIdx += insnWidth;
	}

	free(className);
}

void dumpCode(DexFile* pDexFile, const DexMethod* pDexMethod)
{
	const DexCode* pCode = dexGetCode(pDexFile, pDexMethod);

	printf("      registers     : %d\n", pCode->registersSize);
	printf("      ins           : %d\n", pCode->insSize);
	printf("      outs          : %d\n", pCode->outsSize);
	printf("      insns size    : %d 16-bit code units\n", pCode->insnsSize);
	dumpBytecodes(pDexFile, pDexMethod);

	//dumpCatches(pDexFile, pCode);
	/* both of these are encoded in debug info */
	//dumpPositions(pDexFile, pCode, pDexMethod);
	//dumpLocals(pDexFile, pCode, pDexMethod);
}

void dumpMethod(DexFile* pDexFile, const DexMethod* pDexMethod, int i)
{
	const DexMethodId* pMethodId;
	const char* backDescriptor;
	const char* name;
	char* typeDescriptor = NULL;
	char* accessStr = NULL;
	
	pMethodId = dexGetMethodId(pDexFile, pDexMethod->methodIdx);
	name = dexStringById(pDexFile, pMethodId->nameIdx);
	typeDescriptor = dexCopyDescriptorFromMethodId(pDexFile, pMethodId);

	backDescriptor = dexStringByTypeIdx(pDexFile, pMethodId->classIdx);

	accessStr = createAccessFlagStr(pDexMethod->accessFlags,
		kAccessForMethod);

	printf("    #%d              : (in %s)\n", i, backDescriptor);
	printf("      name          : '%s'\n", name);
	printf("      type          : '%s'\n", typeDescriptor);
	printf("      access        : 0x%04x (%s)\n",
		pDexMethod->accessFlags, accessStr);

	if (pDexMethod->codeOff == 0) {
		printf("      code          : (none)\n");
	}
	else {
		printf("      code          -\n");
		dumpCode(pDexFile, pDexMethod);
	}
	putchar('\n');

	free(typeDescriptor);
	free(accessStr);
}

void dumpClass(DexFile* pDexFile, int idx, char** pLastPackage)
{
	const DexTypeList* pInterfaces;
	const DexClassDef* pClassDef;
	DexClassData* pClassData = NULL;
	const u1* pEncodedData;
	const char* fileName;
	const char* classDescriptor;
	const char* superclassDescriptor;
	char* accessStr = NULL;
	int i;

	pClassDef = dexGetClassDef(pDexFile, idx);

	pEncodedData = dexGetClassData(pDexFile, pClassDef);
	pClassData = dexReadAndVerifyClassData(&pEncodedData, NULL);

	if (pClassData == NULL) {
		printf("Trouble reading class data (#%d)\n", idx);
		goto bail;
	}

	classDescriptor = dexStringByTypeIdx(pDexFile, pClassDef->classIdx);
	if (!(classDescriptor[0] == 'L' &&
		classDescriptor[strlen(classDescriptor) - 1] == ';'))
	{
		/* arrays and primitives should not be defined explicitly */
		fprintf(stderr, "Malformed class name '%s'\n", classDescriptor);
		/* keep going? */
	}
	accessStr = createAccessFlagStr(pClassDef->accessFlags, kAccessForClass);

	if (pClassDef->superclassIdx == kDexNoIndex) {
		superclassDescriptor = NULL;
	}
	else {
		superclassDescriptor =
			dexStringByTypeIdx(pDexFile, pClassDef->superclassIdx);
	}
	printf("Class #%d            -\n", idx);
	printf("  Class descriptor  : '%s'\n", classDescriptor);
	printf("  Access flags      : 0x%04x (%s)\n",
		pClassDef->accessFlags, accessStr);

	if (superclassDescriptor != NULL)
		printf("  Superclass        : '%s'\n", superclassDescriptor);

	printf("  Interfaces        -\n");

	pInterfaces = dexGetInterfacesList(pDexFile, pClassDef);
	if (pInterfaces != NULL) {
		for (i = 0; i < (int)pInterfaces->size; i++)
			dumpInterface(pDexFile, dexGetTypeItem(pInterfaces, i), i);
	}

	printf("  Static fields     -\n");
	for (i = 0; i < (int)pClassData->header.staticFieldsSize; i++) {
		dumpSField(pDexFile, &pClassData->staticFields[i], i);
	}
	printf("  Instance fields   -\n");
	for (i = 0; i < (int)pClassData->header.instanceFieldsSize; i++) {
		dumpIField(pDexFile, &pClassData->instanceFields[i], i);
	}

	printf("  Direct methods    -\n");
	for (i = 0; i < (int)pClassData->header.directMethodsSize; i++) {
		dumpMethod(pDexFile, &pClassData->directMethods[i], i);
	}

bail:
	// detet it 
	int a = 10;
	return;
}

void processDexFile(const char* fileName, DexFile* pDexFile) {
	char* package = NULL;
	int i;
	printf("Opened '%s', DEX version '%.3s'\n", fileName,
		pDexFile->pHeader->magic + 4);

	//if (gOptions.dumpRegisterMaps) {
		dumpRegisterMaps(pDexFile);
		//return;
	//}
	//	if (gOptions.showFileHeaders) {
		dumpFileHeader(pDexFile);
		dumpOptDirectory(pDexFile);
	//	}

	for (i = 0; i < (int)pDexFile->pHeader->classDefsSize; i++) {
		//if (gOptions.showSectionHeaders)
		dumpClassDef(pDexFile, i);

		dumpClass(pDexFile, i, &package);
	}

	/* free the last one allocated */
	if (package != NULL) {
		printf("</package>\n");
		free(package);
	}
}

int process(const char* fileName)
{
	DexFile* pDexFile = NULL;
	MemMapping map;
	int retsult = -1;
	bool mapped = false;

	if (dexOpenAndMap(fileName, &map, false) != 0) {
		return retsult;
	}
	mapped = true;
	int flags = kDexParseVerifyChecksum;
	//if (gOptions.ignoreBadChecksum)
	flags |= kDexParseContinueOnError;

	pDexFile = dexFileParse((u1*)map.addr, map.length, flags);
	if (pDexFile == NULL) {
		fprintf(stderr, "ERROR: DEX parse failed\n");
		goto bail;
	}

//	if (gOptions.checksumOnly) {
		printf("Checksum verified\n");
	//}
	//else {
		processDexFile(fileName, pDexFile);
	//}
	retsult = 0;
bail:
	if (mapped)
		sysReleaseShmem(&map);
	if (pDexFile != NULL)
		dexFileFree(pDexFile);
	return retsult;
}

int main(int argc, char* const argv[]) {
	return process(argv[1]);
}