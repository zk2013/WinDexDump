#include <stdio.h>
#include <Windows.h>
#include "TypeDefs.h"
#include "adler32.h"

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
	return 0;
}

int safe_add(size_t* pResult, int a, int b) {
	*pResult = a+b;
	return 0;
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
		}
	}
	return result;
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

	HANDLE hFile = ::CreateFile(fileName, GENERIC_READ| GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
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
	pMap->baseLength = pMap->length = GetFileSize(hFile,NULL);
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

int process(const char* fileName)
{
	MemMapping map;
	int retsult = -1;

	if (dexOpenAndMap(fileName, &map, false) != 0) {
		return retsult;
	}

	return 0;
}

int main(int argc, char* const argv[]) {
	return process(argv[1]);
}