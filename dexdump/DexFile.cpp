#include "TypeDefs.h"

void dexFileSetupBasicPointers(DexFile* pDexFile, const u1* data) {
	DexHeader *pHeader = (DexHeader*)data;

	pDexFile->baseAddr = data;
	pDexFile->pHeader = pHeader;
	pDexFile->pStringIds = (const DexStringId*)(data + pHeader->stringIdsOff);
	pDexFile->pTypeIds = (const DexTypeId*)(data + pHeader->typeIdsOff);
	pDexFile->pFieldIds = (const DexFieldId*)(data + pHeader->fieldIdsOff);
	pDexFile->pMethodIds = (const DexMethodId*)(data + pHeader->methodIdsOff);
	pDexFile->pProtoIds = (const DexProtoId*)(data + pHeader->protoIdsOff);
	pDexFile->pClassDefs = (const DexClassDef*)(data + pHeader->classDefsOff);
	pDexFile->pLinkData = (const DexLink*)(data + pHeader->linkOff);
}

bool dexParseOptData(const u1* data, size_t length, DexFile* pDexFile) {
	// later implement it.
	return true;
}

DexFile* dexFileParse(const u1* data, size_t length, int flags)
{
	DexFile* pDexFile = NULL;
	const DexHeader* pHeader;
	const u1* magic;
	int result = -1;

	if (length < sizeof(DexHeader)) {
		ALOGE("too short to be a valid .dex");
		goto bail;      /* bad file format */
	}

	pDexFile = (DexFile*)malloc(sizeof(DexFile));
	if (pDexFile == NULL)
		goto bail;      /* alloc failure */
	memset(pDexFile, 0, sizeof(DexFile));

	if (memcmp(data, DEX_OPT_MAGIC, 4) == 0) {
		magic = data;
		if (memcmp(magic + 4, DEX_OPT_MAGIC_VERS, 4) != 0) {
			ALOGE("bad opt version (0x%02x %02x %02x %02x)",
				magic[4], magic[5], magic[6], magic[7]);
			goto bail;
		}

		pDexFile->pOptHeader = (const DexOptHeader*)data;
		ALOGV("Good opt header, DEX offset is %d, flags=0x%02x",
			pDexFile->pOptHeader->dexOffset, pDexFile->pOptHeader->flags);

		/* parse the optimized dex file tables */
		if (!dexParseOptData(data, length, pDexFile))
			goto bail;

		/* ignore the opt header and appended data from here on out */
		data += pDexFile->pOptHeader->dexOffset;
		length -= pDexFile->pOptHeader->dexOffset;
		if (pDexFile->pOptHeader->dexLength > length) {
			ALOGE("File truncated? stored len=%d, rem len=%d",
				pDexFile->pOptHeader->dexLength, (int)length);
			goto bail;
		}
		length = pDexFile->pOptHeader->dexLength;
	}

	dexFileSetupBasicPointers(pDexFile, data);
	pHeader = pDexFile->pHeader;

	if (!dexHasValidMagic(pHeader)) {
		goto bail;
	}
	if (pHeader->fileSize != length) {
		ALOGE("ERROR: stored file size (%d) != expected (%d)",
			(int)pHeader->fileSize, (int)length);
		if (!(flags & kDexParseContinueOnError))
			goto bail;
	}

	if (pHeader->classDefsSize == 0) {
		ALOGE("ERROR: DEX file has no classes in it, failing");
		goto bail;
	}

	/*
	* Success!
	*/
	result = 0;
bail:
	if (result != 0 && pDexFile != NULL) {
		dexFileFree(pDexFile);
		pDexFile = NULL;
	}
	return pDexFile;
}

void dexFileFree(DexFile* pDexFile)
{
	if (pDexFile == NULL)
		return;

	free(pDexFile);
}