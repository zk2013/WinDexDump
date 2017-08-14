#include "TypeDefs.h"

void dexDataMapFree(DexDataMap* map) {
	/*
	* Since everything got allocated together, everything can be freed
	* in one fell swoop. Also, free(NULL) is a nop (per spec), so we
	* don't have to worry about an explicit test for that.
	*/
	free(map);
}

bool dexHasValidMagic(const DexHeader* pHeader)
{
	const u1* magic = pHeader->magic;
	const u1* version = &magic[4];

	if (memcmp(magic, DEX_MAGIC, 4) != 0) {
		ALOGE("ERROR: unrecognized magic number (%02x %02x %02x %02x)",
			magic[0], magic[1], magic[2], magic[3]);
		return false;
	}

	if ((memcmp(version, DEX_MAGIC_VERS, 4) != 0) &&
		(memcmp(version, DEX_MAGIC_VERS_API_13, 4) != 0)) {
		/*
		* Magic was correct, but this is an unsupported older or
		* newer format variant.
		*/
		ALOGE("ERROR: unsupported dex version (%02x %02x %02x %02x)",
			version[0], version[1], version[2], version[3]);
		return false;
	}

	return true;
}