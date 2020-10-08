#include <windows.h>
#include <stdio.h>
#include "boxreflect.h"

DWORD findExportDirectoryInfo(DWORD pointerToRawData, DWORD virtualAddressOffset) {
    printf("         [-] [0x%04x] %-26s : 0x%02X%02X%02X%02X\n", pointerToRawData, "[exportFlags]", boxreflect_dll[pointerToRawData+3], boxreflect_dll[pointerToRawData+2], boxreflect_dll[pointerToRawData+1], boxreflect_dll[pointerToRawData]);

    DWORD timeDateStampOffset = pointerToRawData + 0x4;
    printf("         [-] [0x%04x] %-26s : 0x%02X%02X%02X%02X\n", timeDateStampOffset, "[Time/DateStamp]", boxreflect_dll[timeDateStampOffset+3], boxreflect_dll[timeDateStampOffset+2], boxreflect_dll[timeDateStampOffset+1], boxreflect_dll[timeDateStampOffset]);

    DWORD majorVersionOffset = timeDateStampOffset + 0x4;
    printf("         [-] [0x%04x] %-26s : 0x%02X%02X\n", majorVersionOffset, "[majorVersion]", boxreflect_dll[majorVersionOffset+1], boxreflect_dll[majorVersionOffset]);

    DWORD minorVersionOffset = majorVersionOffset + 0x2;
    printf("         [-] [0x%04x] %-26s : 0x%02X%02X\n", minorVersionOffset, "[minorVersion]", boxreflect_dll[minorVersionOffset+1], boxreflect_dll[minorVersionOffset]);

    DWORD nameRVAOffset = minorVersionOffset + 0x2;
    printf("         [-] [0x%04x] %-26s : 0x%02X%02X%02X%02X %s\n", nameRVAOffset, "[nameRVA]", boxreflect_dll[nameRVAOffset+3], boxreflect_dll[nameRVAOffset+2], boxreflect_dll[nameRVAOffset+1], boxreflect_dll[nameRVAOffset], " (RVA to PE name)");

    DWORD ordinalBaseOffset = nameRVAOffset + 0x4;
    printf("         [-] [0x%04x] %-26s : 0x%02X%02X%02X%02X\n", ordinalBaseOffset, "[ordinalBase]", boxreflect_dll[ordinalBaseOffset+3], boxreflect_dll[ordinalBaseOffset+2], boxreflect_dll[ordinalBaseOffset+1], boxreflect_dll[ordinalBaseOffset]);

    DWORD addressTableEntriesOffset = ordinalBaseOffset + 0x4;
    printf("         [-] [0x%04x] %-26s : 0x%02X%02X%02X%02X %s\n", addressTableEntriesOffset, "[addressTableEntries]", boxreflect_dll[addressTableEntriesOffset+3], boxreflect_dll[addressTableEntriesOffset+2], boxreflect_dll[addressTableEntriesOffset+1], boxreflect_dll[addressTableEntriesOffset], " (Count of functions in Export Address Table)");

    DWORD numberOfNamePointersOffset = addressTableEntriesOffset + 0x4;
    printf("         [-] [0x%04x] %-26s : 0x%02X%02X%02X%02X %s\n", numberOfNamePointersOffset, "[numberOfNamePointers]", boxreflect_dll[numberOfNamePointersOffset+3], boxreflect_dll[numberOfNamePointersOffset+2], boxreflect_dll[numberOfNamePointersOffset+1], boxreflect_dll[numberOfNamePointersOffset], " (Count of entries in the name pointer table/ordinal table)");

    DWORD exportAddressTableRVAOffset = numberOfNamePointersOffset + 0x4;
    printf("         [-] [0x%04x] %-26s : 0x%02X%02X%02X%02X %s\n", exportAddressTableRVAOffset, "[exportAddressTableRVA]", boxreflect_dll[exportAddressTableRVAOffset+3], boxreflect_dll[exportAddressTableRVAOffset+2], boxreflect_dll[exportAddressTableRVAOffset+1], boxreflect_dll[exportAddressTableRVAOffset], " (RVA of the Export Address Table)");

    DWORD namePointerRVAOffset = exportAddressTableRVAOffset + 0x4;
    printf("         [-] [0x%04x] %-26s : 0x%02X%02X%02X%02X %s\n", namePointerRVAOffset, "[namePointerRVA]", boxreflect_dll[namePointerRVAOffset+3], boxreflect_dll[namePointerRVAOffset+2], boxreflect_dll[namePointerRVAOffset+1], boxreflect_dll[namePointerRVAOffset], " (RVA of the Export Name Pointer Table)");

    DWORD ordinalTableRVAOffset = namePointerRVAOffset + 0x4;
    printf("         [-] [0x%04x] %-26s : 0x%02X%02X%02X%02X %s\n", ordinalTableRVAOffset, "[ordinalTableRVA]", boxreflect_dll[ordinalTableRVAOffset+3], boxreflect_dll[ordinalTableRVAOffset+2], boxreflect_dll[ordinalTableRVAOffset+1], boxreflect_dll[ordinalTableRVAOffset], " (RVA of the Ordinal Table)");

    DWORD exportNamePointerRVA = (boxreflect_dll[namePointerRVAOffset+3] << 24) | (boxreflect_dll[namePointerRVAOffset+2] << 16) | (boxreflect_dll[namePointerRVAOffset+1] << 8) | boxreflect_dll[namePointerRVAOffset];
    DWORD edataVirtualAddress = (boxreflect_dll[virtualAddressOffset+3] << 24) | (boxreflect_dll[virtualAddressOffset+2] << 16) | (boxreflect_dll[virtualAddressOffset+1] << 8) | boxreflect_dll[virtualAddressOffset];
    DWORD exportNamePointerFileOffset = ( exportNamePointerRVA - edataVirtualAddress ) + pointerToRawData;
    printf("         [-] [0x%04x] %-26s : 0x%02X%02X%02X%02X\n", exportNamePointerFileOffset, "[exportNamePointerRVA]", boxreflect_dll[exportNamePointerFileOffset+3], boxreflect_dll[exportNamePointerFileOffset+2], boxreflect_dll[exportNamePointerFileOffset+1], boxreflect_dll[exportNamePointerFileOffset]);

    DWORD symbolNameRVA = (boxreflect_dll[exportNamePointerFileOffset+3] << 24) | (boxreflect_dll[exportNamePointerFileOffset+2] << 16) | (boxreflect_dll[exportNamePointerFileOffset+1] << 8) | boxreflect_dll[exportNamePointerFileOffset];
    DWORD symbolFileOffset = ( symbolNameRVA - edataVirtualAddress ) + pointerToRawData;
    unsigned char symbolName[MAX_PATH] = { 0 };
    for (int i = 0; i < MAX_PATH; i++) {
        if (boxreflect_dll[symbolFileOffset+i] == 0) {
            break;
        }
        symbolName[i] = boxreflect_dll[symbolFileOffset+i];
    }
    printf("         [-] [0x%04x] %-26s : %s\n", symbolFileOffset, "[symbolName]", symbolName);

    DWORD exportAddressTableRVA = (boxreflect_dll[exportAddressTableRVAOffset+3] << 24) | (boxreflect_dll[exportAddressTableRVAOffset+2] << 16) | (boxreflect_dll[exportAddressTableRVAOffset+1] << 8) | boxreflect_dll[exportAddressTableRVAOffset];
    DWORD symbolRVAOffset = ( exportAddressTableRVA - edataVirtualAddress ) + pointerToRawData;
    DWORD symbolRVA = (boxreflect_dll[symbolRVAOffset+3] << 24) | (boxreflect_dll[symbolRVAOffset+2] << 16) | (boxreflect_dll[symbolRVAOffset+1] << 8) | boxreflect_dll[symbolRVAOffset];
    printf("         [-] [0x%04x] %-26s : 0x%08X\n", symbolRVAOffset, "[symbolRVA]", symbolRVA);
    return symbolRVA;
}

void findSectionHeaders(DWORD firstSectionHeaderOffset, DWORD noOfSections) {
    printf("\n [Sections headers start at: 0x%04x]\n", firstSectionHeaderOffset);

    DWORD nextSectionHeaderOffset = firstSectionHeaderOffset;
    for (int i = 0; i < noOfSections; i++) {
        CHAR headerName[] = { boxreflect_dll[nextSectionHeaderOffset], boxreflect_dll[nextSectionHeaderOffset+1],
            boxreflect_dll[nextSectionHeaderOffset+2], boxreflect_dll[nextSectionHeaderOffset+3],
            boxreflect_dll[nextSectionHeaderOffset+4], boxreflect_dll[nextSectionHeaderOffset+5],
            boxreflect_dll[nextSectionHeaderOffset+6], boxreflect_dll[firstSectionHeaderOffset+7], 0x00 };

        printf(" [+] [Section Header %d]\n", i);
        printf("     [+] [0x%04x] %-30s : %-30s\n", nextSectionHeaderOffset, "[Name]", headerName);

        DWORD virtualSizeOffset = nextSectionHeaderOffset + 0x8;
        printf("     [+] [0x%04x] %-30s : 0x%02X%02X%02X%02X\n", virtualSizeOffset, "[VirtualSize]", boxreflect_dll[virtualSizeOffset+3], boxreflect_dll[virtualSizeOffset+2], boxreflect_dll[virtualSizeOffset+1], boxreflect_dll[virtualSizeOffset]);

        DWORD virtualAddressOffset = virtualSizeOffset + 0x4;
        printf("     [+] [0x%04x] %-30s : 0x%02X%02X%02X%02X\n", virtualAddressOffset, "[VirtualAddress]", boxreflect_dll[virtualAddressOffset+3], boxreflect_dll[virtualAddressOffset+2], boxreflect_dll[virtualAddressOffset+1], boxreflect_dll[virtualAddressOffset]);

        DWORD sizeOfRawDataOffset = virtualAddressOffset + 0x4;
        printf("     [+] [0x%04x] %-30s : 0x%02X%02X%02X%02X\n", sizeOfRawDataOffset, "[SizeOfRawData]", boxreflect_dll[sizeOfRawDataOffset+3], boxreflect_dll[sizeOfRawDataOffset+2], boxreflect_dll[sizeOfRawDataOffset+1], boxreflect_dll[sizeOfRawDataOffset]);

        DWORD pointerToRawDataOffset = sizeOfRawDataOffset + 0x4;
        printf("     [+] [0x%04x] %-30s : 0x%02X%02X%02X%02X\n", pointerToRawDataOffset, "[PointerToRawData]", boxreflect_dll[pointerToRawDataOffset+3], boxreflect_dll[pointerToRawDataOffset+2], boxreflect_dll[pointerToRawDataOffset+1], boxreflect_dll[pointerToRawDataOffset]);

        DWORD pointerToRelocationsOffset = pointerToRawDataOffset + 0x4;
        printf("     [+] [0x%04x] %-30s : 0x%02X%02X%02X%02X\n", pointerToRelocationsOffset, "[PointerToRelocations]", boxreflect_dll[pointerToRelocationsOffset+3], boxreflect_dll[pointerToRelocationsOffset+2], boxreflect_dll[pointerToRelocationsOffset+1], boxreflect_dll[pointerToRelocationsOffset]);

        DWORD pointerToLinenumbersOffset = pointerToRelocationsOffset + 0x4;
        printf("     [+] [0x%04x] %-30s : 0x%02X%02X%02X%02X\n", pointerToLinenumbersOffset, "[PointerToLinenumbers]", boxreflect_dll[pointerToLinenumbersOffset+3], boxreflect_dll[pointerToLinenumbersOffset+2], boxreflect_dll[pointerToLinenumbersOffset+1], boxreflect_dll[pointerToLinenumbersOffset]);

        DWORD numberOfLinenumbersOffset = pointerToLinenumbersOffset + 0x4;
        printf("     [+] [0x%04x] %-30s : 0x%02X%02X%02X%02X\n", numberOfLinenumbersOffset, "[NumberOfLinenumbers]", boxreflect_dll[numberOfLinenumbersOffset+3], boxreflect_dll[numberOfLinenumbersOffset+2], boxreflect_dll[numberOfLinenumbersOffset+1], boxreflect_dll[numberOfLinenumbersOffset]);

        DWORD characteristicsOffset = numberOfLinenumbersOffset + 0x4;
        printf("     [+] [0x%04x] %-30s : 0x%02X%02X%02X%02X\n", characteristicsOffset, "[Characteristics]", boxreflect_dll[characteristicsOffset+3], boxreflect_dll[characteristicsOffset+2], boxreflect_dll[characteristicsOffset+1], boxreflect_dll[characteristicsOffset]);

        if (strstr(headerName, ".edata")) {
            DWORD firstByte = boxreflect_dll[pointerToRawDataOffset+3];
            DWORD secondByte = boxreflect_dll[pointerToRawDataOffset+2];
            DWORD thirdByte = boxreflect_dll[pointerToRawDataOffset+1];
            DWORD fourthByte = boxreflect_dll[pointerToRawDataOffset+0];

            DWORD pointerToRawData = ( firstByte << 24 ) | ( secondByte << 16 ) | ( thirdByte << 8 ) | fourthByte;
            DWORD symbolRVA = findExportDirectoryInfo(pointerToRawData, virtualAddressOffset);

            DWORD tempSectionHeaderOffset = firstSectionHeaderOffset;
            for (int i = 0; i < 11; i++) {
                // VirtualAddress offset is 12 bytes from firstSectionHeaderOffset ( Name = 8 bytes, VirtualSize = 4 bytes )
                DWORD sectionVirtualAddressOffset = firstSectionHeaderOffset + 0xC;
                DWORD sectionVirtualAddress = (boxreflect_dll[sectionVirtualAddressOffset+3] << 24) | (boxreflect_dll[sectionVirtualAddressOffset+2] << 16) | (boxreflect_dll[sectionVirtualAddressOffset+1] << 8) | boxreflect_dll[sectionVirtualAddressOffset];
                // SizeOfRawData offset is 4 bytes from VirtualAddress ( VirtualAddress = 4 )
                DWORD sectionSizeOfRawDataOffset = sectionVirtualAddressOffset + 0x4;
                DWORD sectionSizeOfRawData = (boxreflect_dll[sectionSizeOfRawDataOffset+3] << 24) | (boxreflect_dll[sectionSizeOfRawDataOffset+2] << 16) | (boxreflect_dll[sectionSizeOfRawDataOffset+1] << 8) | boxreflect_dll[sectionSizeOfRawDataOffset];
                // SizeOfRawData offset is 4 bytes from SizeOfRawData ( SizeOfRawData = 4 )
                DWORD sectionPointerToRawDataOffset = sectionSizeOfRawDataOffset + 0x4;
                DWORD sectionPointerToRawData = (boxreflect_dll[sectionPointerToRawDataOffset+3] << 24) | (boxreflect_dll[sectionPointerToRawDataOffset+2] << 16) | (boxreflect_dll[sectionPointerToRawDataOffset+1] << 8) | boxreflect_dll[sectionPointerToRawDataOffset];

                if  (symbolRVA > sectionVirtualAddress && (symbolRVA < sectionVirtualAddress + sectionSizeOfRawData) ) {
                    DWORD symbolFileOffset = ( symbolRVA - sectionVirtualAddress ) + sectionPointerToRawData;
                    printf("     [*] [0x%04x] %-30s : 0x%08X\n", symbolRVA, "[symbolFileOffset]", symbolFileOffset);

                    LPVOID boxreflectDllExectuableBuffer = VirtualAllocEx(GetCurrentProcess(), NULL, boxreflect_dll_len, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                    WriteProcessMemory(GetCurrentProcess(), boxreflectDllExectuableBuffer, boxreflect_dll, boxreflect_dll_len, NULL);
                    LPTHREAD_START_ROUTINE symbolExecutableAddress = (LPTHREAD_START_ROUTINE)( (ULONG_PTR)boxreflectDllExectuableBuffer + symbolFileOffset );
                    DWORD lpThreadId;
                    HANDLE hThread = CreateRemoteThread( GetCurrentProcess(), NULL, 1024*1024, symbolExecutableAddress, NULL, NULL, &lpThreadId);
                    WaitForSingleObject(hThread, INFINITE);
                    break;
                }
                tempSectionHeaderOffset += 0x28;
            }
        }

        nextSectionHeaderOffset += 0x28;
        printf("\n");
    }
}

int main() {
    DWORD initialOffset = 0x3c;
	DWORD peHeaderOffset = boxreflect_dll[initialOffset];
	printf(" [0x%04x] %-38s : 0x%02X\n", initialOffset, "[peHeader offset]", peHeaderOffset);
	printf(" [0x%04x] %-38s : %c%c\n", peHeaderOffset, "[peHeader]", boxreflect_dll[peHeaderOffset], boxreflect_dll[peHeaderOffset+1]);

	DWORD machineTypeOffset = peHeaderOffset + 4;
	printf(" [0x%04x] %-38s : x%x%x\n", machineTypeOffset, "[machineType]", boxreflect_dll[machineTypeOffset+1], boxreflect_dll[machineTypeOffset]);

	DWORD noOfSectionsOffset = machineTypeOffset + 0x2;
    DWORD noOfSections = ( boxreflect_dll[noOfSectionsOffset+1] << 8 ) | ( boxreflect_dll[noOfSectionsOffset] );
	printf(" [0x%04x] %-38s : (%d) 0x%02X\n", noOfSectionsOffset, "[noOfSections]",  noOfSections, noOfSections);

	DWORD timeDateStampOffset = noOfSectionsOffset + 0x2;
	printf(" [0x%04x] %-38s : 0x%02X%02X%02X%02X\n", timeDateStampOffset, "[timeDateStamp]", boxreflect_dll[timeDateStampOffset+3], boxreflect_dll[timeDateStampOffset+2], boxreflect_dll[timeDateStampOffset+1], boxreflect_dll[timeDateStampOffset]);

    //PointerToSymbolTable deprecated = 0x4 bytes
    //NumberOfSymbols  deprecated = 0x4 bytes
    DWORD sizeOfOptionalHeaderOffset = timeDateStampOffset + 0x4 + 0x4 + 0x4;
    DWORD sizeOfOptionalHeader = ( boxreflect_dll[sizeOfOptionalHeaderOffset+1]<<8) | (boxreflect_dll[sizeOfOptionalHeaderOffset]);
	printf(" [0x%04x] %-38s : 0x%02X\n", sizeOfOptionalHeaderOffset, "[sizeOfOptionalHeader]", sizeOfOptionalHeader);

    //Characteristics = 0x2 bytes
    //Data at sizeOfOptionalHeaderOffset = 0x2 bytes
    //First Section Header Offset = sizeOfOptionalHeaderOffset (since data at sizeOfOptionalHeaderOffset is 2 bytes, add 2 to the start of this offset) + 0x2 + characteristicsOffset (2 bytes) + sizeOfOptionalHeader
    DWORD firstSectionHeaderOffset = sizeOfOptionalHeaderOffset + 0x2 + 0x2 + sizeOfOptionalHeader;

    findSectionHeaders(firstSectionHeaderOffset, noOfSections);
    return 1;
}



