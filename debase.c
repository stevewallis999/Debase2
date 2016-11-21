// Debase.cpp : Defines the entry point for the console application.
// ReadPE.cpp : Defines the entry point for the console application.
//
#define _CRT_SECURE_NO_WARNINGS
#include "stdafx.h"


#include <stdio.h>
#include <malloc.h>
#include <windows.h>


int main(int argc, char *argv[])
{
    if(argc != 2)
    {   
		printf("Debase will report if an exe has ASLR is enabled\n");
        printf("Usage : %s filename\n",argv[0]);
        return -1;
    }else{
        FILE *fp = fopen(argv[1],"rb");
        IMAGE_DOS_HEADER DosHeader = {0};
        IMAGE_FILE_HEADER FileHeader = {0};
        IMAGE_SECTION_HEADER SectionHeader = {0};
		//my code
		IMAGE_OPTIONAL_HEADER OpionHeader;// = {0}; 
		//my code
        DWORD Signature = 0;
        DWORD RawPointerToPeHeader = 0, SizeOfFile = 0;
        DWORD SectionCount = 0;
        DWORD ByteCount = 0;
        BYTE *pData = NULL;
        if(!fp)
        {
            perror("");
            return -1;
        }
        fseek(fp,0,SEEK_END);
        SizeOfFile = ftell(fp);
        if(SizeOfFile <
            sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS))
            goto not_pe_file;
        fseek(fp,0,SEEK_SET);
        fread(&DosHeader,1,sizeof DosHeader,fp);
        if(DosHeader.e_magic != 'M' + 'Z' * 256)
            goto not_pe_file;
        RawPointerToPeHeader = DosHeader.e_lfanew;
        if(SizeOfFile <=
            RawPointerToPeHeader + sizeof(IMAGE_NT_HEADERS))
            goto not_pe_file;
        fseek(fp,RawPointerToPeHeader,SEEK_SET);
        fread(&Signature,1,sizeof(DWORD),fp);
        if(Signature != 'P' + 'E' * 256)
            goto not_pe_file;
        fread(&FileHeader,1,sizeof FileHeader,fp);
        if(FileHeader.SizeOfOptionalHeader !=
            sizeof(IMAGE_OPTIONAL_HEADER))
            goto not_pe_file;
        SectionCount = FileHeader.NumberOfSections;
        if(SectionCount == 0)
        {
            printf("No section for this file.\n");
            fclose(fp);
            return -1;
        }
        if(SizeOfFile <=
            RawPointerToPeHeader +
            sizeof(IMAGE_NT_HEADERS) +
            SectionCount * sizeof(IMAGE_SECTION_HEADER))
            goto not_pe_file;
        fseek(fp,
            RawPointerToPeHeader + sizeof(IMAGE_NT_HEADERS) +
            (SectionCount - 1) * sizeof(IMAGE_SECTION_HEADER),
                SEEK_SET);
        fread(&SectionHeader,1,sizeof SectionHeader,fp);

        ByteCount = SectionHeader.Misc.VirtualSize < SectionHeader.PointerToRawData ?
            SectionHeader.Misc.VirtualSize : SectionHeader.PointerToRawData;

        if(ByteCount == 0)
        {
            printf("No data to read for target section.\n");
            fclose(fp);
            return -1;
        }else if(ByteCount + SectionHeader.PointerToRawData > SizeOfFile)
        {
            printf("Bad section data.\n");
            fclose(fp);
            return -1;
        }
        fseek(fp,SectionHeader.PointerToRawData,SEEK_SET);

        pData = (BYTE*)malloc(ByteCount);

        fread(pData,1,ByteCount,fp);

		// Simple dump out the headers I should be able to increase t6he code easy
		//this worked wil need to scan on a real rebased exe

		//puthis back in printf("Headers %d \n", SectionHeader); 

		if ( OpionHeader.DllCharacteristics && IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0)
			
			printf("ASLR is disabled\n");
	
		else
			printf("ASLR is enabled dynamic base\n");
        //ShowHexData(pData,ByteCount);
        free(pData);
        fclose(fp);
		getchar();
        return 0;


not_pe_file:
        printf("Not a PE file.\n");
        fclose(fp);
		getchar();
        return -1;
    }


    return 0;
} 