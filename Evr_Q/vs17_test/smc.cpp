#include "smc.h"

int VAtoFileOffset(void *pModuleBase, void *pVA)
{
	IMAGE_DOS_HEADER *pDosHead;
	IMAGE_FILE_HEADER *pPEHead;
	IMAGE_SECTION_HEADER *pSection;

	if (::IsBadReadPtr(pModuleBase, sizeof(IMAGE_DOS_HEADER)) || ::IsBadReadPtr(pVA, 4))
		return -1;

	unsigned char *pszModuleBase = (unsigned char *)pModuleBase;
	pDosHead = (IMAGE_DOS_HEADER *)pszModuleBase;
	//����DOSͷ����DOS stub���룬��λ��PE��־λ��
	DWORD Signature = *(DWORD *)(pszModuleBase + pDosHead->e_lfanew);
	if (Signature != IMAGE_NT_SIGNATURE) //"PE\0\0"
		return -1;

	unsigned char *pszVA = (unsigned char *)pVA;
	int nFileOffset = -1;

	//��λ��PE header
	pPEHead = (IMAGE_FILE_HEADER *)(pszModuleBase + pDosHead->e_lfanew + sizeof(DWORD));
	int nSizeofOptionHeader;
	if (pPEHead->SizeOfOptionalHeader == 0)
		nSizeofOptionHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	else
		nSizeofOptionHeader = pPEHead->SizeOfOptionalHeader;

	//����PE header��Option Header����λ��Section��λ��
	pSection = (IMAGE_SECTION_HEADER *)((unsigned char *)pPEHead + sizeof(IMAGE_FILE_HEADER) + nSizeofOptionHeader);
	for (int i = 0; i < pPEHead->NumberOfSections; i++)
	{
		if (!strncmp(".text", (const char*)pSection[i].Name, 5)) //�Ƚ϶�����
		{
			//�����ļ�ƫ���� = �����ڴ������ַ - (������ڴ������ַ - ����ε��ļ�ƫ��)
			nFileOffset = pszVA - (pszModuleBase + pSection[i].VirtualAddress - pSection[i].PointerToRawData);
			break;
		}
	}

	return nFileOffset;
}

static bool XorBlock(void *pStartAddr, int nLength, unsigned char cMask)
{
	if (!pStartAddr || nLength <= 0)
		return false;

	unsigned char *p = (unsigned char *)pStartAddr;
	for (int i = 0; i < nLength; i++)
	{
		*p++ ^= cMask;
	}

	return true;
}

bool EncryptBlock(void *pStartAddr, int nLength, unsigned char cMask)
{
	return XorBlock(pStartAddr, nLength, cMask);
}

bool DecryptBlock(void *pStartAddr, int nLength, unsigned char cMask)
{
	return XorBlock(pStartAddr, nLength, cMask);
}