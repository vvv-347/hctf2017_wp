#include <windows.h>

int VAtoFileOffset(void *pModuleBase, void *pVA);
static bool XorBlock(void *pStartAddr, int nLength, unsigned char cMask);
bool EncryptBlock(void *pStartAddr, int nLength, unsigned char cMask);
bool DecryptBlock(void *pStartAddr, int nLength, unsigned char cMask);