#pragma once
#include <ntifs.h>
#include <wdmsec.h>



void init_trans();

void ChToBit(char* dest, char* src, int length);

void BitToCh(char* dest, char* src, int length);

void BatchSet(char* dest, char* src, char* offset, int count);

void getKeys();

void msgPro(char* dest, char* src);

void DES(char* pmsg, int st, int cl, int step);

