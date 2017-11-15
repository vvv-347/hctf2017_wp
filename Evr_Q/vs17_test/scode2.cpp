#include "scode2.h"

void enc2_f(unsigned char * enc_t, unsigned char *plain_t) {
	for (int i = 0; i < 7; i++) {
		enc_t[i] = plain_t[14 + i] ^ 0xBE;
		int v1 = (enc_t[i] & 0xCC) >> 2;
		int v2 = (enc_t[i] << 2) & 0xCC;
		enc_t[i] = v1 | v2;
	}
		
}

void enc2_end() {
	printf("...");
}