#include "scode3.h"

void enc3_f(unsigned char * enc_t, unsigned char *plain_t) {
	for (int i = 0; i < 7; i++) {
		enc_t[i] = plain_t[21 + i] ^ 0xEF;
		int v1 = (enc_t[i] & 0xF0) >> 4;
		int v2 = (enc_t[i] << 4) & 0xF0;
		enc_t[i] = v1 | v2;
	}
		
}

void enc3_end() {
	printf("...");
}