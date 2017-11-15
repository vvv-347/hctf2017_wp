#include "scode.h"

void enc0_f(unsigned char * enc_t, char *plain_t) {
	for (int i = 0; i < 35; i++) {
		enc_t[i] = plain_t[i] ^ 0x76;
	}

}

void enc0_end() {
	printf("...");
}