#include "get_watermark.h"

u_char *get_wm() {
    u_char buf[1674] = { 0x00, };
    FILE *fp = fopen("BBB_watermark", "r");

    if(fp == nullptr) {
        fprintf(stderr, "file open error...\n");
        return nullptr;
    }

    fread(buf, 1, 1674, fp);
    fclose(fp);

    return buf;
}
