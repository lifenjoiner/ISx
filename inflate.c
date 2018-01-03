/* This is a wrapper for inflating useing miniz_tinfl
@YX Hao
#201712 v0.1
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <direct.h>
#include "miniz_tinfl.h"

#if !defined(_STDINT) && !defined(_STDINT_H) && !defined(__int8_t_defined)
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long uint32_t;
#endif

#define IN_BUF_SIZE (1024*512)
#define OUT_BUF_SIZE (1024*512)

int inflate_fp(FILE *fp_r, FILE *fp_w) {
    static uint8_t pbuf_in[IN_BUF_SIZE];
    static uint8_t pbuf_out[OUT_BUF_SIZE];
    size_t infile_size, infile_remaining;
    size_t avail_in, in_bytes, total_in;
    size_t avail_out, out_bytes, total_out;
    uint8_t *pnext_in, *pnext_out;
    tinfl_status status;
    tinfl_decompressor inflator;
    //
    if (fp_r == fp_w) {
        fprintf(stderr, "Output file is the same as input file!\n");
        return 1;
    }
    //
    infile_size = _filelength(fileno(fp_r));
    infile_remaining = infile_size;
    pnext_in  = pbuf_in;
    pnext_out = pbuf_out;
    avail_in  = 0;
    avail_out = OUT_BUF_SIZE;
    total_in = 0;
    total_out = 0;
    //
    tinfl_init(&inflator);
    //
    for ( ; ; ) {
        if (!avail_in) { // pbuf_in left size
            size_t n = __min(IN_BUF_SIZE, infile_remaining);
            //
            if (fread(pbuf_in, 1, n, fp_r) != n) {
                fprintf(stderr, "Failed reading from input file!\n");
                return 1;
            }
            //
            avail_in = n;
            pnext_in = pbuf_in;
            infile_remaining -= n;
        }
        //
        in_bytes  = avail_in;
        out_bytes = avail_out;
        status = tinfl_decompress(&inflator, pnext_in, &in_bytes,
                    pbuf_out, pnext_out, &out_bytes,
                    (infile_remaining ? TINFL_FLAG_HAS_MORE_INPUT : 0)
                    | TINFL_FLAG_PARSE_ZLIB_HEADER);
        //
        avail_in -= in_bytes;
        pnext_in += in_bytes;
        total_in += in_bytes;
        //
        avail_out -= out_bytes;
        pnext_out += out_bytes;
        total_out += out_bytes;
        //
        if ((status <= TINFL_STATUS_DONE) || (!avail_out)) {
            // Output buffer is full or decompression is done
            size_t n = OUT_BUF_SIZE - avail_out;
            if (fwrite(pbuf_out, 1, n, fp_w) != n) {
                fprintf(stderr, "Failed writing to output file!\n");
                return 1;
            }
            pnext_out = pbuf_out;
            avail_out = OUT_BUF_SIZE;
        }

        // done or went wrong
        if (status <= TINFL_STATUS_DONE) {
            if (status == TINFL_STATUS_DONE) {
                break;
            }
            else {
                fprintf(stderr, "Decompression failed with status %i!\n", status);
                return 1;
            }
        }
    }
    //
    return 0;
}

int inflate_f(char *f_r, char *f_w) {
    FILE *fp_r, *fp_w;
    int ret;
    //
    if (stricmp(f_r, f_w) == 0) {
        fprintf(stderr, "Output file is the same as input file!\n");
        return 1;
    }
    //
    ret = 1;
    fp_r = fopen(f_r, "rb");
    //
    if (!fp_r) {
        fprintf(stderr, "Can't open file: %s!\n", f_r);
    }
    else {
        fp_w = fopen(f_w, "wb");
        if (!fp_w) {
            fprintf(stderr, "Can't open file: %s!\n", f_w);
        }
        else {
            ret = inflate_fp(fp_r, fp_w);
            fflush(fp_w);
            fclose(fp_w);
        }
        fclose(fp_r);
    }
    //
    return ret;
}