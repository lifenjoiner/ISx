/* An InstallShield installer extractor
@YX Hao

History:
#202212 v0.3.3
+ Cover 'ISSetupStream' v4.

#201712 v0.3
+ Support unicode file name, and 'ISSetupStream' format.

#201712 v0.2
+ Support extra inflation for unicode launcher.

#201712 v0.1
Work with plain dump and decryption.

* read the license file *
*/

/* The InstallShield installer Info
Starting sig:
read 0x2E, 46;
Offset      0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F
0004C000   49 6E 73 74 61 6C 6C 53  68 69 65 6C 64 00 07 00   InstallShield...

Trace:
MapViewOfFile
WriteFile
ReadFile
CloseHandle
SetFilePointer

Decryption methods:
plain:  no encryption, first file is 'data1.cab'
M1024:  every block size 1024, 7 files
Mfile:  full file size, found in v12/v10.5, not DevStudio 9
Mmis:   leading data
inflate: zlib inlate, flaged unicode, > v12, not v10.5


history versions:
https://www.flexera.com/producer/support/additional-support/end-of-life/installshield.html
Application                         Version 'General Availability'  Methods
InstallShield 2016                  23      2016-08                 <ISSetupStream>
InstallShield 2015                  22      2015-06                 <ISSetupStream>
InstallShield 2014                  21      2014-05
InstallShield 2013                  20      2013-06
InstallShield 2012 Spring           19      2012-05
InstallShield 2012                  18      2011-08
InstallShield 2011                  17      2010-07                 Unicode Pro: M1024
InstallShield 2010                  16      2009-07                 Unicode Pro: M1024
InstallShield 2009                  15      2008-05                 plain
InstallShield Express 2009          2009    2008-08
InstallShield 2008                  14      2007-05
InstallShield Express 2008          2008    2007-08
InstallShield All German Editions   All     6/1/2010
InstallShield 12                    12      2006-06                 plain or M1024
InstallShield 11.5                  11.5    2005-11
InstallShield Express 11.5          11.5    2006-02
InstallShield 11                    11      2005-05
InstallShield Express 11            11      2005-07
InstallShield 10.5                  10.5    2004-11                 M1024
InstallShield X SP1                 X       2004-07
InstallShield Express X SP1         X       2004-07
InstallShield X                     X       2004-05
InstallShield Express X             X       2004-06
InstallShield Express 5 SP2         5       2004-01
InstallShield Express 5             5       2003-10
DevStudio 9 SP1                     9       2003-11
DevStudio 9                         9       2003-09                 plain

InstallShield DevStudio - 9.0
InstallShield Developer 8 - 8.0
InstallShield Developer 7 - 7.0
InstallShield 6.x - 6.2 or 6.3
InstallShield 5.1 - 5.1


Download
https://saturn.installshield.com/product/is/2011/domestic/pro/installshield2011professional.exe
https://saturn.installshield.com/product/is/2010/domestic/premier/installShield2010.exe
https://saturn.installshield.com/product/is/2009/domestic/premier/installshield2009.exe
https://saturn.installshield.com/product/is/2008/domestic/premier/installshield2008.exe

https://saturn.installshield.com/is/12/windows/japanese/premier/installshield12japanese.exe
https://saturn.installshield.com/is/11.5/windows/japanese/wrapped/prem/installshield1150japanese.exe
https://saturn.installshield.com/is/11/windows/japanese/wrapped/prem/installshield11japanese.exe

https://saturn.installshield.com/is/10.5sp1/premier/full/package/installshield1050sp1premier.exe
https://saturn.installshield.com/is/10.5/windows/premier/full/package/installshield1050premier.exe

https://saturn.installshield.com/is/x/express/eval/package/isxexpresseval.exe

http://saturn.installshield.com/devstudio/

broken url:
http://saturn.installshield.com/isd/802/full/pftw/InstallShieldDeveloper80SP2Ecomm.exe
http://saturn.installshield.com/isd/8/full/phobubro/pftw/InstallShieldDeveloper80Full.exe

On line help
http://helpnet.installshield.com/installshield22helplib/helplibrary/IHelpContents.htm
23~19
*/

/* Launcher tools:
setup.exe
program files\Macrovision\IS2008\Redist\Language Independent\i386\
program files\InstallShield\2011\Redist\Language Independent\i386\
program files\InstallShield\2011\Redist\Language Independent\i386\ISP\:
plain, file name could be unicode
setupPreReq.exe

Setup.exe and Update.exe Command-Line Parameters

Re-package:
ReleasePackager.exe
Or you can make them to other sfx installer.
Unicode version will produce plain package with unicode strings.

Cab viewer:
IsCabView.exe
MediaBuild??.dll
ToolkitPro1331vc90U.dll (Xtreme Toolkit Pro Library, UI)

InstallShield Command Line Cab File Editor (2009):
ISCAB.exe
ISCAB.exe.manifest
ISTools.dll
MediaBuild40.dll (versions)

InstallShield Script Compiler:
compiler.exe
compiler.dll
*/

/* zlib
inflate 1.2.3 Copyright 1995-2005 Mark Adler
https://github.com/madler/zlib
https://github.com/richgel999/miniz
https://github.com/pfalcon/uzlib
https://bitbucket.org/jibsen/tinf
comparation: https://github.com/micropython/micropython/issues/741
*/

/* debug the installer
"H:\InstallShield\InstallShield2016_SP2.exe"  -IS_temp ORIGINALSETUPEXEDIR="H:\InstallShield" ORIGINALSETUPEXENAME="InstallShield2016_SP2.exe"
*/

/* compile
tcc -o ISx-tcc.exe ISx.c inflate_tinfl.c ..\miniz\miniz_tinfl.c -I..\miniz
gcc -Os -s -o ISx-gcc.exe ISx.c inflate_tinfl.c ..\miniz\miniz_tinfl.c -I..\miniz
cl /Os /MD /FeISx-vc.exe ISx.c inflate_tinfl.c ..\miniz\miniz_tinfl.c /I..\miniz
*/


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <direct.h>
#include <tchar.h>
#include <locale.h>

// PE file struct, 'WideChar <--> MultiByte'
#if defined(_WIN32)

// MSVCR80.dll: v8.0.40310 from PSDK-2003-amd64 still doesn't have; v8.0.50727 has.
#if _MSC_FULL_VER <= 140040310 && __MSVCRT_VERSION__ < 0x1400
#include <errno.h>
int __cdecl _fseeki64(FILE* stream, __int64 offset, int whence)
{
    fpos_t pos;
    if (whence == SEEK_CUR) {
        if (fgetpos(stream, &pos))
            return (-1);
        pos += (fpos_t)offset;
    }
    else if (whence == SEEK_END) {
        fflush(stream);
        pos = (fpos_t)(_filelengthi64(_fileno(stream)) + offset);
    }
    else if (whence == SEEK_SET)
        pos = (fpos_t)offset;
    else {
        errno = EINVAL;
        return (-1);
    }
    return fsetpos(stream, &pos);
}

__int64 __cdecl _ftelli64(FILE* stream)
{
    fpos_t pos;
    if (fgetpos(stream, &pos))
        return (__int64)-1;
    else
        return (__int64)pos;
}
#endif

#define ftellx _ftelli64
#define fseekx _fseeki64

#include <windows.h>
int utf16_to_cs(const wchar_t *str_w, UINT cp_out, char **str_m) {
    const wchar_t *str_wn;
    int len_m;
    unsigned char *U16LE_BOM = "\xFF\xFE";
    //
    str_wn = (cp_out != 65000 && memcmp(str_w, U16LE_BOM, 2) == 0) ? str_w + 1 : str_w;
    len_m = WideCharToMultiByte(cp_out, 0, str_wn, -1, NULL, 0, NULL, NULL);
    if (len_m == 0) {return 0;}
    *str_m = calloc(len_m, sizeof(char));
    len_m = WideCharToMultiByte(cp_out, 0, str_wn, -1, *str_m, len_m, NULL, NULL);
    return len_m - 1;
}

int __cdecl _getmbcp(void); // #include <mbctype.h>

#else // defined(_WIN32)
#define ftellx _ftello64
#define fseekx _fseeko64
// the header you need
#endif // defined(_WIN32)

#ifndef NO_INFLATE // maybe require 'stdint.h'
extern int inflate_f(char *f_r, char *f_w);
#endif

/* **** */
#define PREFER_BLOCK_SIZE (4096 * 64) // n * SECTOR_SIZE, for high efficiency

#if !defined(_STDINT) && !defined(_STDINT_H) && !defined(__int8_t_defined)
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long uint32_t;
#endif


/* **** */
char *g_Ver = "0.3.11";
char *g_DestDir;
char *g_Seed;
int g_CP;


/* **** */
/* header
Following PE file's last section.
len: 46, 0x2E
*/
char *ISSIG = "InstallShield";

// new formats
char *ISSIG_strm = "ISSetupStream";

// file structure
#pragma pack(push, 1)

/* Arch header
size: 46, 0x2E */
typedef struct IS_HEADER
{
    char SIG[14];
    uint16_t num_files;
    uint32_t type;  // used by "ISSetupStream" format
    uint8_t  x4[8];
    uint16_t x5;    // >= 8, SIG[8] is 'wchar_t **'
    uint8_t  x6[16];
} IS_HEADER, *PIS_HEADER;

/* file attributes
len: 312, 0x138
extra data? */
typedef struct IS_FILE_ATTRIBUTES
{
    char file_name[_MAX_PATH]; // _MAX_PATH
    uint32_t encoded_flags; // encoded: 0x2|0x4 for num_files = 7, 0x2 for 5
    uint32_t x3;
    uint32_t file_len;
    uint8_t  x5[8];
    uint16_t is_unicode_launcher;
    uint8_t  x7[30];
} IS_FILE_ATTRIBUTES, *PIS_FILE_ATTRIBUTES;

/* For "ISSetupStream" attributes
size: 24, 0x18
following is unicode file name
utf8 file name as decoding seeds */
typedef struct IS_FILE_ATTRIBUTES_X
{
    uint32_t filename_len;
    uint32_t encoded_flags;
    uint8_t  x3[2];
    uint32_t file_len;
    uint8_t  x5[8];
    uint16_t is_unicode_launcher;   // read unit 0x4000
} IS_FILE_ATTRIBUTES_X, *PIS_FILE_ATTRIBUTES_X;

#pragma pack(pop)

/* **** */
char *strcat_x(char *path, char *ext_path) {
    path = realloc(path, strlen(path) + strlen(ext_path) + 1);
    return strcat(path, ext_path);
}

/* Dir name must have a seperator suffix. Or, it is a file name.
   Make sure it won't overwrite the existing ones on your platform! */
void make_all_dir_created(char *path, size_t start) {
    char *p, *path_new;
    //
    path_new = strdup(path);
    p = path_new + start;
    while (p = strpbrk(p, "\\/"), p) {
        *p = 0;
        p++;
        _mkdir(path_new); // existing or new
        strcpy(path_new, path);
    }
    //
    free(path_new);
}


/* **** */
typedef uint8_t (*BYTE_DECODE_FUN)(uint8_t Byte, uint8_t key);

typedef uint32_t (*DATA_DECODE_FUN)
(
    uint8_t *data,
    uint32_t data_len,
    uint32_t offset, // for shift
    BYTE_DECODE_FUN decode_byte,
    uint8_t *key,
    uint32_t key_len
);

typedef struct DATA_DECODER
{
    uint8_t *key;
    uint32_t key_len;
    BYTE_DECODE_FUN decode_byte;
    DATA_DECODE_FUN decode_data;
    int decode_type;    // 0: every block, 1: full length
}DATA_DECODER, *PDATA_DECODER;

typedef uint32_t (*FILE_DECODE_FUN)(
    FILE *fp_r,
    uint32_t offset,
    uint32_t length,
    uint32_t encoded_block_len,
    DATA_DECODER decode_data,
    FILE *fp_w
);

// get attributes of the new and old format into the same struct
typedef uint32_t (*GET_IS_FILE_ATTRIBUTES_FUN)(
    FILE *fp,
    uint32_t data_offset,
    PIS_FILE_ATTRIBUTES pifa,
    uint32_t type
);


// used by type 'InstallShield' and 'ISSetupStream'
uint8_t *gen_key(uint8_t *seeds, uint32_t len) {
    const uint8_t MAGIC_DEC[4] = {0x13, 0x35, 0x86, 0x07};
    uint32_t i;
    uint8_t *key;
    //
    key = malloc(len);
    for (i = 0; i < len; i++) {
        key[i] = seeds[i] ^ MAGIC_DEC[i % sizeof(MAGIC_DEC)];
    }
    //
    return key;
}

uint8_t decode_byte(uint8_t Byte, uint8_t key) {
    return ~(key ^ (Byte * 16 | Byte >> 4));
}

uint8_t encode_byte(uint8_t Byte, uint8_t key) {
    Byte = key ^ ~Byte;
    return Byte * 16 | Byte >> 4;
}

uint32_t decode_data(
    uint8_t *data,
    uint32_t data_len,
    uint32_t offset, // for new version
    BYTE_DECODE_FUN decode_byte,
    uint8_t *key,
    uint32_t key_len
)
{
    uint32_t i;
    //
    if (key_len <= 0) return 0;
    for (i = 0; i < data_len; i++) {
        data[i] = decode_byte(data[i], key[(i + offset) % key_len]);
    }
    //
    return i;
}

/* stream type
unicode: decode unit 1024, 0x400
Read 16k, as inflate
*/
uint32_t decode_data_ustrm(
    uint8_t *data,
    uint32_t data_len,
    uint32_t offset,
    BYTE_DECODE_FUN decode_byte,
    uint8_t *key,
    uint32_t key_len
)
{
    uint32_t i, decode_start, task_len, left_len, decoded_len, task_end;
    //
    if (key_len <= 0) return 0;
    decoded_len = 0;
    while (decoded_len < data_len) {
        decode_start = (decoded_len + offset) % 1024;
        task_len = 1024 - decode_start;
        left_len = data_len - decoded_len;
        if (task_len > left_len) {task_len = left_len;}
        // decode data
        decode_data(data + decoded_len, task_len, decode_start % key_len, decode_byte, key, key_len);
        //
        decoded_len += task_len;
    };
    //
    return decoded_len;
}

// + just compatitable for substitution
uint32_t decode_file(
    FILE *fp_r,
    uint32_t offset_r,
    uint32_t length,
    uint32_t encoded_block_len,
    FILE *fp_w,
    PDATA_DECODER pdata_decoder
)
{
    uint8_t *pbuffer;
    uint32_t len_read, len_read_i, len_left, len_encoded_done, offset_w;
    int need_decode_data;
    //
    if (length <= 0) { return 0; }
    //
    fseekx(fp_r, offset_r, SEEK_SET);
    need_decode_data = pdata_decoder && pdata_decoder->key_len > 0 && pdata_decoder->decode_data;
    if (need_decode_data) {fprintf(stdout, "* ");}
    else {fprintf(stdout, "  ");}
    //
    len_read = PREFER_BLOCK_SIZE;
    if (len_read > encoded_block_len) {len_read = encoded_block_len;}
    pbuffer = malloc(len_read);
    offset_w = 0;
    while (length > 0) { // length left
        if (len_read > length) { len_read = length; }
        // for big file
        if (encoded_block_len > length) { encoded_block_len = length; }
        len_encoded_done = 0;
        len_read_i = len_read;
        len_left = encoded_block_len;
        while (len_left > 0) {
            len_read_i = fread(pbuffer, 1, len_read_i, fp_r);
            if (need_decode_data) {
                if (pdata_decoder->decode_data(pbuffer, len_read_i, len_encoded_done,
                    pdata_decoder->decode_byte, pdata_decoder->key, pdata_decoder->key_len) != len_read_i) break;
            }
            if (fp_r == fp_w) {fseekx(fp_r, offset_r, SEEK_SET);}
            if (fwrite(pbuffer, 1, len_read_i, fp_w) != len_read_i) break;
            offset_r += len_read_i;
            offset_w += len_read_i;
            len_encoded_done += len_read_i;
            len_left -= len_read_i;
            if (len_read_i > len_left) {len_read_i = len_left;}
        }
        //
        length -= encoded_block_len;
    }
    free(pbuffer);
    //
    fflush(fp_w);
    //
    return offset_r;
}

uint32_t get_is_file_attributes(FILE *fp, uint32_t data_offset, PIS_FILE_ATTRIBUTES pifa, uint32_t type) {
    fseekx(fp, data_offset, SEEK_SET);
    if (fread(pifa, 1, sizeof(IS_FILE_ATTRIBUTES), fp) == sizeof(IS_FILE_ATTRIBUTES)) {
        data_offset += sizeof(IS_FILE_ATTRIBUTES);
    }
    else {
        fseekx(fp, data_offset, SEEK_SET);
    }
    return data_offset;
}

uint32_t get_is_file_attributes_ustrm(FILE *fp, uint32_t data_offset, PIS_FILE_ATTRIBUTES pifa, uint32_t type) {
    IS_FILE_ATTRIBUTES_X is_ax;
    wchar_t file_name_w[_MAX_PATH] = {0};
    char *file_name;
    //
    fseekx(fp, data_offset, SEEK_SET);
    if (fread(&is_ax, 1, sizeof(IS_FILE_ATTRIBUTES_X), fp) == sizeof(IS_FILE_ATTRIBUTES_X)
        && is_ax.filename_len > 0 && is_ax.filename_len < _MAX_PATH * 2
        && (type == 4 ? fseekx(fp, sizeof(IS_FILE_ATTRIBUTES_X), SEEK_CUR) == 0 : 1)
        && fread(file_name_w, 1, is_ax.filename_len, fp) == is_ax.filename_len)
    {
        utf16_to_cs(file_name_w, 65001, &g_Seed);
        if (utf16_to_cs(file_name_w, g_CP, &file_name) > 0) {
            strcpy(pifa->file_name, file_name);
            free(file_name);
        }
        else {
            fprintf(stdout, "File name can't be converted in your environment at:\n");
            sprintf(pifa->file_name, "0x%X", data_offset);
        }
        pifa->encoded_flags = is_ax.encoded_flags;
        pifa->file_len = is_ax.file_len;
        pifa->is_unicode_launcher = is_ax.is_unicode_launcher;
        data_offset = ftellx(fp);
    }
    else {
        fseekx(fp, data_offset, SEEK_SET);
    }
    return data_offset;
}

uint32_t get_is_header(FILE *fp, uint32_t data_offset, PIS_HEADER pis_hdr) {
    fseekx(fp, data_offset, SEEK_SET);
    if (fread(pis_hdr, 1, sizeof(IS_HEADER), fp) == sizeof(IS_HEADER)) {
        if (!strcmp(pis_hdr->SIG, ISSIG) || !strcmp(pis_hdr->SIG, ISSIG_strm)) {
            data_offset += sizeof(IS_HEADER);
        }
    }
    fseekx(fp, data_offset, SEEK_SET);
    return data_offset;
}

uint32_t extract_encrypted_files(FILE *fp, uint32_t data_offset, int n_2trans) {
    IS_HEADER is_hdr;
    IS_FILE_ATTRIBUTES is_file_attr;
    uint32_t offset, file_len, encoded_block_len;
    int g_DestDir_len;
    uint16_t num_files, i;
    // reuse the framework
    GET_IS_FILE_ATTRIBUTES_FUN get_is_file_attributes_fun;
    DATA_DECODE_FUN data_decode_fun;
    //
    offset = get_is_header(fp, data_offset, &is_hdr);
    if (is_hdr.type > 4) {
        return data_offset;
    }
    if (offset <= data_offset) {return data_offset;}
    data_offset = offset;
    //
    encoded_block_len = PREFER_BLOCK_SIZE;
    get_is_file_attributes_fun = get_is_file_attributes;
    data_decode_fun = decode_data;
    if (!strcmp(is_hdr.SIG, ISSIG_strm)) {
        get_is_file_attributes_fun = get_is_file_attributes_ustrm;
        data_decode_fun = decode_data_ustrm;
        encoded_block_len = 0x4000;
    }
    //
    num_files = is_hdr.num_files;
    fprintf(stdout, "Files total: %d\n", num_files);
    fprintf(stdout, "Extracting:\n");
    g_DestDir_len = strlen(g_DestDir);
    for (i = 0; i < num_files; i++) {
        char *seed, *file_name_out;
        DATA_DECODER data_decoder = {0};
        FILE *fp_w;
        int has_type_2_or_4, has_type_4, is_need_inflate;
        uint32_t encoded_block_len_i = encoded_block_len;
        //
        offset = get_is_file_attributes_fun(fp, data_offset, &is_file_attr, is_hdr.type);
        if (offset <= data_offset) {break;}
        data_offset = offset;
        data_offset += is_file_attr.file_len;
        fprintf(stdout, "0x%08X % 10u \"%s\"\n", offset, is_file_attr.file_len, is_file_attr.file_name);
        fprintf(stdout, "% 22c", ' ');
        //
        file_name_out = strdup(g_DestDir);
        file_name_out = strcat_x(file_name_out, is_file_attr.file_name);
        make_all_dir_created(file_name_out, g_DestDir_len);
        //
        fp_w = fopen(file_name_out, "wb+");
        //free(file_name_out);
        if (!fp_w) {
            fprintf(stderr, "Can't create file!\n");
            break;
        }
        //
        is_need_inflate = 0;
        seed = is_file_attr.file_name;
        if (!strcmp(is_hdr.SIG, ISSIG_strm)) {
            seed = g_Seed;
        }
        data_decoder.key_len = strlen(seed);
        data_decoder.key = gen_key(seed, data_decoder.key_len);
        data_decoder.decode_byte = decode_byte;
        // get encoded type
        has_type_2_or_4 = is_file_attr.encoded_flags & 6;
        has_type_4 = is_file_attr.encoded_flags & 4;
        if (has_type_4 && has_type_2_or_4) {
            encoded_block_len_i = 1024;
            data_decoder.decode_data = data_decode_fun;
        }
        //
        fprintf(stdout, "[b] ");
        offset = decode_file(fp, offset, is_file_attr.file_len, encoded_block_len_i, fp_w, &data_decoder);
        if (offset != data_offset) {
            fseekx(fp, data_offset, SEEK_SET);
            fprintf(stdout, "N");
        }
        else {
            fprintf(stdout, "Y");
            //
            // Another round/type by file length as data length
            // >= v10.5 (no n_2trans), n_2trans: v12
            if (n_2trans && !has_type_4 && has_type_2_or_4) {
                fprintf(stdout, " => [f] ");
                // 1st type could be 
                if (!strcmp(is_hdr.SIG, ISSIG_strm)) {
                    data_decode_fun = decode_data; // old method
                }
                else {
                    data_decoder.decode_data = data_decode_fun;
                }
                data_decoder.decode_type = 1;
                //
                offset = decode_file(fp_w, 0, is_file_attr.file_len, is_file_attr.file_len, fp_w, &data_decoder);
                if (offset != is_file_attr.file_len) {
                    fseekx(fp, data_offset, SEEK_SET);
                    fprintf(stdout, "N");
                }
                else {
                    fprintf(stdout, "Y");
                }
            }
            // infalte
            if (is_file_attr.is_unicode_launcher) {
                is_need_inflate = 1;
            }
        }
        //
        fclose(fp_w);
        //
        if (is_need_inflate) {
#ifndef NO_INFLATE
            char *file_name_out_d = NULL;
            //
            fprintf(stdout, " => [inflate] ");
            //
            file_name_out_d = strdup(file_name_out);
            file_name_out_d = strcat_x(file_name_out_d, ".tmp");
            if (inflate_f(file_name_out, file_name_out_d) == 0) {
                if (remove(file_name_out) == 0
                    && rename(file_name_out_d, file_name_out) == 0)
                {
                    fprintf(stdout, "Y\n");
                }
                else {
                    fprintf(stdout, "N!\n");
                }
            }
            // else, error occured, '\n' printed
            free(file_name_out_d);
#else
            fprintf(stdout, "{deflated!}\n");
#endif
        }
        else {
            fprintf(stdout, "\n");
        }
        //
        free(data_decoder.key);
        free(file_name_out);
   }
    return data_offset;
}


/* **** */
uint32_t save_data_to_file(FILE *fp, uint32_t start, uint32_t data_len, char *file_name) {
    char *file_name_out;
    FILE *fp_w;
    uint32_t offset;
    //
    fprintf(stdout, "0x%08X % 10u \"%s\" ... ", start, data_len, file_name);
    file_name_out = strdup(g_DestDir);
    file_name_out = strcat_x(file_name_out, file_name);
    //
    make_all_dir_created(file_name_out, strlen(g_DestDir));
    //
    fp_w = fopen(file_name_out, "wb");
    free(file_name_out);
    if (!fp_w) {
        fprintf(stderr, "Can't open file to write!\n");
        return start;
    }
    //
    offset = decode_file(fp, start, data_len, PREFER_BLOCK_SIZE, fp_w, NULL);
    start += data_len;
    fclose(fp_w);
    if (start != offset) {
        fseekx(fp, data_len, SEEK_SET);
        fprintf(stdout, "N\n");
    }
    else {
        fprintf(stdout, "Y\n");
    }
    //
    return start;
}

typedef struct PLAIN_FILE_ATTRIBUTES
{
    char file_name[_MAX_PATH];
    char file_dest_name[_MAX_PATH];
    char version[32];
    uint32_t file_len;
} PLAIN_FILE_ATTRIBUTES, *PPLAIN_FILE_ATTRIBUTES;

uint32_t get_plain_file_attributes(FILE *fp, uint32_t data_offset, PPLAIN_FILE_ATTRIBUTES ppfa) {
    /*  char range
        https://en.wikipedia.org/wiki/Control_character
        "%[\x20-\xFF]" won't work on win10! "%[^\x0-\x1F]" will stop at blank!
        \x0 doesn't work for ucrt! Use [^\x01-\xFE].
    */
    // in case dumping failed
    fseekx(fp, data_offset, SEEK_SET);
    if (fscanf(fp, "%259[\x20-\xFE]%*[^\x01-\xFE]%259[\x20-\xFE]%*[^\x01-\xFE]%31[\x20-\xFE]%*[^\x01-\xFE]%d%*[^\x01-\xFE]",
        ppfa->file_name, ppfa->file_dest_name, ppfa->version, &ppfa->file_len) == 4)
    {
        return ftellx(fp);
    }
    else {
        fseekx(fp, data_offset, SEEK_SET);
        return data_offset;
    }
}

uint32_t extract_plain_files(FILE *fp, uint32_t data_offset) {
    // ver: 15.0
    uint32_t offset;
    PLAIN_FILE_ATTRIBUTES pa;
    FILE *fp_w;
    //
    while ((offset = get_plain_file_attributes(fp, data_offset, &pa)) > data_offset) {
        data_offset = offset;
        data_offset += pa.file_len; // no mater succeed or not on 1 file
        //
        save_data_to_file(fp, offset, pa.file_len, pa.file_dest_name);
    }
    //
    return data_offset;
}


typedef struct PLAIN_FILE_ATTRIBUTES_W
{
    wchar_t file_name[_MAX_PATH];
    wchar_t file_dest_name[_MAX_PATH];
    wchar_t version[32];
    uint32_t file_len;
} PLAIN_FILE_ATTRIBUTES_W, *PPLAIN_FILE_ATTRIBUTES_W;

uint32_t get_plain_file_attributes_w(FILE *fp, uint32_t data_offset, PPLAIN_FILE_ATTRIBUTES_W ppfa_w) {
    /*  char range
        https://en.wikipedia.org/wiki/Control_character
        "%[^\x0-\x1F]" will stop at blank!
        \xFFFE is BOM
        \x0 doesn't work for ucrt! Use [^\x01-\xFFFE]. \xFFFF blocks msvcrt!
    */
    // in case dumping failed
    fseekx(fp, data_offset, SEEK_SET);
    if (fwscanf(fp, L"%259[\x20-\xFFFD]%*[^\x01-\xFFFE]%259[\x20-\xFFFD]%*[^\x01-\xFFFE]%31[\x20-\xFFFD]%*[^\x01-\xFFFE]%d%*[^\x01-\xFFFE]",
            ppfa_w->file_name, ppfa_w->file_dest_name, ppfa_w->version, &ppfa_w->file_len) == 4)
    {
        return ftellx(fp);
    }
    else {
        fseekx(fp, data_offset, SEEK_SET);
        return data_offset;
    }
}

uint32_t extract_plain_files_w(FILE *fp, uint32_t data_offset) {
    // ver: 
    uint32_t offset, offset_o, num_files;
    PLAIN_FILE_ATTRIBUTES_W pa_w;
    FILE *fp_w;
    char *file_dest_name;
    //
    fread(&num_files, 1, sizeof(uint32_t), fp);
    offset_o = data_offset;
    data_offset += 4;
    //
    while ((offset = get_plain_file_attributes_w(fp, data_offset, &pa_w)) > data_offset) {
        char file_name_new[11]; // preserved for file name that can't be converted
        //
        if (data_offset == offset_o + 4) {
            fprintf(stdout, "Files total: %d\n", num_files);
            fprintf(stdout, "Extracting:\n");
        }
        data_offset = offset;
        data_offset += pa_w.file_len; // no mater succeed or not on 1 file
        //
        if (utf16_to_cs(pa_w.file_dest_name, g_CP, &file_dest_name) == 0) {
            fprintf(stdout, "File name can't be converted in your environment at:\n");
            sprintf(file_name_new, "0x%X", data_offset);
            file_dest_name = file_name_new;
        }
        save_data_to_file(fp, offset, pa_w.file_len, file_dest_name);
        free(file_dest_name);
    }
    //
    return data_offset > offset_o + 4 ? data_offset : offset_o;
}


/* **** */
uint32_t get_data_offset(FILE *fp){
    IMAGE_DOS_HEADER dos_hdr;
    IMAGE_NT_HEADERS32 pe_hdr;
    uint16_t section_n;
    IMAGE_SECTION_HEADER image_section_hdr;
    // pre-test
    fread(&dos_hdr, 1, sizeof(IMAGE_DOS_HEADER), fp);
    if (dos_hdr.e_magic != 0x5A4D) {
        return 0;
    }
    //
    fseekx(fp, dos_hdr.e_lfanew, SEEK_SET);
    fread(&pe_hdr, 1, sizeof(IMAGE_NT_HEADERS32), fp);
    if (pe_hdr.Signature != 0x4550) {
        return 0;
    }
    // pure 64-bit installers
    switch (pe_hdr.FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_I386:
        break;
    case IMAGE_FILE_MACHINE_AMD64:
    case 0xAA64: // IMAGE_FILE_MACHINE_ARM64
        fseekx(fp, sizeof(IMAGE_NT_HEADERS64) - sizeof(IMAGE_NT_HEADERS32), SEEK_CUR);
        break;
    default:
        // Haven't seen any.
        break;
    }
    // goto the last section table
    fseekx(fp, (pe_hdr.FileHeader.NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER), SEEK_CUR);
    fread(&image_section_hdr, 1, sizeof(IMAGE_SECTION_HEADER), fp);
    //
    return image_section_hdr.PointerToRawData + image_section_hdr.SizeOfRawData;
}


/* **** */
void help(){
    fprintf(stderr, "InstallShield file extractor v%s @YX Hao\n", g_Ver);
    fprintf(stderr, "Usage: %s <InstallShield file> [output dir]\n", __argv[0]);
}


/* **** */
int main(int argc, char **argv) {
    FILE *fp = NULL;
    char version_sig[8];
    uint32_t data_offset, data_offset_x, data_len, total_len;
    int n_2trans, ret, n_tmp;
    char *filename;
    char drive[_MAX_DRIVE], ext[_MAX_EXT];
    char *dir = NULL, *fname = NULL, *launcher_name = NULL;
    //
    char MBCP[8] = "";
    //
    g_CP = _getmbcp();
    if (g_CP > 0) sprintf(MBCP, ".%d", g_CP);
    setlocale(LC_ALL, MBCP);
    //
    n_2trans = 1;
    ret = 0;
    //
    if (argc < 2) {
        help();
        goto error;
    }
    //
    filename = argv[1];
    fprintf(stdout, "%s\n", filename);
    fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Can't open file!\n");
        goto error;
    }
    //
    total_len = _filelength(fileno(fp)); // works when greater than 2GB
    data_offset = get_data_offset(fp);
    if (data_offset <= 0) {
        fprintf(stderr, "Not-pe-file!\n");
        goto error;
    }
    if (data_offset >= total_len) {
        fprintf(stdout, "No extra data found!\n");
        goto cleanup;
    }
    fprintf(stdout, "0x%08X\n", data_offset);
    //
    n_tmp = strlen(filename);
    dir = malloc(n_tmp);
    fname = malloc(n_tmp);
    _splitpath(filename, drive, dir, fname, ext);
    //
    if (argc < 3) {
        g_DestDir = calloc(n_tmp - strlen(ext) + 1, 1);
        _makepath(g_DestDir, drive, dir, fname, NULL);
        g_DestDir = strcat_x(g_DestDir, "_u\\"); // in case of no ext
        g_DestDir = g_DestDir;
    }
    else {
        g_DestDir = strdup(argv[2]);
        g_DestDir = strcat_x(g_DestDir, "\\");
    }
    make_all_dir_created(g_DestDir, 0);
    //
    launcher_name = strdup(fname);
    launcher_name = strcat_x(launcher_name, "_sfx");
    launcher_name = strcat_x(launcher_name, ext);
    //
    fprintf(stdout, "Dir: \"%s\"\n", g_DestDir);
    //
    save_data_to_file(fp, 0, data_offset, launcher_name);
    //
    // start with some string
    // skip the rubbish? 2009/2010
    fseekx(fp, data_offset, SEEK_SET);
    if (fscanf(fp, "%7[\x20-\xFE]%*[^\x01-\xFE]%*[\x01-\xFE]%*[^\x01-\xFE]%*[\x20-\xFE]%*[^\x01-\xFE]", version_sig) == 1) {
        if (strcmp(version_sig, "NB10") == 0) {
            data_offset = ftellx(fp);
        }
    }
    //
    // try different types
    //
    fseekx(fp, data_offset, SEEK_SET);
    //
    // most
    if ((data_offset_x = extract_encrypted_files(fp, data_offset, n_2trans)) > data_offset) {goto check_extra;}
    // try unicode
    /* Special case:
        Offset      0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F
        000C4E00   54 00 00 00 30 00 78 00  30 00                     T   0 x 0 
    */
    // unicode version: 0C000000, and wide attibute strings
    if ((data_offset_x = extract_plain_files_w(fp, data_offset)) > data_offset) {goto check_extra;}
    // plain
    if ((data_offset_x = extract_plain_files(fp, data_offset)) > data_offset) {
        fprintf(stderr, "Unrecognized version installer!\n");
        goto check_extra;
    }
    //
    // try different types end
    //
check_extra:
    data_len = total_len - data_offset_x;
    //
    if (data_len > 0) { // feof <> 100%
        char *file_name_out;
        //
        fprintf(stdout, "Extra data:\n");
        file_name_out = strdup(fname);
        file_name_out = strcat_x(file_name_out, "_ext.bin");
        //
        save_data_to_file(fp, data_offset_x, data_len, file_name_out);
        free(file_name_out);
    }
    //
cleanup:
    free(dir);
    free(fname);
    free(launcher_name);
    free(g_DestDir);
    if (fp) fclose(fp);
    //
    return ret;
    //
error:
    ret = 1;
    goto cleanup;
}
