
/*
Starting sig:
read 0x2E, 46;
Offset      0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F
0004C000   49 6E 73 74 61 6C 6C 53  68 69 65 6C 64 00 07 00   InstallShield...

Trace:
WriteFile
ReadFile
CloseHandle
SetFilePointer
MapViewOfFile

Decryption methods:
plain:  no encryption, first file is 'data1.cab'
M1024:  every block size 1024, 7 files
Mfile:  full file size, found in v12/v10.5, not DevStudio 9
Mmis:   leading data
inflate: zlib inlate, flaged unicode, > v12, not v10.5

zlib:
deflate 1.2.3 Copyright 1995-2005 Jean-loup Gailly
inflate 1.2.3 Copyright 1995-2005 Mark Adler
http://www.zlib.net/manual.html
https://github.com/richgel999/miniz

history versions:
https://www.flexera.com/producer/support/additional-support/end-of-life/installshield.html
Application                         Version 'General Availability'  Methods
InstallShield 2016                  23      2016-08                 <ISSetupStream>
InstallShield 2015                  22      2015-06
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
DevStudio 9                         9       2003-09

InstallShield DevStudio - Ver 9.0
InstallShield Developer 8 - Ver 8.0
InstallShield Developer 7 - Ver 7.0
InstallShield 6.x - Ver 6.2»ò6.3
InstallShield 5.1 - Ver 5.1

Launcher location:
setup.exe
program files\Macrovision\IS2008\Redist\Language Independent\i386\
program files\InstallShield\2011\Redist\Language Independent\i386\
program files\InstallShield\2011\Redist\Language Independent\i386\ISP\:
plain, file name could be unicode
setupPreReq.exe

Re-package:
ReleasePackager.exe
Or you can make them to other sfx installer.

Cab viewer:
IsCabView.exe
MediaBuild??.dll
ToolkitPro1331vc90U.dll (Xtreme Toolkit Pro Library, UI)

InstallShield Script Compiler:
compiler.exe
compiler.dll
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <direct.h>

#if defined(_MSC_VER) || defined(WINVER)
#include <windows.h>
#else
// the header you need
#endif


/* **** */
char *g_DestDir;
char *g_Ver = "0.1.0 #20171221";


/* **** */
/* header
Following PE file's last section.
len: 46, 0x2E
*/
char *ISSIG = "InstallShield";

// new formats
char *ISSIG_2016 = "ISSetupStream";

typedef struct IS_HEADER
{
    char SIG[14];
    unsigned short num_files;
    unsigned char x3[30];
} IS_HEADER, *PIS_HEADER;

/* file attributes
len: 312, 0x138
extra data?
*/
typedef struct IS_FILE_ATTRIBUTES
{
    char file_name[260]; // MAX_PATH
    unsigned long encoded_flags; // encoded: 0x2|0x4 for num_files = 7, 0x2 for 5
    unsigned long x3;
    unsigned long file_len;
    unsigned char x5[8];
    unsigned short is_unicode_launcher;
    unsigned char x7[30];
} IS_FILE_ATTRIBUTES, *PIS_FILE_ATTRIBUTES;


/* **** */
char *strcat_x(char *path, char *ext_path) {
    path = realloc(path, strlen(path) + strlen(ext_path) + 1);
    return strcat(path, ext_path);
}

/* Make sure it won't overwrite the existing ones in your environment! */
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
typedef unsigned char (*BYTE_DECODE_FUN)(unsigned char Byte, unsigned char key);

typedef unsigned long (*DATA_DECODE_FUN)
(
    unsigned char *data,
    unsigned long data_len,
    BYTE_DECODE_FUN decode_byte,
    unsigned char *key,
    unsigned long key_len
);

typedef struct DATA_DECODER
{
    unsigned char *key;
    unsigned long key_len;
    BYTE_DECODE_FUN decode_byte;
    DATA_DECODE_FUN decode_data;
}DATA_DECODER, *PDATA_DECODER;

typedef unsigned long *FILE_DECODE_FUN(
    FILE *fp_r,
    unsigned long offset,
    unsigned long length,
    unsigned long encoded_len,
    DATA_DECODER decode_data,
    FILE *fp_w
);

unsigned char *gen_key(unsigned char *seeds, unsigned long len) {
    const unsigned char MAGIC_DEC[4] = {0x13, 0x35, 0x86, 0x07};
    unsigned long i;
    unsigned char *key;
    //
    key = malloc(len);
    for (i = 0; i < len; i++) {
        key[i] = seeds[i] ^ MAGIC_DEC[i % sizeof(MAGIC_DEC)];
    }
    //
    return key;
}

unsigned char decode_byte(unsigned char Byte, unsigned char key) {
    return ~(key ^ (Byte * 16 | Byte >> 4));
}

unsigned char encode_byte(unsigned char Byte, unsigned char key) {
    Byte = key ^ ~Byte;
    return Byte * 16 | Byte >> 4;
}

unsigned long decode_data(
    unsigned char *data,
    unsigned long data_len,
    BYTE_DECODE_FUN decode_byte,
    unsigned char *key,
    unsigned long key_len
)
{
    unsigned long i;
    //
    if (key_len <= 0) return 0;
    for (i = 0; i < data_len; i++) {
        data[i] = decode_byte(data[i], key[i % key_len]);
    }
    //
    return i;
}

unsigned long decode_file(
    FILE *fp_r,
    unsigned long offset,
    unsigned long length,
    unsigned long encoded_len,
    FILE *fp_w,
    PDATA_DECODER pdata_decoder
)
{
    unsigned char *pbuffer;
    long len_read;
    //
    if (length <= 0) { return 0; }
    //
    fseek(fp_r, offset, SEEK_SET);
    pbuffer = malloc(encoded_len);
    while (length > 0) { // length left
        if (encoded_len > length) { encoded_len = length; }
        len_read = fread(pbuffer, 1, encoded_len, fp_r);
        if (pdata_decoder && pdata_decoder->key_len > 0 && pdata_decoder->decode_data) {
            if (pdata_decoder->decode_data(pbuffer, len_read, pdata_decoder->decode_byte,
                pdata_decoder->key, pdata_decoder->key_len) != len_read) break;
        }
        if (fp_r == fp_w) {fseek(fp_r, offset, SEEK_SET);}
        if (fwrite(pbuffer, 1, len_read, fp_w) != len_read) break;
        offset = ftell(fp_r);
        length -= len_read;
    }
    free(pbuffer);
    //
    fflush(fp_w);
    //
    return offset;
}

unsigned long get_is_file_attributes(FILE *fp, unsigned long data_offset, PIS_FILE_ATTRIBUTES pifa) {
    fseek(fp, data_offset, SEEK_SET);
    if (fread(pifa, 1, sizeof(IS_FILE_ATTRIBUTES), fp) == sizeof(IS_FILE_ATTRIBUTES)) {
        data_offset += sizeof(IS_FILE_ATTRIBUTES);
    }
    else {
        fseek(fp, data_offset, SEEK_SET);
    }
    return data_offset;
}

unsigned long get_is_header(FILE *fp, unsigned long data_offset, PIS_HEADER pis_hdr) {
    fseek(fp, data_offset, SEEK_SET);
    if (fread(pis_hdr, 1, sizeof(IS_HEADER), fp) == sizeof(IS_HEADER)) {
        if (!strcmp(pis_hdr->SIG, ISSIG)) {
            data_offset += sizeof(IS_HEADER);
        }
    }
    else {
        fseek(fp, data_offset, SEEK_SET);
    }
    return data_offset;
}

unsigned long extract_encrypted_files(FILE *fp, unsigned long data_offset, int n_2trans) {
    IS_HEADER is_hdr;
    IS_FILE_ATTRIBUTES is_file_attr;
    unsigned long offset, file_len, encoded_len;
    int is_encrypted, g_DestDir_len;
    unsigned short num_files, i;
    //
    offset = get_is_header(fp, data_offset, &is_hdr);
    if (offset <= data_offset) {return data_offset;}
    data_offset = offset;
    //
    num_files = is_hdr.num_files;
    fprintf(stdout, "files total: %d\n", num_files);
    fprintf(stdout, "extracting:\n");
    g_DestDir_len = strlen(g_DestDir);
    for (i = 0; i < num_files; i++) {
        char *file_name, *file_name_out;
        DATA_DECODER data_decoder = {0};
        FILE *fp_w;
        int has_type_2_or_4, has_type_4;
        //
        offset = get_is_file_attributes(fp, data_offset, &is_file_attr);
        if (offset <= data_offset) {break;}
        data_offset = offset;
        data_offset += is_file_attr.file_len;
        fprintf(stdout, "[0x%08X] [% 12u] %s ... ", offset, is_file_attr.file_len, is_file_attr.file_name);
        //
        file_name_out = strdup(g_DestDir);
        file_name_out = strcat_x(file_name_out, is_file_attr.file_name);
        make_all_dir_created(file_name_out, g_DestDir_len);
        //
        fp_w = fopen(file_name_out, "wb+");
        free(file_name_out);
        if (!fp_w) {
            fprintf(stderr, "can't create file!\n");
            break;
        }
        //
        // get encoded type
        encoded_len = 4096; // 4k for high speed
        is_encrypted = 0;
        has_type_2_or_4 = is_file_attr.encoded_flags & 6;
        has_type_4 = is_file_attr.encoded_flags & 4;
        if (has_type_4 && has_type_2_or_4) {
            is_encrypted = 1;
        }
        //
        if (is_encrypted) {
            encoded_len = 1024;
            data_decoder.key_len = strlen(is_file_attr.file_name);
            data_decoder.key = gen_key(is_file_attr.file_name, data_decoder.key_len);
            data_decoder.decode_byte = decode_byte;
            data_decoder.decode_data = decode_data;
        }
        //
        fprintf(stdout, ">>> ");
        offset = decode_file(fp, offset, is_file_attr.file_len, encoded_len, fp_w, &data_decoder);
        if (offset != data_offset) {
            fseek(fp, data_offset, SEEK_SET);
            fprintf(stdout, "N\n");
        }
        else {
            fprintf(stdout, "Y");
            //
            // Another round/type by file length as data length
            // >= v10.5 (no n_2trans), n_2trans: v12
            if (n_2trans && !has_type_4 && has_type_2_or_4) {
                fprintf(stdout, " >>> ");
                offset = decode_file(fp_w, 0, is_file_attr.file_len,
                                    is_file_attr.file_len, fp_w, &data_decoder);
                if (offset != data_offset) {
                    fseek(fp, data_offset, SEEK_SET);
                    fprintf(stdout, "N");
                }
                else {
                    fprintf(stdout, "Y");
                }
            }
            // infalte
            if (is_file_attr.is_unicode_launcher) {
                fprintf(stdout, " {deflated!}");
            }
            //
            fprintf(stdout, "\n");
        }
        //
        fclose(fp_w);
   }
    return i;
}


/* **** */
unsigned long save_data_to_file(FILE *fp, unsigned long start, unsigned long data_len, char *file_name) {
    char *file_name_out;
    FILE *fp_w;
    unsigned long offset;
    //
    file_name_out = strdup(g_DestDir);
    file_name_out = strcat_x(file_name_out, file_name);
    //
    make_all_dir_created(file_name_out, strlen(g_DestDir));
    //
    fp_w = fopen(file_name_out, "wb");
    free(file_name_out);
    if (!fp_w) {
        fprintf(stderr, "can't open file to write!\n");
        return start;
    }
    fprintf(stdout, "[0x%08X] [% 12u] %s ... ", start, data_len, file_name);
    //
    fprintf(stdout, ">>> ");
    offset = decode_file(fp, start, data_len, 4096, fp_w, NULL);
    start += data_len;
    fclose(fp_w);
    if (start != offset) {
        fseek(fp, data_len, SEEK_SET);
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
    char file_name[MAX_PATH];
    char file_dest_name[MAX_PATH];
    char version[32];
    unsigned long file_len;
} PLAIN_FILE_ATTRIBUTES, *PPLAIN_FILE_ATTRIBUTES;

unsigned long get_plain_file_attributes(FILE *fp, unsigned long data_offset, PPLAIN_FILE_ATTRIBUTES ppfa) {
    fseek(fp, data_offset, SEEK_SET);
    // "%[\x20-\xFF]" won't work on win10! "%[^\x0-\x1F]" will stop at blank!
    if (fscanf(fp, "%[\x20-\xFE]%*\x0%[\x20-\xFE]%*\x0%[\x20-\xFE]%*\x0%d%*\x0",
        ppfa->file_name, ppfa->file_dest_name, ppfa->version, &ppfa->file_len) == 4)
    {
        return ftell(fp);
    }
    else {
        fseek(fp, data_offset, SEEK_SET);
        return data_offset;
    }
}

unsigned long extract_plain_files(FILE *fp, unsigned long data_offset) {
    // ver: 15.0
    unsigned long offset;
    PLAIN_FILE_ATTRIBUTES pa;
    FILE *fp_w;
    //
    fseek(fp, data_offset, SEEK_SET);
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


/* **** */
unsigned long get_data_offset(FILE *fp){
    IMAGE_DOS_HEADER dos_hdr;
    IMAGE_NT_HEADERS pe_hdr;
    unsigned short section_n;
    IMAGE_SECTION_HEADER image_section_hdr;
    // pre-test
    fread(&dos_hdr, 1, sizeof(IMAGE_DOS_HEADER), fp);
    if (dos_hdr.e_magic != 0x5A4D) {
        return 0;
    }
    //
    fseek(fp, dos_hdr.e_lfanew, SEEK_SET);
    fread(&pe_hdr, 1, sizeof(IMAGE_NT_HEADERS), fp);
    if (pe_hdr.Signature != 0x4550) {
        return 0;
    }
    // goto the last section table
    fseek(fp, (pe_hdr.FileHeader.NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER), SEEK_CUR);
    fread(&image_section_hdr, 1, sizeof(IMAGE_SECTION_HEADER), fp);
    //
    return image_section_hdr.PointerToRawData + image_section_hdr.SizeOfRawData;
}


/* **** */
void help(){
    fprintf(stderr, "InstallShield file extractor v%s @YX Hao\n", g_Ver);
    fprintf(stderr, "Usage: %s <InstallShield file>\n", __argv[0]);
}


/* **** */
int main(int argc, char **argv) {
    FILE *fp;
    char version_sig[MAX_PATH];
    unsigned long data_offset, data_len, total_len;
    int n_2trans, ret;
    char drive[_MAX_DRIVE], dir[_MAX_DIR], fname[_MAX_FNAME], ext[_MAX_EXT];
    char *launcher_name;
    //
    n_2trans = 1;
    ret = 0;
    fp = NULL;
    //
    if (argc < 2) {
        help();
        goto error;
    }
    //
    fprintf(stdout, "%s\n", argv[1]);
    fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "Can't open file!\n");
        goto error;
    }
    //
    total_len = _filelength(fileno(fp));
    data_offset = get_data_offset(fp);
    if (data_offset <= 0) {
        fprintf(stderr, "Not-pe-file!\n");
        goto error;
    }
    if (data_offset >= total_len) {
        fprintf(stdout, "no extra data found!\n");
        goto cleanup;
    }
    fprintf(stdout, "[0x%08X]\n", data_offset);
    //
    _splitpath(argv[1], drive, dir, fname, ext);
    g_DestDir = calloc(strlen(argv[1]) - strlen(ext) + 1, 1);
    _makepath(g_DestDir, drive, dir, fname, NULL);
    g_DestDir = strcat_x(g_DestDir, "_u\\"); // in case of no ext
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
    // skip the rubbish? 2009/2010, gnutools-arm-elf-4.6.0.exe
    fseek(fp, data_offset, SEEK_SET);
    if (fscanf(fp, "%[\x20-\xFE]%*[\x0]%*[\x01-\xFE]%*[\x0]%*[\x20-\xFE]%*[\x0]", version_sig) != 1) {
        fprintf(stderr, "unrecgnized file type!\n");
        goto error;
    }
    if (strcmp(version_sig, "NB10") == 0) {
        data_offset = ftell(fp);
        //n_2trans = 1;
    }
    //
    // try different types
    //
    fseek(fp, data_offset, SEEK_SET);
    // try plain 1st
    if (extract_plain_files(fp, data_offset) > data_offset) {goto check_extra;}
    // most
    if (extract_encrypted_files(fp, data_offset, n_2trans) > data_offset) {goto check_extra;}
    //
    // try different types end
    //
check_extra:
    data_offset = ftell(fp);
    data_len = total_len - data_offset;
    //
    if (data_len > 0) { // feof <> 100%
        char *file_name_out;
        //
        fprintf(stdout, "extra data:\n");
        file_name_out = strdup(fname);
        file_name_out = strcat_x(file_name_out, "_ext");
        file_name_out = strcat_x(file_name_out, ext);
        //
        save_data_to_file(fp, data_offset, data_len, file_name_out);
        free(file_name_out);
    }
    //
cleanup:
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
