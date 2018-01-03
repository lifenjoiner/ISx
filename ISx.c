
/*
Starting sig:
read 0x2E, 46;
Offset      0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F
0004C000   49 6E 73 74 61 6C 6C 53  68 69 65 6C 64 00 07 00   InstallShield...

Trace:
WriteFile
ReadFile
CloseHandle


Decryption methods
plain:  no encryption, first file is 'data1.cab'
M1024:  every block size 1024, 7 files
Mfile:  full file size, 9 files
Mmis:   leading data

history versions:
https://www.flexera.com/producer/support/additional-support/end-of-life/installshield.html
Application                         Version 'General Availability'  Methods
InstallShield 2016                  23      2016-08                 <ISSetupStream>
InstallShield 2015                  22      2015-06
InstallShield 2014                  21      2014-05
InstallShield 2013                  20      2013-06
InstallShield 2012 Spring           19      2012-05
InstallShield 2012                  18      2011-08
InstallShield 2011                  17      2010-07                 Unicode Pro: M1024 + Mfile, has '.isc' file
InstallShield 2010                  16      2009-07                 Unicode Pro: M1024 + Mfile, has '.isc' file
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

char *g_DestDir;
char *g_Ver = "0.1.0 #20171221";

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
} IS_HEADER, PIS_HEADER;


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
    unsigned char x5[40];
} IS_FILE_ATTRIBUTES, *PIS_FILE_ATTRIBUTES;


/**/
char *strcat_x(char *path, char *ext_path) {
    path = realloc(path, strlen(path) + strlen(ext_path) + 1);
    return strcat(path, ext_path);
}

char *get_parent_path(char *path) {
    int len, i;
    char *parent_path, *p;
    //
    len = strlen(path);
    for (i = len; i > 0; i--) {
        if (path[i] == '/' || path[i] == '\\') {
            parent_path = malloc(i);
        }
    }
    //
    return strdup(path);
}

/* Make sure it won't overwrite the existing ones in your environment! */
void make_all_dir_created(char *path) {
    char *p, *path_new;
    //
    path_new = strdup(path);
    p = path_new;
    while (p = strpbrk(p, "\\/"), p) {
        *p = 0;
        p++;
        _mkdir(path_new);// existing or new
        strcpy(path_new, path);
    }
    //
    free(path_new);
}


/**/
unsigned char *get_decode_keys(char *seeds, long len) {
    const unsigned char MAGIC_DEC[4] = {0x13, 0x35, 0x86, 0x07};
    long i;
    unsigned char *keys;
    //
    keys = malloc(len);
    for (i = 0; i < len; i++) {
        keys[i] = seeds[i] ^ MAGIC_DEC[i % sizeof(MAGIC_DEC)];
    }
    //
    return keys;
}

unsigned char decode_byte_by_keys(unsigned char Byte, unsigned char key) {
    return ~(key ^ (Byte * 16 | Byte >> 4));
}

/* do it on small/limited blocks */
long decode_data_by_keys(unsigned char *data, long data_len, unsigned char *keys, long keys_len) {
    long i;
    //
    if (!keys) return 0;
    for (i = 0; i < data_len; i++) {
        data[i] = decode_byte_by_keys(data[i], keys[i % keys_len]);
    }
    //
    return i;
}

/* do it on small/limited blocks */
unsigned long transform_file_by_offset_length_seeds(
    FILE *fp_r,
    unsigned long offset, unsigned long length,
    unsigned long types,
    unsigned char *decode_keys, unsigned long keys_len,
    FILE *fp_w
)
{
    unsigned char *pbuffer;
    int is_encrypted_block;
    long len_to_read, len_read, len_left, len_got, i;
    //
    if (length <= 0) { return 0; }
    //
    len_left = length;
    /* encoded type: ISWI\7.0 */
    if (types == 2) {
        // ver: DevStudio 9
        len_to_read = len_left;
        is_encrypted_block = 1;
    }
    else if (types == 6) {
        // ver: 12, 10.5
        len_to_read = 1024;
        is_encrypted_block = 1;
    }
    else { // just dump
        // ver: 12 EVALUATION VERSION
        len_to_read = 1024;
        is_encrypted_block = 0;
        fprintf(stdout, ">>> ");
    }
    //
    fseek(fp_r, offset, SEEK_SET);
    pbuffer = malloc(len_to_read);
    len_got = 0;
    while (len_left > 0) {
        if (len_to_read > len_left) { len_to_read = len_left; }
        len_read = fread(pbuffer, 1, len_to_read, fp_r);
        if (is_encrypted_block) {
            if (decode_data_by_keys(pbuffer, len_read, decode_keys, keys_len) != len_read) break;
        }
        if (fwrite(pbuffer, 1, len_read, fp_w) != len_read) break;
        len_left -= len_read;
    }
    free(pbuffer);
    //
    fflush(fp_w);
    //
    if (len_left > 0) {
        fprintf(stderr, "can't access completely!\n");
        return 0;
    }
    //
    return length;
}

/* do it on small/limited blocks */
unsigned long extract_file_by_attributes(
    FILE *fp, unsigned long data_offset, int n_2trans,
    PIS_FILE_ATTRIBUTES pis_file_attributes
)
{
    unsigned char *decode_keys, *pbuffer;
    long keys_len;
    char *file_name, *file_name_out;
    long len_to_read;
    FILE *fp_w;
    //
    file_name = pis_file_attributes->file_name;
    if (!*file_name || pis_file_attributes->file_len <= 0) {return 0;}
    //
    file_name_out = strdup(g_DestDir);
    file_name_out = strcat_x(file_name_out, "\\");
    file_name_out = strcat_x(file_name_out, file_name);
    make_all_dir_created(file_name_out);
    fprintf(stdout, "[0x%08X] [% 12u] %s ... ", data_offset, pis_file_attributes->file_len, file_name);
    //
    keys_len = strlen(file_name);
    decode_keys = get_decode_keys(file_name, keys_len);
    //
    fp_w = fopen(file_name_out, "wb+");
    free(file_name_out);
    if (!fp_w) {
        fprintf(stderr, "can't open file to write!\n");
        return 0;
    }
    //
    fprintf(stdout, "[1]-> ");
    len_to_read = pis_file_attributes->file_len;
    if (len_to_read != transform_file_by_offset_length_seeds(
                        fp, data_offset, len_to_read,
                        pis_file_attributes->encoded_flags,
                        decode_keys, keys_len, fp_w)) {return 0;}
    //
    // Another round by file length as data length
    if (n_2trans) {
        fprintf(stdout, "[2]-> ");
        rewind(fp_w);
        if (len_to_read != transform_file_by_offset_length_seeds(
                            fp_w, data_offset, len_to_read,
                            2,
                            decode_keys, keys_len, fp_w)) {return 0;}
    }
    fclose(fp_w);
    fprintf(stdout, "OK\n");
    //
    return len_to_read;
}

unsigned short extract_encrypted_files(FILE *fp, unsigned short num_files, unsigned long data_offset, int n_2trans) {
    IS_FILE_ATTRIBUTES is_file_attr;
    unsigned long file_len;
    unsigned short i;
    //
    fprintf(stdout, "extracting:\n");
    for (i = 0; i < num_files; i++) {
        fseek(fp, data_offset, SEEK_SET);
        if (fread(&is_file_attr, 1, sizeof(IS_FILE_ATTRIBUTES), fp) != sizeof(IS_FILE_ATTRIBUTES)) {
            fprintf(stderr, "file corrupted!\n");
            break;
        }
        //
        data_offset += sizeof(IS_FILE_ATTRIBUTES);
        file_len = extract_file_by_attributes(fp, data_offset, n_2trans, &is_file_attr);
        if (file_len <= 0) {
            break;
        }
        data_offset += file_len;
    }
    return i;
}

/**/
unsigned short extract_plain_files(FILE *fp, unsigned long data_offset) {
    // ver: 15.0
    char *file_name, *file_dest_name, version[32];
    unsigned long file_len;
    char *file_name_out;
    FILE *fp_w;
    //
    fseek(fp, data_offset, SEEK_SET);
    //
    file_name = malloc(MAX_PATH);
    file_dest_name = malloc(MAX_PATH);
    // "%[\x20-\xFF]" won't work on win10! "%[^\x0-\x1F]" will stop at blank!
    //while (fscanf(fp, "%[^\x0-\x1F]%*\x0%[^\x0-\x1F]%*\x0%[^\x0-\x1F]%*\x0%d%*\x0",
    while (fscanf(fp, "%[\x20-\xFE]%*\x0%[\x20-\xFE]%*\x0%[\x20-\xFE]%*\x0%d%*\x0",
                       file_name, file_dest_name, version, &file_len) == 4)
   {
        //
        data_offset = ftell(fp);
        fprintf(stdout, "[0x%08X] [% 12u] %s ... ", data_offset, file_len, file_dest_name);
        file_name_out = strdup(g_DestDir);
        file_name_out = strcat_x(file_name_out, "\\");
        file_name_out = strcat_x(file_name_out, file_dest_name);
        //
        make_all_dir_created(file_name_out);
        //
        fp_w = fopen(file_name_out, "wb");
        free(file_name_out);
        if (!fp_w) {
            fprintf(stderr, "can't open file to write!\n");
            return 1;
        }
        //
        if (file_len != transform_file_by_offset_length_seeds(
                        fp, data_offset, file_len, 0,
                        NULL, 0, fp_w)) {return 0;}
        //
        fclose(fp_w);
        fprintf(stdout, "OK\n");
    }
    //
    free(file_name);
    free(file_dest_name);
    //
    return 0;
}


/**/
unsigned long save_lancher(FILE *fp, unsigned long data_offset, char *file_name) {
    FILE *fp_w;
    char *file_name_out;
    //
    file_name_out = strdup(g_DestDir);
    file_name_out = strcat_x(file_name_out, "\\");
    file_name_out = strcat_x(file_name_out, file_name);
    make_all_dir_created(file_name_out);
    //
    fp_w = fopen(file_name_out, "wb");
    free(file_name_out);
    if (!fp_w) {
        fprintf(stderr, "can't open file to write!\n");
        return 0;
    }
    //
    fprintf(stdout, "[0x%08X] [% 12u] %s ... ", 0, data_offset, file_name);
    transform_file_by_offset_length_seeds(
        fp, 0, data_offset, 0,
        NULL, 0, fp_w);
    fclose(fp_w);
    fprintf(stdout, "OK\n");
    // in case save data failed
    fseek(fp, data_offset, SEEK_SET);
    return data_offset;
}

unsigned long save_extra_data(FILE *fp, unsigned long data_offset, unsigned long data_len, char *file_name) {
    char *file_name_out;
    FILE *fp_w;
    //
    file_name_out = strdup(g_DestDir);
    file_name_out = strcat_x(file_name_out, "\\");
    file_name_out = strcat_x(file_name_out, file_name);
    //
    make_all_dir_created(file_name_out);
    //
    fp_w = fopen(file_name_out, "wb");
    free(file_name_out);
    if (!fp_w) {
        fprintf(stderr, "can't open file to write!\n");
        return 1;
    }
    fprintf(stdout, "[0x%08X] [% 12u] %s ... ", data_offset, data_offset, file_name);
    //
    data_len = transform_file_by_offset_length_seeds(
                fp, data_offset, data_len,
                0, NULL, 0, fp_w);
    fclose(fp_w);
    fprintf(stdout, "OK\n");
    //
    return data_len;
}

/**/
unsigned long get_data_offset(FILE *fp){
    IMAGE_DOS_HEADER dos_hdr;
    IMAGE_NT_HEADERS pe_hdr;
    unsigned short section_n;
    IMAGE_SECTION_HEADER image_section_hdr;
    //
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
    //
    // goto the last section table
    fseek(fp, (pe_hdr.FileHeader.NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER), SEEK_CUR);
    fread(&image_section_hdr, 1, sizeof(IMAGE_SECTION_HEADER), fp);
    //
    return image_section_hdr.PointerToRawData + image_section_hdr.SizeOfRawData;
}

/**/
void help(){
    fprintf(stderr, "InstallShield file extractor v%s @YX Hao\n", g_Ver);
    fprintf(stderr, "Usage: %s <InstallShield file>\n", __argv[0]);
}

/**/
int main(int argc, char **argv) {
    FILE *fp;
    char version_sig[MAX_PATH];
    char drive[_MAX_DRIVE], dir[_MAX_DIR], fname[_MAX_FNAME], ext[_MAX_EXT];
    char *launcher_name;
    unsigned long data_offset, data_len;
    IS_HEADER is_hdr;
    int n_2trans, ret;
    //
    n_2trans = 0;
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
    data_offset = get_data_offset(fp);
    fprintf(stdout, "[0x%08X]\n", data_offset);
    if (data_offset <= 0) {
        fprintf(stderr, "Not-pe-file!\n");
        goto error;
    }
    //
    _splitpath(argv[1], drive, dir, fname, ext);
    g_DestDir = calloc(strlen(argv[1]) - strlen(ext) + 1, 1);
    _makepath(g_DestDir, drive, dir, fname, NULL);
    g_DestDir = strcat_x(g_DestDir, "_u"); // in case of no ext
    launcher_name = strdup(fname);
    launcher_name = strcat_x(launcher_name, "_sfx");
    launcher_name = strcat_x(launcher_name, ext);
    //
    fprintf(stdout, "Dir: \"%s\"\n", g_DestDir);
    //
    save_lancher(fp, data_offset, launcher_name);
    //
    fseek(fp, data_offset, SEEK_SET);
    if (fscanf(fp, "%[\x20-\xFE]%*[\x0]%*[\x01-\xFE]%*[\x0]%*[\x20-\xFE]%*[\x0]", version_sig) != 1) {
        fprintf(stderr, "unrecgnized file type!\n");
        goto error;
    }
    //
    // skip the rubbish? 2009/2010, gnutools-arm-elf-4.6.0.exe
    if (strcmp(version_sig, "NB10") == 0) {
        data_offset = ftell(fp);
        n_2trans = 1;
    }
    //
    fseek(fp, data_offset, SEEK_SET);
    if (fread(&is_hdr, 1, sizeof(IS_HEADER), fp) < sizeof(IS_HEADER)) {
        fprintf(stderr, "not-complete-file?!\n");
        goto error;
    }
    //
    if (!strcmp(is_hdr.SIG, ISSIG)) {
        fprintf(stdout, "files total: %d\n", is_hdr.num_files);
        data_offset += sizeof(IS_HEADER);
        extract_encrypted_files(fp, is_hdr.num_files, data_offset, n_2trans) == is_hdr.num_files;
    }
    else {
        //
        fprintf(stdout, "trying as plain type ...\n");
        extract_plain_files(fp, data_offset);
    }
    //
    fprintf(stdout, "[0x%08X]\n", data_offset);
    data_offset = ftell(fp);
    data_len = _filelength(fileno(fp)) - data_offset;
    //if (!feof(fp)) { // some times wrong
    if (data_len > 0) { // feof <> 100%
        char *file_name_out;
        //
        fprintf(stdout, "extra data:\n");
        file_name_out = strdup(fname);
        file_name_out = strcat_x(file_name_out, "_ext");
        file_name_out = strcat_x(file_name_out, ext);
        //
        save_extra_data(fp, data_offset, data_len, file_name_out);
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
