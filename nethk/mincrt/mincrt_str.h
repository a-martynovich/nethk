//=============================================================================

#ifndef __MINCRT_STR_H_INCLUDED__
#define __MINCRT_STR_H_INCLUDED__

//-----------------------------------------------------------------------------

#include <stdint.h>

//-----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

#ifdef MINCRT
size_t str_len(const char* sz_src);
size_t str_len_w(const wchar_t* sz_src);

void str_cpy(char* sz_dst, const char* sz_src, size_t src_sz_len);
void str_cpy_w(wchar_t* sz_dst, const wchar_t* sz_src, size_t src_sz_len);

void str_cat(char* sz_dst, const char* sz_src, size_t src_sz_len);
void str_cat_w(wchar_t* sz_dst, const wchar_t* sz_src, size_t src_sz_len);

int str_cmp(
	const char* sz_1, const char* sz_2, size_t len_1, size_t len_2
	);
int str_icmp(const char* sz_1, const char* sz_2);
int str_cmp_w(
	const wchar_t* sz_1, const wchar_t* sz_2, size_t len_1, size_t len_2
	);

char* str_str(const char* sz_src, const char* sz_substr);
wchar_t* str_str_w(const wchar_t* sz_src, const wchar_t* sz_substr);

int is_digit(char c_num);
int is_digit_w(wchar_t c_num);

int a_to_i(const char* sz_num);
int a_to_i_w(const wchar_t* sz_num);

char* i_to_a(int value, char* result, int base);
wchar_t* i_to_w(int value, wchar_t* result, int base);

//int sprintf (char *string, const char *format, ...);
#define sprintf wsprintfA
#define snprintf wnsprintfA
#define snprintfW wnsprintfW

const char * str_chr (const char * string, int ch);
int str_isspace(int c);
unsigned long str_toul (const char *nptr, char **endptr,int ibase);
int str_isprint(int c);
char * str_tok (char * string, const char * control);
#else
#include <stdio.h>
#include <string.h>
#define str_len strlen
#define str_cpy strcpy
#define str_cmp(a,b,c,d) strcmp(a,b)
#define str_icmp(a,b) stricmp(a,b)
#define str_str strstr
#define a_to_i atoi
//#define str_isprint isprint
int str_isprint(int c);
#define str_isspace isspace
#define str_toul strtoul
#define str_tok strtok
#define str_chr strchr
#endif

#ifdef __cplusplus
}
#endif

//-----------------------------------------------------------------------------

#endif //__MINCRT_STR_H_INCLUDED__

//=============================================================================