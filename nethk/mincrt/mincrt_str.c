//=============================================================================

#include "mincrt_str.h"
#include "mincrt_mem.h"
#include <stdarg.h>
#include <limits.h>
#include <windows.h>
//-----------------------------------------------------------------------------

size_t str_len(const char* sz_src)
{
	size_t	result = 0;

	while (sz_src[result] != 0)
		result++;

	return result;
}

//-----------------------------------------------------------------------------

size_t str_len_w(const wchar_t* sz_src)
{
	size_t	result = 0;

	while (sz_src[result] != 0)
		result++;

	return result;
}

//-----------------------------------------------------------------------------

void str_cpy(char* sz_dst, const char* sz_src, size_t src_sz_len)
{
	if (src_sz_len == -1)
		src_sz_len = str_len(sz_src);

	mem_cpy(sz_dst, sz_src, src_sz_len);

	sz_dst[src_sz_len] = 0;
}

//-----------------------------------------------------------------------------

void str_cpy_w(wchar_t* sz_dst, const wchar_t* sz_src, size_t src_sz_len)
{
	if (src_sz_len == -1)
		src_sz_len = str_len_w(sz_src);

	mem_cpy(sz_dst, sz_src, src_sz_len * sizeof(wchar_t));

	sz_dst[src_sz_len] = 0;
}

//-----------------------------------------------------------------------------

void str_cat(char* sz_dst, const char* sz_src, size_t src_sz_len)
{
	str_cpy(sz_dst + str_len(sz_dst), sz_src, src_sz_len);
}

//-----------------------------------------------------------------------------

void str_cat_w(wchar_t* sz_dst, const wchar_t* sz_src, size_t src_sz_len)
{
	str_cpy_w(sz_dst + str_len_w(sz_dst), sz_src, src_sz_len);
}

//-----------------------------------------------------------------------------

int str_cmp(
	const char* sz_1, const char* sz_2, size_t len_1, size_t len_2
	)
{
	if ((sz_1 == 0) && (sz_2 != 0)) return -1;
	if ((sz_1 != 0) && (sz_2 == 0)) return 1;
	if ((sz_1 == 0) && (sz_2 == 0)) return 0;

	if ((len_1 == -1) && (len_2 == -1))
	{
		while (((len_1 = *sz_1 - *sz_2) == 0) && (*sz_2 != 0))
		{
			sz_1++;
			sz_2++;
		}
	}
	else
	{
		if (len_1 == -1) len_1 = str_len(sz_1);
		if (len_2 == -1) len_2 = str_len(sz_2);

		if ((len_1 != len_2) || (len_1 == 0) || (len_2 == 0))
		{
			len_1 -= len_2;
		}
		else
		{
			size_t c;

			for (c = 0; c < len_2; c++)
			{
				if ((len_1 = *sz_1 - *sz_2) != 0)
					break;

				sz_1++;
				sz_2++;
			}
		}
	}

	return (len_1 == 0 ? 0 : (len_1 > 0 ? 1 : -1));
}

//-----------------------------------------------------------------------------

int str_cmp_w(
	const wchar_t* sz_1, const wchar_t* sz_2, size_t len_1, size_t len_2
	)
{
	if ((sz_1 == 0) && (sz_2 != 0)) return -1;
	if ((sz_1 != 0) && (sz_2 == 0)) return 1;
	if ((sz_1 == 0) && (sz_2 == 0)) return 0;

	if ((len_1 == -1) && (len_2 == -1))
	{
		while (((len_1 = *sz_1 - *sz_2) == 0) && (*sz_2 != 0))
		{
			sz_1++;
			sz_2++;
		}
	}
	else
	{
		if (len_1 == -1) len_1 = str_len_w(sz_1);
		if (len_2 == -1) len_2 = str_len_w(sz_2);

		if ((len_1 != len_2) || (len_1 == 0) || (len_2 == 0))
			len_1 -= len_2;

		else
		{
			size_t c;

			for (c = 0; c < len_2; c++)
			{
				if ((len_1 = *sz_1 - *sz_2) != 0)
					break;

				sz_1++;
				sz_2++;
			}
		}
	}

	return (len_1 == 0 ? 0 : (len_1 > 0 ? 1 : -1));
}

//-----------------------------------------------------------------------------

char* str_str(const char* sz_src, const char* sz_substr)
{
	char*	cp = (char*)sz_src;
	char*	s1, *s2;

	while (*cp)
	{
		s1 = cp;
		s2 = (char*)sz_substr;

		while ((*s1) && (*s2) && (!(*s1-*s2)))
			s1++, s2++;

		if (!*s2)
			return cp;

		cp++;
	}

	return 0;
}

//-----------------------------------------------------------------------------

wchar_t* str_str_w(const wchar_t* sz_src, const wchar_t* sz_substr)
{
	wchar_t*	cp = (wchar_t*)sz_src;
	wchar_t*	s1, *s2;

	while (*cp)
	{
		s1 = cp;
		s2 = (wchar_t*)sz_substr;

		while ((*s1) && (*s2) && (!(*s1-*s2)))
			s1++, s2++;

		if (!*s2)
			return cp;

		cp++;
	}

	return 0;
}

//-----------------------------------------------------------------------------

int is_digit(char c_num)
{
	return ((c_num >= '0') && (c_num <= '9'));
}

//-----------------------------------------------------------------------------

int is_digit_w(wchar_t c_num)
{
	return ((c_num >= '0') && (c_num <= '9'));
}

//-----------------------------------------------------------------------------

int a_to_i(const char* sz_num)
{
	size_t	num_len = str_len(sz_num);
	int		flag = 1;
	int		rt = 0;
	size_t	i = 0;

	if (num_len <= 0)
		return 0;

	if (!is_digit(sz_num[i]))
	{
		if (sz_num[0] == '-')
			flag = 0;
		else if (sz_num[0] == '+')
			flag = 1;
		else
			return 0;

		i++;
	}

	for (; i < num_len; i++)
	{
		if (!is_digit(sz_num[i]))
			break;

		rt = rt * 10 + (sz_num[i] - '0');
	}

	if (!flag)
		rt = -rt;

	return rt;
}

//-----------------------------------------------------------------------------

int a_to_i_w(const wchar_t* sz_num)
{
	size_t	num_len = str_len_w(sz_num);
	int		flag = 1;
	int		rt = 0;
	size_t	i = 0;

	if (num_len <= 0)
		return 0;

	if (!is_digit_w(sz_num[i]))
	{
		if (sz_num[0] == '-')
			flag = 0;
		else if (sz_num[0] == '+')
			flag = 1;
		else
			return 0;

		i++;
	}

	for (; i < num_len; i++)
	{
		if (!is_digit_w(sz_num[i]))
			break;

		rt = rt * 10 + (sz_num[i] - '0');
	}

	if (!flag)
		rt = -rt;

	return rt;
}

//-----------------------------------------------------------------------------

char* i_to_a(int value, char* result, int base)
{
	char*	ptr = result, *ptr1 = result, tmp_char;
	int		tmp_value;

	if ((base < 2) || (base > 36))
	{
		*result = '\0';
		return result;
	}
	
	do
	{
		tmp_value = value;
		value /= base;
		*ptr++ = "fedcba9876543210123456789abcdefghijklmnopqrstuvwxyz"[35 + (tmp_value - value * base)];
	} while (value);
	
	if (tmp_value < 0)
		*ptr++ = '-';
	*ptr-- = '\0';

	while (ptr1 < ptr)
	{
		tmp_char = *ptr;
		*ptr--= *ptr1;
		*ptr1++ = tmp_char;
	}

	return result;
}

//-----------------------------------------------------------------------------

wchar_t* i_to_w(int value, wchar_t* result, int base)
{
	wchar_t*	ptr = result, *ptr1 = result, tmp_char;
	int			tmp_value;

	if ((base < 2) || (base > 36))
	{
		*result = '\0';
		return result;
	}
	
	do
	{
		tmp_value = value;
		value /= base;
		*ptr++ = "fedcba9876543210123456789abcdefghijklmnopqrstuvwxyz"[35 + (tmp_value - value * base)];
	} while (value);
	
	if (tmp_value < 0)
		*ptr++ = '-';
	*ptr-- = '\0';

	while (ptr1 < ptr)
	{
		tmp_char = *ptr;
		*ptr--= *ptr1;
		*ptr1++ = tmp_char;
	}

	return result;
}

const char * str_chr(
	const char * string,
	int ch
	) {
		while (*string && *string != (char)ch)
			string++;

		if (*string == (char)ch)
			return((char *)string);
		return(NULL);
}

/* flag values */
#define FL_UNSIGNED   1       /* strtoul called */
#define FL_NEG        2       /* negative sign found */
#define FL_OVERFLOW   4       /* overflow occured */
#define FL_READDIGIT  8       /* we've read at least one correct digit */

// __ascii_isdigit returns a non-zero value if c is a decimal digit (0 – 9).
int __ascii_isdigit(int c)
{
	return (c >= '0' && c <= '9');
}

// __ascii_isalpha returns a nonzero value if c is within
// the ranges A – Z or a – z.
int __ascii_isalpha(int c)
{
	return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

// __ascii_toupper converts lowercase character to uppercase.
int __ascii_toupper(int c)
{
	if (c >= 'a' && c <= 'z') return (c - ('a' - 'A'));
	return c;
}

int str_isspace(int c)
{
	static unsigned char spaces[256] =
	{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 1,  // 0-9
		1, 1, 1, 1, 0, 0, 0, 0, 0, 0,  // 10-19
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 20-29
		0, 0, 1, 0, 0, 0, 0, 0, 0, 0,  // 30-39
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 40-49
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 50-59
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 60-69
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 70-79
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 80-89
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 90-99
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 100-109
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 110-119
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 120-129
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 130-139
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 140-149
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 150-159
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 160-169
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 170-179
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 180-189
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 190-199
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 200-209
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 210-219
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 220-229
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 230-239
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 240-249
		0, 0, 0, 0, 0, 1,              // 250-255
	};

	return spaces[(unsigned char)c] == 1;
}

static unsigned long __cdecl strtoxl (
        const char *nptr,
        const char **endptr,
        int ibase,
        int flags
        )
{
        const char *p;
        char c;
        unsigned long number;
        unsigned digval;
        unsigned long maxval;

        p = nptr;                       /* p is our scanning pointer */
        number = 0;                     /* start with zero */

        c = *p++;                       /* read char */
        while ( str_isspace((int)(unsigned char)c) )
                c = *p++;               /* skip whitespace */

        if (c == '-') {
                flags |= FL_NEG;        /* remember minus sign */
                c = *p++;
        }
        else if (c == '+')
                c = *p++;               /* skip sign */

        if (ibase < 0 || ibase == 1 || ibase > 36) {
                /* bad base! */
                if (endptr)
                        /* store beginning of string in endptr */
                        *endptr = nptr;
                return 0L;              /* return 0 */
        }
        else if (ibase == 0) {
                /* determine base free-lance, based on first two chars of
                   string */
                if (c != '0')
                        ibase = 10;
                else if (*p == 'x' || *p == 'X')
                        ibase = 16;
                else
                        ibase = 8;
        }

        if (ibase == 16) {
                /* we might have 0x in front of number; remove if there */
                if (c == '0' && (*p == 'x' || *p == 'X')) {
                        ++p;
                        c = *p++;       /* advance past prefix */
                }
        }

        /* if our number exceeds this, we will overflow on multiply */
        maxval = ULONG_MAX / ibase;


        for (;;) {      /* exit in middle of loop */
                /* convert c to value */
                if ( __ascii_isdigit((int)(unsigned char)c) )
                        digval = c - '0';
                else if ( __ascii_isalpha((int)(unsigned char)c) )
                        digval = __ascii_toupper(c) - 'A' + 10;
                else
                        break;
                if (digval >= (unsigned)ibase)
                        break;          /* exit loop if bad digit found */

                /* record the fact we have read one digit */
                flags |= FL_READDIGIT;

                /* we now need to compute number = number * base + digval,
                   but we need to know if overflow occured.  This requires
                   a tricky pre-check. */

                if (number < maxval || (number == maxval &&
                (unsigned long)digval <= ULONG_MAX % ibase)) {
                        /* we won't overflow, go ahead and multiply */
                        number = number * ibase + digval;
                }
                else {
                        /* we would have overflowed -- set the overflow flag */
                        flags |= FL_OVERFLOW;
                }

                c = *p++;               /* read next digit */
        }

        --p;                            /* point to place that stopped scan */

        if (!(flags & FL_READDIGIT)) {
                /* no number there; return 0 and point to beginning of
                   string */
                if (endptr)
                        /* store beginning of string in endptr later on */
                        p = nptr;
                number = 0L;            /* return 0 */
        }
        else if ( (flags & FL_OVERFLOW) ||
                  ( !(flags & FL_UNSIGNED) &&
                    ( ( (flags & FL_NEG) && (number > -LONG_MIN) ) ||
                      ( !(flags & FL_NEG) && (number > LONG_MAX) ) ) ) )
        {
                /* overflow or signed overflow occurred */
                // errno = ERANGE;
                if ( flags & FL_UNSIGNED )
                        number = ULONG_MAX;
                else if ( flags & FL_NEG )
                        number = (unsigned long)(-LONG_MIN);
                else
                        number = LONG_MAX;
        }

        if (endptr != NULL)
                /* store pointer to char that stopped the scan */
                *endptr = p;

        if (flags & FL_NEG)
                /* negate result if there was a neg sign */
                number = (unsigned long)(-(long)number);

        return number;                  /* done. */
}

unsigned long str_toul (const char *nptr, char **endptr,int ibase)
{
	return strtoxl(nptr, (const char**)endptr, ibase, FL_UNSIGNED);
}

int str_isprint(int c) {
	return (c >= 040 && c <= 0176) ? 1: 0;
}

//=============================================================================