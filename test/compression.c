/*#include <windows.h>
#include <tchar.h>

#include "LiteUnzip.h"


int main()
{
	HMODULE		unzipDll;
	HUNZIP		huz;
	DWORD		result;

		// Open a ZIP archive on disk named "test.zip".
		if (!(result = lpUnzipOpenFileRaw(&huz, _T("test.zip"), 0)))
		{
			ZIPENTRY		ze;
			unsigned char	*buffer;

			// Because the zip archive was created "raw" (ie, without any ZIP
			// header), then we MUST know what the original size is, as well as
			// the compressed size. We put these two values in the ZIPENTRY before
			// we call one of the UnzipItemXXX functions
			ze.CompressedSize = 67;
			ze.UncompressedSize = 69;

			// Allocate a memory buffer to decompress the item
#ifdef WIN32
			if (!(buffer = GlobalAlloc(GMEM_FIXED, ze.UncompressedSize)))
#else
			if (!(buffer = malloc(ze.UncompressedSize)))
#endif
			{
#ifdef WIN32
				TCHAR msg[160];

				msg[0] = 0;
				FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &msg[0], 160, 0);
				MessageBox(0, &msg[0], _T("Error"), MB_OK);
#else
				printf("ERROR: %s\n", strerror(errno));
#endif
			}

			else
			{
				// Decompress the item into our buffer
				if ((result = lpUnzipItemToBuffer(huz, buffer, ze.UncompressedSize, &ze)))
				{
#ifdef WIN32
					GlobalFree(buffer);
#else
					free(buffer);
#endif
					lpUnzipClose(huz);
					goto bad;
				}

#ifdef WIN32
				// Here we would do something with the contents of buffer. It contains
				// ze.UncompressedSize bytes. We'll just display it to the console.
				WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buffer, ze.UncompressedSize, &ze.CompressedSize, 0);

				// We have no further use for the buffer, so we must free it.
				GlobalFree(buffer);
#else
				fwrite(buffer, ze.UncompressedSize, 1, stdout);
				free(buffer);
#endif
			}

			// Done unzipping files, so close the ZIP archive.
			lpUnzipClose(huz);
		}
		else
		{
			TCHAR	msg[100];

bad:		lpUnzipFormatMessage(result, msg, sizeof(msg));
#ifdef WIN32
			MessageBox(0, &msg[0], _T("Error"), MB_OK);
#else
			printf("ERROR: %s\n", &msg[0]);
#endif
		}

		// Free the LiteUnzip.DLL
#ifdef WIN32
		FreeLibrary(unzipDll);
#else
		dlclose(unzipDll);
#endif
	}
	else
	{
#ifdef WIN32
		TCHAR msg[160];

		msg[0] = 0;
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &msg[0], 160, 0);
		MessageBox(0, &msg[0], _T("Error"), MB_OK);
#else
		printf("ERROR: %s\n", dlerror());
#endif
	}

	return(0);
}
*/