#pragma once

#define STATIC      static
#define SIZEOF(el)  sizeof(el)
#define READONLY    const
#define PROCEDURE   void

/*
*  BASE
*  -----------------
* |IMAGE_DOS_HEADER |
*  -----------------
*                         -----------------
* |e_lfanew         | -> |IMAGE_NT_HEADERS |
*                         -----------------
*                        | Signature       |     -----------------
*                        | FileHeader      | -> |IMAGE_FILE_HEADER|
*                                                -----------------
*                                                ----------------------
*                        | OptionalHeader  | -> |IMAGE_OPTIONAL_HEADER |
*                                                ----------------------
*                                               | DataDirectory []     | -> ENTRIES OF DIRECTORY
*/

#define IMAGENTHEADEROFFSET(base)                                             \
	((LPVOID)((BYTE*)base + ((IMAGE_DOS_HEADER*)base)->e_lfanew))

#define IMAGEFILEHEADEROFFSET(base)                                           \
	(LPVOID)(((BYTE*)IMAGENTHEADEROFFSET(base)) + SIZEOF(DWORD))

#define IMAGEOPTIONALHEADEROFFSET(base)                                       \
	(LPVOID)((BYTE*)IMAGEFILEHEADEROFFSET(base) + SIZEOF(IMAGE_FILE_HEADER))

#define IMAGESECTIONHEADEROFFSET(base)                                        \
	(LPVOID)((BYTE*)IMAGEOPTIONALHEADEROFFSET(base) + SIZEOF(IMAGE_OPTIONAL_HEADER))