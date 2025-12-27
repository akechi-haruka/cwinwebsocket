#pragma once

char* stristr(const char* str1, const char* str2);

#ifdef _MSC_VER
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif