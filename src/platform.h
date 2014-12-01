#pragma once

#ifdef _WIN64
#define Xip Rip
#else
#define Xip Eip
#endif
