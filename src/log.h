#ifndef _LOG_H
#define _LOG_H

#ifdef _DEBUG

void log_init();
void log_shutdown();
void log_debug(const char *format, ...);

#else

#define log_init() ((void*)0)
#define log_shutdown() ((void*)0)
#define log_debug(format, ...) ((void*)0)

#endif

#endif
