#pragma once

#ifdef _DEBUG

void log_init();
void log_shutdown();
void log_raw(const char *format, ...);
void log_info(const char *format, ...);
void log_warning(const char *format, ...);
void log_error(const char *format, ...);

#else

#define log_init() ((void*)0)
#define log_shutdown() ((void*)0)
#define log_raw() ((void*)0)
#define log_info(format, ...) ((void*)0)
#define log_warning(format, ...) ((void*)0)
#define log_error(format, ...) ((void*)0)

#endif
