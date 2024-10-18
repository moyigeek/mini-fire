#include "log.h"
#include <linux/ip.h> // for struct iphdr
#include <linux/in.h> // for IPPROTO_* constants
#include <linux/types.h>  
// 根据协议号返回协议类型字符串
char log_file_path[256]="/home/moyi/ws/module/net_log.txt";


void log_message(uint8_t level, const char *fmt, ...) {
    FILE *log_file = fopen(log_file_path, "a");
    if (!log_file) {
        return;
    }

    const char *level_str;
    switch (level) {
        case LOG_DEBUG: level_str = "DEBUG"; break;
        case LOG_INFO:  level_str = "INFO"; break;
        case LOG_WARN:  level_str = "WARN"; break;
        case LOG_ERROR: level_str = "ERROR"; break;
        default: level_str = "UNKNOWN"; break;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

    fprintf(log_file, "[%s] [%s] ", time_str, level_str);

    va_list args;
    va_start(args, fmt);
    vfprintf(log_file, fmt, args);
    va_end(args);

    fprintf(log_file, "\n");
    fclose(log_file);
}