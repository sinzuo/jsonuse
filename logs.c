#include "logs.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

char g_logfile[256] = "";
/* 设置日志存储文件
 * ffile: 日志文件, 含绝对路径
*/
void SetLogFile(const char *ffile)
{
    if (!ffile)
        return;

    memset(g_logfile, 0, sizeof(g_logfile));
    snprintf(g_logfile, sizeof(g_logfile), "%s", ffile);
    //system("echo \"ffile: 日志文件, 含绝对路径\" > /tmp/.http.log");
}

/* 日志记录*/
void WriteLog(const char *_Format, ...)
{
    if (!_Format)
        return;

    time_t timep;
    struct tm *dtNow;
    FILE *fp = NULL;

    time(&timep);
    dtNow=gmtime(&timep);

    if ((fp = fopen(g_logfile, "a")))
    {
        fprintf(fp, "%04d-%02d-%02d %02d:%02d:%02d    ", dtNow->tm_year, dtNow->tm_mon, dtNow->tm_yday,
                dtNow->tm_hour, dtNow->tm_min, dtNow->tm_sec);

        va_list arg_ptr;
        va_start(arg_ptr,_Format);
        vfprintf(fp, _Format, arg_ptr);
        va_end(arg_ptr);
        fprintf(fp, "\r\n");
        fflush(fp);
        fclose(fp);
    }
}
