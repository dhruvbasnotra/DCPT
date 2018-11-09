#ifndef __LOGS_H__
#define __LOGS_H__

#ifdef _WIN32
#include <windows.h>
#include <processthreadsapi.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif

#include <iostream>
#include <fstream>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#define LOG_FILE_NAME                   "DcptLogs.log"
#define IS_LOGS_ON                      1
#define LOG_BUFF_MAX_LEN                4096
#define Null                            0
#define MAXP                            255
#define True                            1

#define BEGIN_LOG                       CLogger logs(__LINE__,__FUNCTION__);
#define BEGIN_LOG_FILE(filename)        CLogger logs(__LINE__,__FUNCTION__, filename);
#define WRITE_LOG(msg, ...)             logs.WriteToLog(__LINE__,msg, ##__VA_ARGS__);

class CLogger
{

  int m_iLineNo;
  bool m_bIsWriteLog;
  char m_szFileName[MAXP];
  char m_szFuncName[MAXP];

public:
  CLogger(int iLine, const char *pszFuncName = Null, const char *pszFileName = Null, bool bIsWriteLog = True)
  {
    m_iLineNo = iLine;
    if (Null == pszFileName)
    {
      strcpy(m_szFileName, LOG_FILE_NAME);
    }
    else
    {
      strcpy(m_szFileName, pszFileName);
    }
    if (Null == pszFuncName)
    {
      strcpy(m_szFuncName, "UNKNOWN");
    }
    else
    {
      strcpy(m_szFuncName, pszFuncName);
    }
    m_bIsWriteLog = bIsWriteLog;
    WriteToLog(iLine, "Start");
  }

  ~CLogger()
  {
    WriteToLog(m_iLineNo, "End");
  }

  void WriteToLog(int iLine, const char *szLogMsg, ...)
  {
  #if IS_LOGS_ON
    char szFullLogMsg[LOG_BUFF_MAX_LEN];
    if (false == m_bIsWriteLog)
    {
      return;
    }

    va_list argList;
    char szLogBuff[1024] = "";
    va_start(argList, szLogMsg);
    vsprintf(szLogBuff, szLogMsg, argList);
    va_end(argList);
    
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d, %X", &tstruct);
    try
    {
      FILE* pLog;
      pLog = fopen(m_szFileName, "a+");
      if (Null == pLog)
      {
        return;
      }
      if (0 == strcmp("Start", szLogBuff))
      {
      #ifdef _WIN32
        std::sprintf(szFullLogMsg, "\n %s %04u  %10s (%03d)  %s", buf, GetCurrentThreadId(), m_szFuncName, iLine, szLogBuff);
      #else
        std::sprintf(szFullLogMsg, "\n %s %04u  %10s (%03d)  %s", buf, getpid(), m_szFuncName, iLine, szLogBuff);
      #endif
      }
      else
      {
      #ifdef _WIN32
        std::sprintf(szFullLogMsg, "\n %s %04u  %10s (%03d)  %s", buf, GetCurrentThreadId(), m_szFuncName, iLine, szLogBuff);
      #else
        std::sprintf(szFullLogMsg, "\n %s %04u  %10s (%03d)  %s", buf, getpid(), m_szFuncName, iLine, szLogBuff);
      #endif
      }
      fprintf(pLog, szFullLogMsg);
      fclose(pLog);
    }
    catch (...) {}
    #endif
  }
};

#endif  // __LOGS_H__

