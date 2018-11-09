
cmake_minimum_required(VERSION 3.10.0)

project(Device_Tool)

include_directories("C:/OpenSSL-Win32/include")

SET(BUILD_SHARED_LIBS ON)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MD")

if(MSVC)
  add_definitions(           # Add your global definitions here (e.g., -DFOO -FBAR...).
    -DINCLUDE_SYNCHRONOUS_CALLS
    -D_AFXDLL
    -D_CRT_SECURE_NO_WARNINGS
    -D_CRT_NON_CONFORMING_SWPRINTFS
    -D_UNICODE
    -DUNICODE
  )
  
set(SOURCE
    "DCPT_CSR_Creation.h"
    "DCPT_EntryPoint.h"
    "DCPT_X509Certificate_Creation.h"
    "DCPT_SingletonDB.h"
    "logs.h"
    "sqlite3.h"
    "Device_Tool.def"
    "DCPT_CSR_Creation.cpp"
    "DCPT_EntryPoint.cpp"
    "DCPT_X509Certificate_Creation.cpp"
    "DCPT_SingletonDB.cpp"
    "sqlite3.c"
  )

add_library(Device_Tool SHARED ${SOURCE})

target_link_libraries(Device_Tool 
                      "C:/OpenSSL-Win32/lib/ssleay32.lib"
                      "C:/OpenSSL-Win32/lib/libeay32.lib"
                      "C:/OpenSSL-Win32/lib/gost.lib"
                      "C:/Users/cgangwsw/Downloads/sqlite-dll-win32-x86-3200000/sqlite3.lib")

set_source_files_properties(Device_Tool.def PROPERTIES GENERATED TRUE)

endif(MSVC)