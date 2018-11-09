

#ifndef DCPT_SINGLETON_DB_H
#define DCPT_SINGLETON_DB_H

#include <fstream>
#include <string>
#include "sqlite3.h"

using namespace std;

class DCPTSingletonDB
{
public:
  bool CheckDB(const string& macId);
  void UpdateDB();
  void InsertDB();
  const string ReadBlob();
  static DCPTSingletonDB* CreateDbInstance();
  string GetCertData();
  void OpenDB();

private:
  /* Constructor */
  DCPTSingletonDB();

  /* Destructor */
  ~DCPTSingletonDB();

  /* Copy Constructor */
  DCPTSingletonDB(const DCPTSingletonDB& rhs);

  /* Copy Assignment Operator */
  DCPTSingletonDB& operator =(const DCPTSingletonDB& rhs);

  /* Create database tables */
  void CreateTable();

private:
  const string DbName;
  string MacId;
  sqlite3* pDbInstance; // database handle.
  static DCPTSingletonDB* DcptDbInstance;
};

#endif // end of DCPT_SINGLETON_DB_H
