

#include "DCPT_SingletonDB.h"
#include "logs.h"

DCPTSingletonDB* DCPTSingletonDB::DcptDbInstance = NULL;

//////////////////////////////////////////////////////////////////////////////////////////////////////
DCPTSingletonDB::DCPTSingletonDB() :DbName("DCPT_database.db"), MacId(""), pDbInstance(NULL)
{
  CreateTable();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
DCPTSingletonDB::~DCPTSingletonDB()
{
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
bool DCPTSingletonDB::CheckDB(const string& macId)
{
  MacId = macId;
  string sql = "Select * from CERT where  MAC_ID= '" + macId + "'";
  sqlite3_stmt *selectStmt;

  if (SQLITE_OK == (sqlite3_prepare_v2(pDbInstance, sql.c_str(), -1, &selectStmt, NULL)))
  {
     if (SQLITE_ROW == sqlite3_step(selectStmt))
     {
       sqlite3_finalize(selectStmt);
       sqlite3_close(pDbInstance);
       return true;
     }
     else
     {
        // no record found
        sqlite3_finalize(selectStmt);
        sqlite3_close(pDbInstance);
        return false;
     }
  }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
void DCPTSingletonDB::InsertDB()
{
  BEGIN_LOG;

  // open  database to insert
  OpenDB();

  // preaparing insert query
  string insert = "INSERT INTO CERT (MAC_ID, Certificate) VALUES('" + (MacId)+"','" + (GetCertData())+"')";

  if(sqlite3_exec(pDbInstance, insert.c_str(), 0, 0, 0))
    WRITE_LOG("Error: Unable to execute database while inserting!");

  sqlite3_close(pDbInstance);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
void DCPTSingletonDB::UpdateDB()
{
  BEGIN_LOG;

  // open database to update
  OpenDB();

  // preparing update query
  string update = "UPDATE CERT SET Certificate = '" + GetCertData() + "' WHERE MAC_ID = '" + MacId + "'";

  if(sqlite3_exec(pDbInstance, update.c_str(), 0, 0, 0))
    WRITE_LOG("Error: Unable to execute database while updating!");

  sqlite3_close(pDbInstance);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
const string DCPTSingletonDB::ReadBlob()
{
  BEGIN_LOG;
  sqlite3_stmt* stmt;

  // open database to read
  OpenDB();

  // preparing select query
  string select = "SELECT Certificate FROM Cert WHERE MAC_ID ='" + MacId + "'";

  if(sqlite3_prepare_v2(pDbInstance, select.c_str(), -1, &stmt, NULL))
     WRITE_LOG("Error: Unable to prepare, error: (%s)",sqlite3_errmsg(pDbInstance));

  while (sqlite3_step(stmt) == SQLITE_ROW)
  {
    select = (char*)sqlite3_column_text(stmt, 0);
  }

  sqlite3_finalize(stmt);
  sqlite3_close(pDbInstance);

  return select;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
void DCPTSingletonDB::CreateTable()
{
  BEGIN_LOG;

  OpenDB();

  // preparing create table query
  string createTable = "CREATE TABLE CERT (RecordNum INTEGER PRIMARY KEY NOT NULL, MAC_ID VARCHAR(2) NOT NULL, Certificate BLOB)";
  
  sqlite3_exec(pDbInstance, createTable.c_str(), 0, 0, 0);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
DCPTSingletonDB*  DCPTSingletonDB::CreateDbInstance()
{
  BEGIN_LOG
  if (NULL == DcptDbInstance)
  {
    DcptDbInstance = new DCPTSingletonDB();
  }
  return DcptDbInstance;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
string DCPTSingletonDB::GetCertData()
{
  BEGIN_LOG
  ifstream file("Final.crt");
  if (!file.good())
  {
    WRITE_LOG("Error: An error occurred opening the file\n");
    return "";
  }

  string certData((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
  return certData;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
void DCPTSingletonDB::OpenDB()
{
  BEGIN_LOG
  if (sqlite3_open(DbName.c_str(), &pDbInstance))
  {
    WRITE_LOG("Error: Unable to open database, error: (%s)", sqlite3_errmsg(pDbInstance));
    return;
  }
}
