
#include "DCPT_X509Certificate_Creation.h"
#include "DCPT_SingletonDB.h"
#include "logs.h"

/* extern variables */
extern string macID;
extern X509_REQ* x509ReqPointer;

namespace
{
  const unsigned int FAIL = 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
void X509Cert::Base64toVector(std::vector<unsigned char>& outVal, const char* base64Data)
{
  BEGIN_LOG;
  BIO *b64, *bmem;
  size_t strLen = strlen(base64Data);
  outVal.resize(strLen);              // Allocate sufficient memory to store output data

  // Convert base64 version of ECC public into binary.
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf(base64Data, strLen);
  bmem = BIO_push(b64, bmem);
  int retsize = BIO_read(bmem, outVal.data(), outVal.size());

  // Truncate the output buffer to the actual data size.
  outVal.resize(retsize);

  BIO_free_all(bmem);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
string X509Cert::CreateX509Cert(string& signedDeviceInfoBase64, string& pin)
{
  BEGIN_LOG;
  vector<unsigned char> signedDeviceInfo;
  Base64toVector(signedDeviceInfo, signedDeviceInfoBase64.c_str());

  if(x509ReqPointer)
  {
    WRITE_LOG("Info: x509ReqPointer is Valid");
    ASN1_BIT_STRING_set(x509ReqPointer->signature, signedDeviceInfo.data(), signedDeviceInfo.size());
    x509ReqPointer->signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    x509ReqPointer->signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    x509ReqPointer->sig_alg->algorithm = OBJ_nid2obj(NID_ecdsa_with_SHA256);
    x509ReqPointer->sig_alg->parameter = ASN1_TYPE_new();
    x509ReqPointer->sig_alg->parameter->type = V_ASN1_NULL;

    // constructs CSR file
    const char *szPath = "CSR.pem";
    BIO* out = BIO_new_file(szPath, "w");

    // PEM BIO write
    if (FAIL >= (PEM_write_bio_X509_REQ(out, x509ReqPointer)))
    {
      WRITE_LOG("Error: CSR.pem file not written properly!");
    }
    BIO_free_all(out);
    X509_REQ_free(x509ReqPointer);
  }
  else
  {
     WRITE_LOG("Error: x509ReqPointer is NULL");
     return "";
  }

  // making sure that no nxp-hsm-challenge.crt available before certificate creation
  if (remove("nxp-hsm-challenge.crt") != FAIL)
    puts("deleting file");

  ifstream checkIntermediateCert("jcibe-mfg-ca.crt");
  if (FAIL == checkIntermediateCert.good())
  {
    WRITE_LOG("Error: Intermediate jcibe-mfg-ca.crt not found locally !");
    return "";
  }

  // creating x509 certificate
  const string x509CertCommand = "openssl x509 -engine pkcs11 -req -days 3650 -CAform PEM -CA jcibe-mfg-ca.crt -CAkeyform engine -CAkey pkcs11:pin-value=" + pin + " -CAcreateserial -in CSR.pem -out nxp-hsm-challenge.crt -extensions v3_req -extfile subjectAlterNative.cfg";
  system(x509CertCommand.c_str());

  // Appending Intermediate cert to nxp cert
  AppendIntermediateCert();

  // Fetching certificate data from dcpt database
  return FetchCertFromDB();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
string X509Cert::FetchCertFromDB()
{
  /* Creating Singleton Instance */
  DCPTSingletonDB* pDbInstance = DCPTSingletonDB::CreateDbInstance();

  // Checks macID in database, if present then update DB else Insert into DB
  (true != pDbInstance->CheckDB(macID)) ? pDbInstance->InsertDB() : pDbInstance->UpdateDB();

  return pDbInstance->ReadBlob();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
void X509Cert::AppendIntermediateCert()
{
  BEGIN_LOG;
 
  ifstream certNxpFile("nxp-hsm-challenge.crt");
  ifstream certMfgCaFile("jcibe-mfg-ca.crt");
  ofstream combinedFile("Final.crt");

  if(certNxpFile.good() && certMfgCaFile.good())
  {
    combinedFile << certNxpFile.rdbuf() << certMfgCaFile.rdbuf();
    WRITE_LOG("Info: Intermediate cert appended successfully!");
  }

  certNxpFile.close();
  certMfgCaFile.close();
  combinedFile.close();
}
