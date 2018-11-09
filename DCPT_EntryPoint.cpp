
#include "DCPT_EntryPoint.h"
#include "DCPT_CSR_Creation.h"
#include "DCPT_X509Certificate_Creation.h"
#include "logs.h"

// global data
string csrData;
string certificateData;
string rootCertificateData;
string macID;
X509_REQ* x509ReqPointer = NULL;

//////////////////////////////////////////////////////////////////////////////////////////////////////
__declspec(dllexport) const char* getDevInfoToSign(const char* controllerName, const char* serialNumber, const char* subject,
                                                   const char* internalChipNumber, const char* factoryName, const char* factoryAddress,
                                                   const char* factoryStationId, const char* controllerMACId, const char* otherRemarks,
                                                   const char* otherRemarks2, const char* publicKey)
{
  BEGIN_LOG;
  if (NULL == publicKey || ('\0' == *publicKey))
  {
    WRITE_LOG("Error: Insufficient public key data to proceed ");
    return NULL;
  }
  if (NULL == subject || ('\0' == *subject))
  {
    WRITE_LOG("Error: Insufficient subject data data to proceed ");
    return NULL;
  }

  // logging pub key and  sub for now, will remove in final release.
  WRITE_LOG("Info: public key: %s subject : %s", publicKey, subject);

  CSRCreation csrInstance(publicKey, subject);
  csrData = csrInstance.CreateCSRRequest();
  x509ReqPointer = csrInstance.GetX509Req();
  macID = csrInstance.GetMacId();
  return csrData.c_str();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
__declspec(dllexport) const char* getCertificate(const char* sigValBase64, const char* secPIN)
{
  X509Cert certInstance;
  certificateData = certInstance.CreateX509Cert(string(sigValBase64), string(secPIN));
  return certificateData.c_str();
}

////////////////////////////////////////////////////////////////////////////////////////////////////
__declspec(dllexport) const char* getRootCACertificate()
{
  BEGIN_LOG;
  ifstream rootCA("jcibe-root-ca.crt");
  if (0 != (rootCA.peek() == std::ifstream::traits_type::eof()))
  {
    WRITE_LOG("Error: jcibe-root-ca.crt certificate not found!!");
    return "";
  }

  rootCertificateData = string((istreambuf_iterator<char>(rootCA)), istreambuf_iterator<char>());
  return rootCertificateData.c_str();
}
