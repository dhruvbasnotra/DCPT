
#ifndef DCPT_CSR_CREATION_H
#define DCPT_CSR_CREATION_H

#include <string>
#include <vector>
#include <algorithm>
#include <fstream>

/* Openssl Includes */
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

using namespace std;

typedef vector<string> vecString;

class CSRCreation
{
public:
  /* Constructor */
  CSRCreation(string pubKey, string subj);

  // creates certificate signing request info
  string CreateCSRRequest();

  // returns X509_req
  X509_REQ* GetX509Req() const;

  // returns current macID of CSR
  string GetMacId() const;

private:
  bool ConvertEcKeyToEvpKey();
  void CreateSubject();
  string PrepareCSR();
  void AssignSubjectFields(vecString& subject);
  vecString ParseSubject(const string& subjectStr, const string& delimiters);
  void CreateTempConfig();
  void Sha256(unsigned char* hashOut /* Must be SHA256_DIGEST_LENGTH */, const unsigned char* certReqInfo, int certReqInfolength);

  /* Private Members */
  string PublicKey;
  string Subject;
  EVP_PKEY* Pkey;
  X509_REQ *X509_req;
  string CommonName;
  string CountryName;
  string OrganizationName;
  string OrganizationalUnitName;
  string State;
  string Location;
};

#endif  // end of DCPT_CSR_CREATION_H
