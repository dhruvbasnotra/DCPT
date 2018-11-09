
#ifndef DCPT_X509_CERTIFICATE_CREATION_H
#define DCPT_X509_CERTIFICATE_CREATION_H

#include <string>
#include <fstream>
#include <vector>
#include <algorithm>

/* Openssl Includes */
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

using namespace std;

class X509Cert
{
public:
/* Constructor */
  X509Cert(){}

  /* Destructor */
  ~X509Cert(){}

  // Takes ecdsa signature (R + S) and constructs X509 certificate
  string CreateX509Cert(string& signedDeviceInfoBase64, string& pin);

private:
  void AppendIntermediateCert();
  string FetchCertFromDB();
  void Base64toVector(vector<unsigned char>& outVal, const char* base64Data);
};

#endif  // end of DCPT_X509_CERTIFICATE_CREATION_H
