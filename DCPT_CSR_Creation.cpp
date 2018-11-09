

#include "DCPT_CSR_Creation.h"
#include"logs.h"

namespace
{
  const unsigned int SUCCESS = 1;
  const unsigned int FAIL = 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
CSRCreation::CSRCreation(string pubKey, string subj): PublicKey(pubKey), Subject(subj),
                                                      Pkey(NULL), X509_req(NULL)
{
  if(!Subject.empty())
  {
    AssignSubjectFields(ParseSubject(Subject, "/="));
    CreateTempConfig();
  }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
string CSRCreation::CreateCSRRequest()
{
  BEGIN_LOG

  // create x509 req
  X509_req = X509_REQ_new();
  if (NULL == X509_req)
  {
    WRITE_LOG("Error: occured while allocating X509_REQ object");
    return "";
  }

  // setting version 0 in x509_req as per RFC-2986
  if ((FAIL == X509_REQ_set_version(X509_req, 0)))
  {
    WRITE_LOG("Error: X509_REQ version not set, ret (%d)", FAIL);
    return "";
  }

  // set subject of x509 req
  CreateSubject();

  // construct evp key
  if (ConvertEcKeyToEvpKey())
  {
    // Set public Key
    if (SUCCESS != (X509_REQ_set_pubkey(X509_req, Pkey)))
    {
      WRITE_LOG("Error : Set pubkey failed!");
      return "";
    }

    return PrepareCSR();
  }

  return "";
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
bool CSRCreation::ConvertEcKeyToEvpKey()
{
  BEGIN_LOG;

  int retVal;
  EC_KEY *ecKey = NULL;
  const size_t ByteSize = 32;
  const size_t ECC_P256_PUB_KEY_LEN = 2 * 32 + 1;	// Two 256 bit values plus prefix byte.
  vector<unsigned char> pubKeyRaw(ECC_P256_PUB_KEY_LEN);
  BIO *b64, *bmem;

  Pkey = EVP_PKEY_new();

  // Convert base64 version of ECC public into binary.
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf(PublicKey.c_str(), PublicKey.length());
  bmem = BIO_push(b64, bmem);
  retVal = BIO_read(bmem, pubKeyRaw.data(), pubKeyRaw.size());
  if (FAIL == retVal)
  {
    WRITE_LOG("Error :BIO_read failed");
    BIO_free_all(bmem);
    return FAIL;
  }
  BIO_free_all(bmem);

  ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (NULL == ecKey) 
  {
      WRITE_LOG("Error: EC_KEY_new_by_curve_name() returned NULL");
      return FAIL;
  }

  EC_KEY_set_asn1_flag(ecKey, OPENSSL_EC_NAMED_CURVE);

  if (0x04 == pubKeyRaw[0])
  {
    BIGNUM* x = BN_bin2bn((unsigned char*)&pubKeyRaw[1], ByteSize, NULL);
    BIGNUM* y = BN_bin2bn((unsigned char*)&pubKeyRaw[1 + ByteSize], ByteSize, NULL);

    if ((retVal = EC_KEY_set_public_key_affine_coordinates(ecKey, x, y)) != SUCCESS)
    {
      WRITE_LOG("Error: EC_KEY affine key coordinates failed, returned (%d) !", retVal);
    }

    BN_free(x);
    BN_free(y);
  }

  // assining created ec key to evp key
  EVP_PKEY_assign_EC_KEY(Pkey, ecKey);
  return SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
void CSRCreation::CreateSubject()
{
  BEGIN_LOG;
  X509_NAME* x509_name = X509_REQ_get_subject_name(X509_req);

  if(SUCCESS != (X509_NAME_add_entry_by_txt(x509_name, "C", MBSTRING_ASC, (const unsigned char*)CountryName.c_str(), -1, -1, 0)))
    WRITE_LOG("Error :while creating subject Country value not set !!");

  if(SUCCESS != (X509_NAME_add_entry_by_txt(x509_name, "ST", MBSTRING_ASC, (const unsigned char*)State.c_str(), -1, -1, 0)))
    WRITE_LOG("Error :while creating subject State value not set !!");

  if(SUCCESS != (X509_NAME_add_entry_by_txt(x509_name, "L", MBSTRING_ASC, (const unsigned char*)Location.c_str(), -1, -1, 0)))
    WRITE_LOG("Error :while creating subject Location value not set!!");

  if(SUCCESS != (X509_NAME_add_entry_by_txt(x509_name, "OU", MBSTRING_ASC, (const unsigned char*)OrganizationalUnitName.c_str(), -1, -1, 0)))
    WRITE_LOG("Error :while creating subject Organization Unit value not set!!");

  if(SUCCESS != (X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC, (const unsigned char*)CommonName.c_str(), -1, -1, 0)))
    WRITE_LOG("Error : while creating subject Common Name value not set!!");

  if(SUCCESS != (X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC, (const unsigned char*)OrganizationName.c_str(), -1, -1, 0)))
    WRITE_LOG("Error :while creating subject Organization value not set!!");
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
string CSRCreation::PrepareCSR()
{
  BEGIN_LOG;
  unsigned char *csrReqInfo = NULL;
  int csrReqInfoSize = i2d_X509_REQ_INFO(X509_req->req_info, &csrReqInfo);
  if (0 >= csrReqInfoSize)
  {
    WRITE_LOG("Error: i2d_X509_REQ_INFO returnd 0");
    return "";
  }

 
  ofstream createCsrFile("CertReqInfo.der", std::ofstream::out | std::ofstream::binary);
  createCsrFile.write(reinterpret_cast<const char*>(csrReqInfo), csrReqInfoSize);
  createCsrFile.close();

  // Now hash the ReqInfo data with SH256.
  vector<unsigned char> hashBlob(SHA256_DIGEST_LENGTH);
  Sha256(hashBlob.data(), csrReqInfo, csrReqInfoSize);

  BIO *bmem, *b64;
  BUF_MEM *bptr;

  // Use OpenSSL to base64 encode the hashed data.
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);

  // BIO write
  if (0 >= (BIO_write(b64, reinterpret_cast<unsigned char*>(hashBlob.data()), hashBlob.size())))
  {
    WRITE_LOG("Error: BIO_write for encoding failed !");
    return "";
  }

  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);
  string base64Hash(bptr->data, bptr->length);
  BIO_free_all(b64);

  return base64Hash;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
void CSRCreation::CreateTempConfig()
{
  // creating SAN config file to add Subject alternative fields into Certificate
  ofstream sanFile("subjectAlterNative.cfg");
  sanFile << "req_extensions = v3_req\n";
  sanFile << "[v3_req]\n";
  sanFile << "basicConstraints = CA:TRUE, pathlen : 0\n";
  sanFile << "keyUsage = digitalSignature, keyEncipherment, keyCertSign, cRLSign\n";
  sanFile << "subjectKeyIdentifier = hash\n";
  sanFile << "authorityKeyIdentifier = keyid, issuer\n";
  sanFile << "subjectAltName = dirName:dir_sect\n";
  sanFile << "[dir_sect]\n";
  sanFile << "C = " << CountryName.c_str() << '\n';
  sanFile << "O = " << OrganizationName.c_str() << '\n';
  sanFile << "OU = " << OrganizationName.c_str() << '\n';
  sanFile << "CN = " << CommonName.c_str() << '\n';
  sanFile << "L = " << Location.c_str() << '\n';
  sanFile.close();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
vecString CSRCreation::ParseSubject(const string& subjectStr, const string& delimiters)
{
  vecString parseSubVec;
  string::size_type start = 0;
  int pos = subjectStr.find_first_of(delimiters, start);

  while (pos != string::npos)
  {
    if (pos != start) // ignore empty tokens
      parseSubVec.emplace_back(subjectStr, start, pos - start);
    start = pos + 1;
    pos = subjectStr.find_first_of(delimiters, start);
  }

  if (start < subjectStr.length()) // ignore trailing delimiter
    parseSubVec.emplace_back(subjectStr, start, subjectStr.length() - start); // add what's left of the string

  return parseSubVec;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
void CSRCreation::AssignSubjectFields(vecString& subject)
{
  vecString::iterator itr;

  if ((itr = find(subject.begin(), subject.end(), "C")) != subject.end())
    CountryName = *(++itr);

  if ((itr = find(subject.begin(), subject.end(), "CN")) != subject.end())
    CommonName = *(++itr);

  if ((itr = find(subject.begin(), subject.end(), "O")) != subject.end())
    OrganizationName = *(++itr);

  if ((itr = find(subject.begin(), subject.end(), "OU")) != subject.end())
    OrganizationalUnitName = *(++itr);

  if ((itr = find(subject.begin(), subject.end(), "S")) != subject.end())
    State = *(++itr);

  if ((itr = find(subject.begin(), subject.end(), "L")) != subject.end())
    Location = *(++itr);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
void CSRCreation::Sha256(unsigned char* hashOut, const unsigned char* certReqInfo, int certReqInfolength)
{
  BEGIN_LOG;
  SHA256_CTX sha256;

  SHA256_Init(&sha256);
  SHA256_Update(&sha256, certReqInfo, certReqInfolength);
  if(FAIL == SHA256_Final(hashOut, &sha256))
    WRITE_LOG("Error: Hash could not be fetched !");
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
X509_REQ* CSRCreation::GetX509Req() const
{
  return X509_req;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
string CSRCreation::GetMacId() const
{
  return CommonName;
}
