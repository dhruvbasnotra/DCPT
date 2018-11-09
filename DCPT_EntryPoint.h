
#ifndef DCPT_ENTRY_POINT_H
#define DCPT_ENTRY_POINT_H

#ifdef __cplusplus
extern "C"
{
#endif

  __declspec(dllexport)  const char* getDevInfoToSign(const char*  controllerName, const char* serialNumber, const char* subject,
                                                      const char* internalChipNumber,  const char* factoryName, const char* factoryAddress,
                                                      const char* factoryStationId, const char* controllerMACId, const char* otherRemarks,
                                                      const char* otherRemarks2, const char*  publicKey);

  __declspec(dllexport)  const char*  getCertificate(const char* sigValBase64, const char* secPIN);

  __declspec(dllexport)  const char* getRootCACertificate();

#ifdef __cplusplus
}
#endif

#endif // end of DCPT_ENTRY_POINT_H
