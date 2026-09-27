#ifndef CERTIFICATE_READER
#define CERTIFICATE_READER

#include "sdk\src\signature\include\signature_status.h"

#include <wintrust.h>
#include <filesystem>
#include <string>
#include <wincrypt.h>
#include <minwindef.h>

namespace cr
{
  struct CertificateInfo
  {
    std::string Subject;
    std::string Issuer;
    std::string SerialNumber;
    std::string Thumbprint;

    std::string ValidFrom;
    std::string ValidTo;

    std::string SignatureAlgorithm;
    std::string PublicKeyAlgorithm;
    uint32_t PublicKeySize;

    std::string Version;
  };

  class CertificateReader
  {
  public:
    cr::CertificateInfo readCertificate(const std::filesystem::path &file_path);
    PCCERT_CONTEXT extractCertificateContext(WINTRUST_DATA &wintrust_data);

  private:
    std::string getSubject(PCCERT_CONTEXT certificate_context);
    std::string getIssuer(PCCERT_CONTEXT certificate_context);
  };

} // namespace cr

#endif