#define UNICODE
#define _UNICODE

#include "include/certificate_reader.h"
#include "sdk\src\signature\include\wintrust_validator.h"

#include <string>
#include <wincrypt.h>
#include <minwindef.h>
#include <wintrust.h>
#include <softpub.h>

cr::CertificateInfo cr::CertificateReader::readCertificate(const std::filesystem::path &file_path)
{
  WINTRUST_DATA WinTrustData;
  PCCERT_CONTEXT CertificateContext;

  CertificateInfo CertificateInfo{};

  WinTrustData = wtv::WinTrustValidator::getWintrustData(file_path);
  CertificateContext = extractCertificateContext(WinTrustData);

  CertificateInfo.Subject = cr::CertificateReader::getSubject(CertificateContext);
  CertificateInfo.Issuer = cr::CertificateReader::getSubject(CertificateContext);

  // MARK: COLETAR INFOS DO CERTIFICATE_CONTEXT
}

PCCERT_CONTEXT cr::CertificateReader::extractCertificateContext(WINTRUST_DATA &WinTrustData)
{
  if (WinTrustData.hWVTStateData == NULL)
  {
    return nullptr;
  }

  CRYPT_PROVIDER_DATA *ProviderData =
      WTHelperProvDataFromStateData(
          WinTrustData.hWVTStateData);

  if (ProviderData == nullptr)
  {
    return nullptr;
  }

  CRYPT_PROVIDER_SGNR *ProviderSigner =
      WTHelperGetProvSignerFromChain(
          ProviderData,
          0,
          FALSE,
          0);

  if (ProviderSigner == nullptr)
  {
    return nullptr;
  }

  CRYPT_PROVIDER_CERT *ProviderCertificate =
      WTHelperGetProvCertFromChain(
          ProviderSigner,
          0);

  if (ProviderCertificate == nullptr)
  {
    return nullptr;
  }

  return ProviderCertificate->pCert;
}

std::string cr::CertificateReader::getSubject(PCCERT_CONTEXT certificate_context)
{
  if (certificate_context == nullptr)
    return {};

  // Pode dar erro por estar usando o MSYSTEM MINGW64 em vez do MSYSTEM UCRT64
  DWORD size = CertGetNameStringW(
      certificate_context,
      CERT_NAME_SIMPLE_DISPLAY_TYPE,
      0,
      nullptr,
      nullptr,
      0);

  if (size == 0)
    return {};

  std::wstring subject(size, L'\0');

  CertGetNameStringW(
      certificate_context,
      CERT_NAME_SIMPLE_DISPLAY_TYPE,
      0,
      nullptr,
      subject.data(),
      size);

  return std::string(subject.begin(), subject.end() - 1);
}

std::string cr::CertificateReader::getIssuer(PCCERT_CONTEXT certificate_context)
{
  if (certificate_context == nullptr)
    return {};

  DWORD size = CertGetNameStringW(
      certificate_context,
      CERT_NAME_SIMPLE_DISPLAY_TYPE,
      CERT_NAME_ISSUER_FLAG,
      nullptr,
      nullptr,
      0);

  if (size == 0)
    return {};

  std::wstring issuer(size, L'\0');

  CertGetNameStringW(
      certificate_context,
      CERT_NAME_SIMPLE_DISPLAY_TYPE,
      CERT_NAME_ISSUER_FLAG,
      nullptr,
      issuer.data(),
      size);

  return std::string(issuer.begin(), issuer.end() - 1);
}