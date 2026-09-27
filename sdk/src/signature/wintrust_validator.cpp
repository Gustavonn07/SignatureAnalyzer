//-------------------------------------------------------------------
// Copyright (C) Microsoft.  All rights reserved.
// Example of verifying the embedded signature of a PE file by using
// the WinVerifyTrust function.

// Modificado para validação de arquivos PE seguindo o padrão do projeto.

#include "include/wintrust_validator.h"
#include "include/signature_status.h"

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

WINTRUST_DATA wtv::WinTrustValidator::getWintrustData(const std::filesystem::path &file_path)
{
  WINTRUST_FILE_INFO FileData;
  WINTRUST_DATA WinTrustData;

  memset(
      &FileData,
      0,
      sizeof(FileData));

  FileData.cbStruct = sizeof(FileData);
  FileData.pcwszFilePath = file_path.c_str();
  FileData.hFile = NULL;
  FileData.pgKnownSubject = NULL;

  memset(
      &WinTrustData,
      0,
      sizeof(WinTrustData));

  WinTrustData.cbStruct = sizeof(WinTrustData);

  WinTrustData.pPolicyCallbackData = NULL;
  WinTrustData.pSIPClientData = NULL;
  WinTrustData.dwUIChoice = WTD_UI_NONE;
  WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
  WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
  WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
  WinTrustData.hWVTStateData = NULL;
  WinTrustData.pwszURLReference = NULL;
  WinTrustData.dwUIContext = 0;
  WinTrustData.pFile = &FileData;

  return WinTrustData;
}

SignatureStatus wtv::WinTrustValidator::validateSignature(const std::filesystem::path &file_path)
{
  LONG lStatus;
  DWORD dwLastError;
  SignatureStatus status;
  WINTRUST_DATA WinTrustData;

  WinTrustData = wtv::WinTrustValidator::getWintrustData(file_path);

  GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

  lStatus = WinVerifyTrust(
      NULL,
      &WVTPolicyGUID,
      &WinTrustData);

  switch (lStatus)
  {
  case ERROR_SUCCESS:
  {
    status = SignatureStatus::Status_Valid;
    break;
  }

  case TRUST_E_NOSIGNATURE:
  {
    dwLastError = GetLastError();

    if (
        TRUST_E_NOSIGNATURE == dwLastError ||
        TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
        TRUST_E_PROVIDER_UNKNOWN == dwLastError)
    {
      status = SignatureStatus::Status_NotSigned;
    }
    else
    {
      status = SignatureStatus::Status_Error;
    }

    break;
  }

  case TRUST_E_EXPLICIT_DISTRUST:
  {
    status = SignatureStatus::Status_Revoked;
    break;
  }

  case TRUST_E_SUBJECT_NOT_TRUSTED:
  {
    status = SignatureStatus::Status_Untrusted;
    break;
  }

  case CRYPT_E_SECURITY_SETTINGS:
  {
    status = SignatureStatus::Status_Invalid;
    break;
  }

  default:
  {
    status = SignatureStatus::Status_Error;
    break;
  }
  }

  WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

  lStatus = WinVerifyTrust(
      NULL,
      &WVTPolicyGUID,
      &WinTrustData);

  return status;
}
