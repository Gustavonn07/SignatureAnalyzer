#ifndef WIN_TRUST_VALIDATOR
#define WIN_TRUST_VALIDATOR

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <filesystem>

#include "signature/signature_status.h"

namespace wtv
{

  class WinTrustValidator
  {
  public:
    static WINTRUST_DATA getWintrustData(const std::filesystem::path &file_path);
    SignatureStatus validateSignature(const std::filesystem::path &file_path);
  };

} // namespace wtv

#endif