#ifndef WIN_TRUST_VALIDATOR
#define WIN_TRUST_VALIDATOR

#include <filesystem>

#include "sdk\include\signature-analyser\signature_status.h"

namespace wtv {

class WinTrustValidator 
{
  public:
  SignatureStatus validateSignature(const std::filesystem::path& file);
};

} // namespace wtv

#endif