add_library(signature_analyzer_sdk STATIC
  # src/signature/signature_analyzer.cpp
  src/signature/wintrust_validator.cpp
  src/certificate/certificate_reader.cpp
)

target_include_directories(signature_analyzer_sdk
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(signature_analyzer_sdk
    PUBLIC
        wintrust
        crypt32
)