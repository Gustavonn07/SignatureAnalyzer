add_executable(signature_analyzer_api
  src/main.cpp
)

target_link_libraries(signature_analyzer_api
    PRIVATE
        signature_analyzer_sdk
)