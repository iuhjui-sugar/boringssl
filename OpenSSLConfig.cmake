include(${CMAKE_CURRENT_LIST_DIR}/OpenSSLTargets.cmake)

# Recursively collect dependency locations for the imported targets.
macro(_openssl_config_libraries libraries target)
  get_property(_DEPS TARGET ${target} PROPERTY INTERFACE_LINK_LIBRARIES)
  foreach(_DEP ${_DEPS})
    if(TARGET ${_DEP})
      _openssl_config_libraries(${libraries} ${_DEP})
    else()
      set(_LOC ${_DEP})
    endif()
    list(APPEND ${libraries} ${_LOC})
  endforeach()
  get_property(_LOC TARGET ${target} PROPERTY LOCATION)
  list(APPEND ${libraries} ${_LOC})
  list(REMOVE_DUPLICATES ${libraries})
endmacro()

set(OPENSSL_FOUND YES)
get_property(OPENSSL_INCLUDE_DIR TARGET OpenSSL::SSL PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
get_property(OPENSSL_CRYPTO_LIBRARY TARGET OpenSSL::Crypto PROPERTY LOCATION)
_openssl_config_libraries(OPENSSL_CRYPTO_LIBRARIES OpenSSL::Crypto)

get_property(OPENSSL_SSL_LIBRARY TARGET OpenSSL::Crypto PROPERTY LOCATION)
_openssl_config_libraries(OPENSSL_SSL_LIBRARIES OpenSSL::SSL)

set(OPENSSL_LIBRARIES ${OPENSSL_CRYPTO_LIBRARIES} ${OPENSSL_SSL_LIBRARIES})
list(REMOVE_DUPLICATES OPENSSL_LIBRARIES)

set(_DEP)
set(_DEPS)
set(_LOC)
