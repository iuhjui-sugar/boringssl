include_directories(../../include)

add_library(
  bcm_c_generated_asm

  STATIC

  bcm.c
)

SET_TARGET_PROPERTIES(bcm_c_generated_asm PROPERTIES COMPILE_OPTIONS "-S")
SET_TARGET_PROPERTIES(bcm_c_generated_asm PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(
  bcm_c_obj

  STATIC

  bcm.c
)

SET_TARGET_PROPERTIES(bcm_c_obj PROPERTIES POSITION_INDEPENDENT_CODE ON)

set(
  BCM_ASM_SOURCES

  ${CMAKE_CURRENT_BINARY_DIR}/sha256-x86_64.S
)

function(JOIN VALUES GLUE OUTPUT)
  string (REPLACE ";" "${GLUE}" _TMP_STR "${VALUES}")
  set (${OUTPUT} "${_TMP_STR}" PARENT_SCOPE)
endfunction()

JOIN("${BCM_ASM_SOURCES}" "," BCM_ASM_SOURCES_COMMA_SEP)

perlasm(sha256-x86_64.S sha/asm/sha512-x86_64.pl)

add_custom_command(
  OUTPUT bcm-delocated.S
  COMMAND ${GO_EXECUTABLE} run crypto/fipsmodule/delocate.go -a $<TARGET_FILE:bcm_c_generated_asm> -as ${BCM_ASM_SOURCES_COMMA_SEP} -o ${CMAKE_CURRENT_BINARY_DIR}/bcm-delocated.S
  DEPENDS bcm_c_generated_asm ${BCM_ASM_SOURCES} delocate.go
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_library(
  bcm

  bcm-delocated.S
)

SET_TARGET_PROPERTIES(bcm PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(bcm PROPERTIES LINKER_LANGUAGE C)

add_executable(
  module_load_test

  module_load_test.c
)

SET_TARGET_PROPERTIES(bcm_c_generated_asm PROPERTIES COMPILE_FLAGS "-pie")
target_link_libraries(module_load_test bcm)
target_link_libraries(module_load_test crypto)
