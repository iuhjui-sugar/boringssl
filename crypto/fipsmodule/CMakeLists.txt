include_directories(../../include)

add_library(
  bcm_c_generated_asm

  STATIC

  bcm.c
)

SET_TARGET_PROPERTIES(bcm_c_generated_asm PROPERTIES COMPILE_FLAGS "-S")
SET_TARGET_PROPERTIES(bcm_c_generated_asm PROPERTIES POSITION_INDEPENDENT_CODE ON)

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
  OUTPUT bcm-asm.S
  COMMAND ${GO_EXECUTABLE} run crypto/bcm/delocate.go -a $<TARGET_FILE:bcm_c_generated_asm> -as ${BCM_ASM_SOURCES_COMMA_SEP} -o ${CMAKE_CURRENT_BINARY_DIR}/bcm-asm.S
  DEPENDS bcm_c_generated_asm ${BCM_ASM_SOURCES} delocate.go
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_library(
  bcm

  bcm-asm.S
)

SET_TARGET_PROPERTIES(bcm PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(bcm PROPERTIES LINKER_LANGUAGE C)

add_executable(
  bcm_stub

  test.c
)

target_link_libraries(bcm_stub bcm)
target_link_libraries(bcm_stub crypto)
