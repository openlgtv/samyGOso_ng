add_executable(samyGOso samyGOso.c sc.c nxjson/nxjson.c)
set_target_properties(samyGOso PROPERTIES COMPILE_FLAGS "-O2")
target_link_libraries(samyGOso dl)

add_library(inj_common hook.c log.c)
set_property(TARGET inj_common PROPERTY POSITION_INDEPENDENT_CODE ON)