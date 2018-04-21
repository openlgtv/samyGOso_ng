set(samyGOso_sources samyGOso.c sc.c nxjson/nxjson.c)
if(TARGET_ARM)
	list(APPEND samyGOso_sources sc_arm.S)
elseif(TARGET_AMD64) # WARNING: not completed yet
	list(APPEND samyGOso_sources sc_amd64.S)
endif()
add_executable(samyGOso ${samyGOso_sources})
set_property(TARGET samyGOso PROPERTY POSITION_INDEPENDENT_CODE ON)

#set_target_properties(samyGOso PROPERTIES COMPILE_FLAGS "-O2")
target_link_libraries(samyGOso dl)

#get_target_property(LINK_FLAGS samyGOso LINK_FLAGS)
set_target_properties(samyGOso PROPERTIES LINK_FLAGS "-T ${CMAKE_CURRENT_SOURCE_DIR}/core.ld")

add_library(inj_common hook.c log.c)
set_property(TARGET inj_common PROPERTY POSITION_INDEPENDENT_CODE ON)