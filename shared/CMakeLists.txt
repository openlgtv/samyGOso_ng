set(PWD "${CMAKE_CURRENT_LIST_DIR}")
set(RELEASE_SPEC "${PWD}/RELEASE_API.h")
set(RELEASE_API "${CMAKE_CURRENT_BINARY_DIR}/RELEASE_API.c")

# Add API Generator, outputting API and depending on the SPEC
#add_custom_command(
#	OUTPUT ${RELEASE_API}
#	COMMAND php ${PWD}/apigen.php ${RELEASE_SPEC} ${RELEASE_API}
#	DEPENDS ${RELEASE_SPEC}
#)

# Same as above, but it's a target
#add_custom_target(RELEASE_API DEPENDS ${RELEASE_API})