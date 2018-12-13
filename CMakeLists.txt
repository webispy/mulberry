CMAKE_MINIMUM_REQUIRED(VERSION 3.1)
PROJECT(mulberry)

INCLUDE(GNUInstallDirs)
INCLUDE(FindPkgConfig)

SET(VERSION_MAJOR 0)
SET(VERSION_MINOR 1)
SET(VERSION_PATCH 0)
SET(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
SET(version ${VERSION})

SET(prefix ${CMAKE_INSTALL_PREFIX})
SET(bindir "${prefix}/${CMAKE_INSTALL_BINDIR}")

pkg_check_modules(pkgs REQUIRED
	glib-2.0
	gio-2.0
	gio-unix-2.0
	gthread-2.0)
FOREACH(flag ${pkgs_CFLAGS})
	ADD_COMPILE_OPTIONS(${flag})
ENDFOREACH(flag)

# Common compile options
ADD_COMPILE_OPTIONS(
	-g -Os -std=gnu99
	-fdata-sections -ffunction-sections -Wl,--gc-sections
	-fPIC

	# Increased reliability of backtraces
	-fasynchronous-unwind-tables

	# Options from IoTivity-constrained
	-fno-asynchronous-unwind-tables -fno-omit-frame-pointer
	-ffreestanding -fno-stack-protector -fno-reorder-functions
	-fno-defer-pop -fno-strict-overflow

	# Turn on all warnings and treat all warnings as errors.
	-Werror -Wall -Wextra

	# Additiional warnings
	-Wunreachable-code -Wpointer-arith -Waggregate-return
	-Wformat=2

	# Not warnings
	-Wno-missing-field-initializers
	-Wno-unused-parameter)

# Common link options
LINK_LIBRARIES(-Wl,--as-needed)

# RPATH is useful only for testing without installation. Please use the
# '-DNO-RPATH' option for debian packaging.
IF(NOT NO-RPATH)
LINK_LIBRARIES(-Wl,--rpath=${CMAKE_BINARY_DIR})
ENDIF()

# Add __FILENAME__ macro to use path from source directory instead of full path
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__='\"$(subst $(realpath ${CMAKE_SOURCE_DIR})/,,$(abspath $<))\"'")

# Run-time buffer overflow detection
ADD_DEFINITIONS(-D_FORTIFY_SOURCE=2)

ADD_DEFINITIONS(-DEXPORT_API=__attribute__\(\(visibility\(\"default\"\)\)\))
ADD_DEFINITIONS(-D__UNUSED__=__attribute\(\(unused\)\))
ADD_DEFINITIONS(-DVERSION=\"${VERSION}\")
ADD_DEFINITIONS(-DSTORAGE_PATH=\"/var/lib/${PROJECT_NAME}\")

ADD_DEFINITIONS(-DCONFIG_LOG_ANSICOLOR)
ADD_DEFINITIONS(-DCONFIG_PERMANENT_UUID)
ADD_DEFINITIONS(-DCONFIG_CTT_EXCEPTION)
#ADD_DEFINITIONS(-DCONFIG_IOTIVITY_COMPATIBILITY)
ADD_DEFINITIONS(-DCONFIG_EVENTFD)

# IoTivity-constrained definitions
ADD_DEFINITIONS(-DOC_DYNAMIC_ALLOCATION -DOC_SECURITY -DOC_PKI -DOC_SERVER -DOC_CLIENT -DOC_IDD_FILE)
#ADD_DEFINITIONS(-DOC_IPV4 -DOC_TCP)
#ADD_DEFINITIONS(-DOC_DEBUG)

INCLUDE_DIRECTORIES(
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/src
	${CMAKE_SOURCE_DIR}/external/cJSON
	${CMAKE_SOURCE_DIR}/external/iotivity-constrained
	${CMAKE_SOURCE_DIR}/external/iotivity-constrained/port/linux
	${CMAKE_SOURCE_DIR}/external/iotivity-constrained/deps/tinycbor/src
	${CMAKE_SOURCE_DIR}/external/iotivity-constrained/include)

# Build IoTivity-constrained sources
ADD_SUBDIRECTORY(external)

# mulberry library
SET(SRCS
	src/iotivity.c
	src/log.c
	src/util.c
	src/storage.c
	src/manager.c
	src/server_device.c
	src/resource.c
	src/client_device.c
	src/discovered_device.c
	src/object.c)
ADD_LIBRARY(libmulberry SHARED ${SRCS}
	$<TARGET_OBJECTS:objcjson>
	$<TARGET_OBJECTS:objapi_client_server>
	$<TARGET_OBJECTS:objmessaging_client_server>
	$<TARGET_OBJECTS:objport_client_server>
	$<TARGET_OBJECTS:objutil>
	$<TARGET_OBJECTS:objcbor>
	$<TARGET_OBJECTS:objsecurity_client_server>
	$<TARGET_OBJECTS:objdtls>)
TARGET_COMPILE_OPTIONS(libmulberry PRIVATE
	-Wmissing-prototypes -Wmissing-declarations -Wswitch-default
	-fvisibility=hidden)
TARGET_LINK_LIBRARIES(libmulberry PUBLIC ${pkgs_LDFLAGS} "-ldl -lm")
SET_TARGET_PROPERTIES(libmulberry
	PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR} OUTPUT_NAME mulberry)
INSTALL(TARGETS libmulberry LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

# Executable daemon
ADD_EXECUTABLE(${PROJECT_NAME} daemon/main.c)
TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE
	# Full ASLR for executables
	-fpie -Wl,-pie)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${pkgs_LDFLAGS} "-L${CMAKE_BINARY_DIR} -lmulberry" )
INSTALL(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
ADD_DEPENDENCIES(${PROJECT_NAME} libmulberry)

# Additiional tools
SET(ADDITIONAL_TOOLS onboarding_tool client_linux server_linux)
SET(onboarding_tool
	external/iotivity-constrained/onboarding_tool/obtmain.c)
SET(client_linux
	external/iotivity-constrained/apps/client_linux.c)
SET(server_linux
	external/iotivity-constrained/apps/server_linux.c)
FOREACH(list_name IN LISTS ADDITIONAL_TOOLS)
	ADD_EXECUTABLE(${list_name} ${${list_name}})
	TARGET_LINK_LIBRARIES(${list_name} "-L${CMAKE_BINARY_DIR} -lmulberry -pthread")
	INSTALL(TARGETS ${list_name} RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/mulberry/)
	ADD_DEPENDENCIES(${list_name} libmulberry)
ENDFOREACH()

# Configuration files
CONFIGURE_FILE(src/${PROJECT_NAME}.service.in ${PROJECT_NAME}.service @ONLY)
INSTALL(FILES ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.service
	DESTINATION /lib/systemd/system)
INSTALL(FILES src/${PROJECT_NAME}.conf
	DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/dbus-1/system.d)

# Examples (except directory)
FILE(GLOB examples "${CMAKE_SOURCE_DIR}/examples/*")
FOREACH(item IN LISTS examples)
	IF(IS_DIRECTORY ${item})
		LIST(REMOVE_ITEM examples ${item})
	ENDIF()
ENDFOREACH()
LIST(REMOVE_ITEM examples node_modules)
INSTALL(PROGRAMS ${examples}
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/mulberry/)

