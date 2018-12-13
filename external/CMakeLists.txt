
EXECUTE_PROCESS(
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	COMMAND git submodule update --init)

SET(external_path "${CMAKE_CURRENT_SOURCE_DIR}")
IF(NOT EXISTS ${external_path}/mark_patched.txt)
	MESSAGE("Reset external/iotivity-constrained")
	EXECUTE_PROCESS(WORKING_DIRECTORY ${external_path}/iotivity-constrained
		COMMAND git clean -fdx
		COMMAND git reset --hard)

	FILE(GLOB PATCH_FILES
		RELATIVE ${external_path}/patches
		patches/*.patch)
	LIST(SORT PATCH_FILES)

	FOREACH(p ${PATCH_FILES})
		MESSAGE("Applying ${p} ...")
		EXECUTE_PROCESS(WORKING_DIRECTORY ${external_path}/iotivity-constrained
			COMMAND patch -r - -s -N -p1 -i ../patches/${p})
	ENDFOREACH()

	EXECUTE_PROCESS(WORKING_DIRECTORY ${external_path}
		COMMAND touch mark_patched.txt)
ENDIF()

EXECUTE_PROCESS(
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/iotivity-constrained
	COMMAND git submodule update --init)

# util
SET(util_path "${CMAKE_CURRENT_SOURCE_DIR}/iotivity-constrained/util/")
ADD_LIBRARY(objutil OBJECT
	${util_path}/oc_etimer.c
	${util_path}/oc_list.c
	${util_path}/oc_memb.c
	${util_path}/oc_mmem.c
	${util_path}/oc_process.c
	${util_path}/oc_timer.c)
TARGET_INCLUDE_DIRECTORIES(objutil PUBLIC ${util_path}/)

# api
SET(api_path "${CMAKE_CURRENT_SOURCE_DIR}/iotivity-constrained/api/")
SET(api_srcs
	${api_path}/oc_base64.c
	${api_path}/oc_blockwise.c
	${api_path}/oc_buffer.c
	${api_path}/oc_client_api.c
	${api_path}/oc_collection.c
	${api_path}/oc_core_res.c
	${api_path}/oc_discovery.c
	${api_path}/oc_endpoint.c
	${api_path}/oc_helpers.c
	${api_path}/oc_introspection.c
	${api_path}/oc_main.c
	${api_path}/oc_network_events.c
	${api_path}/oc_rep.c
	${api_path}/oc_ri.c
	${api_path}/oc_server_api.c
	${api_path}/oc_session_events.c
	${api_path}/oc_uuid.c)
ADD_LIBRARY(objapi_client_server OBJECT ${api_srcs})

SET(messaging_path "${CMAKE_CURRENT_SOURCE_DIR}/iotivity-constrained/messaging/coap/")
SET(messaging_srcs
	${messaging_path}/coap.c
	${messaging_path}/engine.c
	${messaging_path}/observe.c
	${messaging_path}/separate.c
	${messaging_path}/transactions.c)
ADD_LIBRARY(objmessaging_client_server OBJECT ${messaging_srcs})

# deps
SET(deps_path "${CMAKE_CURRENT_SOURCE_DIR}/iotivity-constrained/deps/")
INCLUDE_DIRECTORIES(${deps_path}/mbedtls/include)

IF(NOT EXISTS ${deps_path}/mark_patched.txt)
	MESSAGE("Reset ${deps_path}/mbedtls")
	EXECUTE_PROCESS(WORKING_DIRECTORY ${deps_path}/mbedtls
		COMMAND git clean -fdx
		COMMAND git reset --hard)

	FILE(GLOB PATCH_FILES
		RELATIVE ${deps_path}/../
		${deps_path}/../patches/*.patch)
	LIST(SORT PATCH_FILES)

	FOREACH(p ${PATCH_FILES})
		MESSAGE("Applying ${p} ...")
		EXECUTE_PROCESS(WORKING_DIRECTORY ${deps_path}/mbedtls
			COMMAND patch -r - -s -N -p1 -i ${deps_path}/../${p})
	ENDFOREACH()

	EXECUTE_PROCESS(WORKING_DIRECTORY ${deps_path}
		COMMAND touch mark_patched.txt)
ENDIF()

SET(dtls_srcs
	${deps_path}/mbedtls/library/aes.c
	${deps_path}/mbedtls/library/aesni.c
	${deps_path}/mbedtls/library/arc4.c
	${deps_path}/mbedtls/library/asn1parse.c
	${deps_path}/mbedtls/library/asn1write.c
	${deps_path}/mbedtls/library/base64.c
	${deps_path}/mbedtls/library/bignum.c
	${deps_path}/mbedtls/library/blowfish.c
	${deps_path}/mbedtls/library/camellia.c
	${deps_path}/mbedtls/library/ccm.c
	${deps_path}/mbedtls/library/cipher.c
	${deps_path}/mbedtls/library/cipher_wrap.c
	${deps_path}/mbedtls/library/cmac.c
	${deps_path}/mbedtls/library/ctr_drbg.c
	${deps_path}/mbedtls/library/des.c
	${deps_path}/mbedtls/library/dhm.c
	${deps_path}/mbedtls/library/ecdh.c
	${deps_path}/mbedtls/library/ecdsa.c
	${deps_path}/mbedtls/library/ecjpake.c
	${deps_path}/mbedtls/library/ecp.c
	${deps_path}/mbedtls/library/ecp_curves.c
	${deps_path}/mbedtls/library/entropy.c
	${deps_path}/mbedtls/library/entropy_poll.c
	${deps_path}/mbedtls/library/error.c
	${deps_path}/mbedtls/library/gcm.c
	${deps_path}/mbedtls/library/havege.c
	${deps_path}/mbedtls/library/hmac_drbg.c
	${deps_path}/mbedtls/library/md.c
	${deps_path}/mbedtls/library/md2.c
	${deps_path}/mbedtls/library/md4.c
	${deps_path}/mbedtls/library/md5.c
	${deps_path}/mbedtls/library/md_wrap.c
	${deps_path}/mbedtls/library/oid.c
	${deps_path}/mbedtls/library/padlock.c
	${deps_path}/mbedtls/library/pem.c
	${deps_path}/mbedtls/library/pk.c
	${deps_path}/mbedtls/library/pk_wrap.c
	${deps_path}/mbedtls/library/pkcs12.c
	${deps_path}/mbedtls/library/pkcs5.c
	${deps_path}/mbedtls/library/pkparse.c
	${deps_path}/mbedtls/library/pkwrite.c
	${deps_path}/mbedtls/library/platform.c
	${deps_path}/mbedtls/library/ripemd160.c
	${deps_path}/mbedtls/library/rsa.c
	${deps_path}/mbedtls/library/sha1.c
	${deps_path}/mbedtls/library/sha256.c
	${deps_path}/mbedtls/library/sha512.c
	${deps_path}/mbedtls/library/threading.c
	${deps_path}/mbedtls/library/timing.c
	${deps_path}/mbedtls/library/version.c
	${deps_path}/mbedtls/library/version_features.c
	${deps_path}/mbedtls/library/xtea.c
	${deps_path}/mbedtls/library/pkcs11.c
	${deps_path}/mbedtls/library/x509.c
	${deps_path}/mbedtls/library/x509_crt.c
	${deps_path}/mbedtls/library/debug.c
	${deps_path}/mbedtls/library/net_sockets.c
	${deps_path}/mbedtls/library/ssl_cache.c
	${deps_path}/mbedtls/library/ssl_ciphersuites.c
	${deps_path}/mbedtls/library/ssl_cli.c
	${deps_path}/mbedtls/library/ssl_cookie.c
	${deps_path}/mbedtls/library/ssl_srv.c
	${deps_path}/mbedtls/library/ssl_ticket.c
	${deps_path}/mbedtls/library/ssl_tls.c
	${deps_path}/mbedtls/library/rsa_internal.c)
ADD_LIBRARY(objdtls OBJECT ${dtls_srcs})
TARGET_COMPILE_DEFINITIONS(objdtls PUBLIC "-D__OC_RANDOM")

ADD_LIBRARY(objcbor OBJECT
	${deps_path}/tinycbor/src/cborencoder.c
	${deps_path}/tinycbor/src/cborencoder_close_container_checked.c
	${deps_path}/tinycbor/src/cbortojson.c
	${deps_path}/tinycbor/src/cborparser_dup_string.c
	${deps_path}/tinycbor/src/cborpretty_stdio.c
	${deps_path}/tinycbor/src/cborpretty.c
	${deps_path}/tinycbor/src/cborerrorstrings.c
	${deps_path}/tinycbor/src/cborparser.c)
TARGET_COMPILE_OPTIONS(objcbor PUBLIC
	-Wno-implicit-function-declaration
)
# security
SET(security_path "${CMAKE_CURRENT_SOURCE_DIR}/iotivity-constrained/security/")
SET(security_srcs
	${security_path}/oc_acl.c
	${security_path}/oc_cred.c
	${security_path}/oc_doxm.c
	${security_path}/oc_pstat.c
	${security_path}/oc_tls.c
	${security_path}/oc_svr.c
	${security_path}/oc_store.c
	${security_path}/oc_pki.c
	${security_path}/oc_certs.c
	${security_path}/oc_sp.c
	${security_path}/oc_obt.c)
SET(security_client_srcs ${security_srcs})
ADD_LIBRARY(objsecurity_client_server OBJECT ${security_client_srcs})
TARGET_INCLUDE_DIRECTORIES(objsecurity_client_server PUBLIC
	${deps_path}/mbedtls/include)

# Porting layers
SET(port_path "${CMAKE_CURRENT_SOURCE_DIR}/iotivity-constrained/port/linux")
SET(port_srcs
	${port_path}/abort.c
	${port_path}/clock.c
	${port_path}/ipadapter.c
	${port_path}/random.c
	${port_path}/tcpadapter.c)
ADD_LIBRARY(objport_client_server OBJECT ${port_srcs})

# cJSON
SET(cjson_path "${CMAKE_CURRENT_SOURCE_DIR}/cJSON")
SET(cjson_srcs
	${cjson_path}/cJSON.c
	${cjson_path}/cJSON_Utils.c)
ADD_LIBRARY(objcjson OBJECT ${cjson_srcs})
