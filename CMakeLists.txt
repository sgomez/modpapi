PROJECT (mod_papi)
CMAKE_MINIMUM_REQUIRED(VERSION 2.4)
INCLUDE (${CMAKE_ROOT}/Modules/FindPkgConfig.cmake)
INCLUDE (${CMAKE_ROOT}/Modules/UsePkgConfig.cmake)

SET(CMAKE_CXX_FLAGS_DEBUG 
      "-g -Wall -g3 -ggdb -gdwarf-2 -Wunused-variable -Wno-unknown-pragmas -Wno-system-headers -std=c99"
      CACHE STRING "Debug builds CMAKE CXX flags " FORCE )
SET(CMAKE_C_FLAGS_DEBUG "-g -Wall -g3 -ggdb -gdwarf-2 -std=c99"
      CACHE STRING "Flags used by the compiler during Debug builds." FORCE )

PKG_CHECK_MODULES(LIBCURL REQUIRED libcurl>=7.0.0)
IF(LIBCURL_FOUND)
	STRING (REGEX REPLACE ";" " " LIBCURL_CFLAGS "${LIBCURL_CFLAGS}" "")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBCURL_CFLAGS}")
	STRING (REGEX REPLACE ";" " " LIBCURL_LDFLAGS "${LIBCURL_LDFLAGS}" "")
	SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LIBCURL_LDFLAGS}")
ELSE(LIBCURL_FOUND)
	MESSAGE("Cannot find libcurl version 7.0.0 or above")
ENDIF(LIBCURL_FOUND)

PKG_CHECK_MODULES(PCRE REQUIRED libpcre>=6.0)
IF(PCRE_FOUND)
	STRING (REGEX REPLACE ";" " " PCRE_CFLAGS "${PCRE_CFLAGS}" "")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${PCRE_CFLAGS}")
	STRING (REGEX REPLACE ";" " " PCRE_LDFLAGS "${PCRE_LDFLAGS}" "")
	SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${PCRE_LDFLAGS}")
ELSE(PCRE_FOUND)
	MESSAGE("Cannot find libpcre version 6.0 or above")
ENDIF(PCRE_FOUND)

PKG_CHECK_MODULES (APR REQUIRED apr-1>=1.2.0)
IF(APR_FOUND)
	STRING (REGEX REPLACE ";" " " APR_CFLAGS "${APR_CFLAGS}"  "")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${APR_CFLAGS}")
	STRING (REGEX REPLACE ";" " " APR_LDFLAGS "${APR_LDFLAGS}"  "")
	SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${APR_LDFLAGS}")
ELSE(APR_FOUND)
	MESSAGE("Cannot find apr-1 version 1.2.0 or above")
ENDIF(APR_FOUND)

PKG_CHECK_MODULES (APR-VERSION apr-1>=1.2.8)
IF (APR-VERSION_FOUND)
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAPR_DBD_SQLITE3")
ELSE (APR-VERSION_FOUND)
	MESSAGE("apr-1 version 1.2.8 or above recomended, you have a older one.")
ENDIF(APR-VERSION_FOUND)

# MCRYPT
FIND_PROGRAM(LIBMCRYPT_CONFIG libmcrypt-config)
IF (LIBMCRYPT_CONFIG)
        EXEC_PROGRAM(${LIBMCRYPT_CONFIG}
                ARGS "--cflags"
                OUTPUT_VARIABLE LIBMCRYPT_CONFIG_CFLAGS)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBMCRYPT_CONFIG_CFLAGS}")
        EXEC_PROGRAM(${LIBMCRYPT_CONFIG}
                ARGS "--libs"
                OUTPUT_VARIABLE LIBMCRYPT_CONFIG_LIBS)
        SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LIBMCRYPT_CONFIG_LIBS}")
ELSE(LIBMCRYPT_CONFIG)
        MESSAGE(SEND_ERROR "Cannot find libmcrypt-config anywhere in your path.  Please update your path to include the directory containing the script.")
ENDIF(LIBMCRYPT_CONFIG)

# APACHE2
FIND_PROGRAM(APXS2 apxs2)
IF (APXS2)
        EXEC_PROGRAM(${APXS2} 
                ARGS "-q CFLAGS"
                OUTPUT_VARIABLE APXS2_C_FLAGS)
        EXEC_PROGRAM(${APXS2} 
                ARGS "-q INCLUDEDIR"
                OUTPUT_VARIABLE APXS2_INCLUDEDIRS)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${APXS2_C_FLAGS} -I${APXS2_INCLUDEDIRS}")
        # apxs2 -q LDFLAGS outputs only a newline which breaks then CMAKE_SHARED_LINKER_FLAGS
        #EXEC_PROGRAM(${APXS2} 
        #       ARGS "-q LDFLAGS"
        #       OUTPUT_VARIABLE APXS2_LDFLAGS)
        #SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${APXS2_LDFLAGS}")
        EXEC_PROGRAM(${APXS2}
                ARGS "-q libexecdir"
                OUTPUT_VARIABLE MOD_DIR)
        SET(APACHE_MODULE_DIR "${MOD_DIR}" CACHE PATH
                        "Installation directory for Apache modules")
ELSE(APXS2)
        MESSAGE(SEND_ERROR "Cannot find apxs2 anywhere in your path.  Please update your path to include the directory containing the script.")
ENDIF(APXS2)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR})
SET(CMAKE_SHARED_LIBRARY_PREFIX "")
SET(CMAKE_INSTALL_PREFIX "" CACHE PATH
                "Install path prefix, prepended onto install directories."
                FORCE)
SET(INSTALL_INCLUDE_DIR /usr/include CACHE PATH
                "Installation directory for header files")

add_library (   mod_papi SHARED
		mod_papi.c                 
		mod_papi_crypt.c           
		mod_papi_redirect_gpoa.c   
		mod_papi_config.c          
		mod_papi_poa.c             
		mod_papi_utils.c           
		mod_papi_cookie_handler.c  
		mod_papi_post_handler.c    )

INSTALL_TARGETS(${APACHE_MODULE_DIR} mod_papi)

