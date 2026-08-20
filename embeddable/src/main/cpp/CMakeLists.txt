cmake_minimum_required(VERSION 3.22)
project(teesim_embedded LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Weak-link NDK symbols newer than the minimum SDK
add_compile_definitions(__ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__)

# Set Android API level from ANDROID_PLATFORM
if(ANDROID_PLATFORM MATCHES "android-([0-9]+)")
  set(ANDROID_API_LEVEL "${CMAKE_MATCH_1}")
else()
  set(ANDROID_API_LEVEL "29")
endif()

# ---------------------------------------------------------------------------
# Rust TA (teesim-km) — imported static library
# ---------------------------------------------------------------------------
set(RUST_TA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../rust")
set(RUST_TA_INCLUDE "${RUST_TA_DIR}/teesim-km/include")

# Determine the Rust triple based on ABI
if(ANDROID_ABI STREQUAL "arm64-v8a")
  set(RUST_TRIPLE aarch64-linux-android)
elseif(ANDROID_ABI STREQUAL "x86_64")
  set(RUST_TRIPLE x86_64-linux-android)
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
  set(RUST_TRIPLE armv7-linux-androideabi)
elseif(ANDROID_ABI STREQUAL "x86")
  set(RUST_TRIPLE i686-linux-android)
else()
  message(FATAL_ERROR "Unsupported ABI: ${ANDROID_ABI}")
endif()

set(RUST_TA_LIB "${RUST_TA_DIR}/target/${RUST_TRIPLE}/release/libteesim_km.a")

# Custom target to build the Rust TA if not already present
add_custom_target(build_rust_ta
    BYPRODUCTS ${RUST_TA_LIB}
    COMMAND ${CMAKE_COMMAND} -E env
            ABI=${ANDROID_ABI}
            API=${ANDROID_API_LEVEL}
            NDK_HOME=${ANDROID_NDK}
            bash ${RUST_TA_DIR}/build.sh
    COMMENT "Building Rust TA for ${ANDROID_ABI}..."
    VERBATIM USES_TERMINAL)

# Import the static library as a CMake target
add_library(teesim_km STATIC IMPORTED GLOBAL)
set_target_properties(teesim_km PROPERTIES IMPORTED_LOCATION ${RUST_TA_LIB})
add_dependencies(teesim_km build_rust_ta)

# ---------------------------------------------------------------------------
# JNI shared library — the bridge between Java/Kotlin and the Rust TA
# ---------------------------------------------------------------------------
add_library(teesim_embedded SHARED
    teesim_embedded_jni.cpp
)
add_dependencies(teesim_embedded teesim_km)

target_include_directories(teesim_embedded PRIVATE
    ${RUST_TA_INCLUDE}
)

target_link_libraries(teesim_embedded PRIVATE
    teesim_km
    log
)

target_link_options(teesim_embedded PRIVATE
    -static-libstdc++
    # The Rust TA references BoringSSL symbols that resolve at runtime from
    # the system's libcrypto.so (always loaded in Android app processes).
    -Wl,-z,undefs
    -Wl,--gc-sections
)