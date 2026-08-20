/**
 * JNI bridge between the embedded TEESimulator Kotlin API and the Rust KeyMint TA.
 *
 * This library is loaded by the target APK via System.loadLibrary(). It wraps the
 * Rust TA's C ABI (teesim_km.h) and exposes a simple JNI surface for Java/Kotlin
 * callers. No root is required — everything runs in the app's own process.
 *
 * The TA uses BoringSSL symbols resolved at runtime from the system's libcrypto.so
 * (always loaded in Android app processes), so no crypto library is bundled.
 */

#include <jni.h>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include <mutex>

#include "teesim_km.h"

namespace {

// The TA handle, protected by a mutex for thread safety.
std::mutex g_ta_mutex;
Ta* g_ta = nullptr;
bool g_initialized = false;

// Convert Java byte array to C vector.
std::vector<uint8_t> jbyteArrayToVector(JNIEnv* env, jbyteArray arr) {
    if (!arr) return {};
    jsize len = env->GetArrayLength(arr);
    std::vector<uint8_t> v(len);
    env->GetByteArrayRegion(arr, 0, len, reinterpret_cast<jbyte*>(v.data()));
    return v;
}

// Convert C byte buffer to Java byte array.
jbyteArray vectorToJByteArray(JNIEnv* env, const uint8_t* data, size_t len) {
    if (!data || len == 0) return nullptr;
    jbyteArray arr = env->NewByteArray(len);
    if (arr) {
        env->SetByteArrayRegion(arr, 0, len, reinterpret_cast<const jbyte*>(data));
    }
    return arr;
}

// Fill a TsDeviceIds from Java string fields. Null/empty strings leave fields NULL/0.
void fillDeviceIds(JNIEnv* env, jobject idsObj, TsDeviceIds* ids) {
    memset(ids, 0, sizeof(*ids));

    if (!idsObj) return;

    jclass cls = env->GetObjectClass(idsObj);

    auto readField = [&](const char* fieldName, const uint8_t*& ptr, size_t& len) {
        jfieldID fid = env->GetFieldID(cls, fieldName, "Ljava/lang/String;");
        if (!fid) return;
        jstring str = (jstring)env->GetObjectField(idsObj, fid);
        if (!str) return;
        const char* utf = env->GetStringUTFChars(str, nullptr);
        if (utf) {
            size_t slen = strlen(utf);
            if (slen > 0) {
                uint8_t* buf = (uint8_t*)malloc(slen);
                memcpy(buf, utf, slen);
                ptr = buf;
                len = slen;
            }
            env->ReleaseStringUTFChars(str, utf);
        }
    };

    readField("brand", ids->brand, ids->brand_len);
    readField("device", ids->device, ids->device_len);
    readField("product", ids->product, ids->product_len);
    readField("serial", ids->serial, ids->serial_len);
    readField("imei", ids->imei, ids->imei_len);
    readField("imei2", ids->imei2, ids->imei2_len);
    readField("meid", ids->meid, ids->meid_len);
    readField("manufacturer", ids->manufacturer, ids->manufacturer_len);
    readField("model", ids->model, ids->model_len);
}

// Free device IDs allocated by fillDeviceIds.
void freeDeviceIds(TsDeviceIds* ids) {
    #define FREE_IF(ptr) do { if (ptr) { free((void*)(ptr)); } } while(0)
    FREE_IF(ids->brand); FREE_IF(ids->device); FREE_IF(ids->product);
    FREE_IF(ids->serial); FREE_IF(ids->imei); FREE_IF(ids->imei2);
    FREE_IF(ids->meid); FREE_IF(ids->manufacturer); FREE_IF(ids->model);
    #undef FREE_IF
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// JNI: Initialize the TA
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jboolean JNICALL
Java_org_matrix_teesim_embedded_TeeSimEmbedded_nativeInit(
    JNIEnv* env, jobject /*thiz*/,
    jbyteArray keyboxXml,
    jint securityLevel,
    jint osVersion,
    jint osPatchLevel,
    jint vendorPatchLevel,
    jint bootPatchLevel,
    jbyteArray vbKey,
    jbyteArray vbHash,
    jboolean deviceLocked,
    jint verifiedBootState,
    jint attestVersionTee,
    jint attestVersionStrongbox,
    jobject deviceIds)
{
    std::lock_guard<std::mutex> lock(g_ta_mutex);

    // Destroy any existing TA first
    if (g_ta) {
        teesim_km_destroy(g_ta);
        g_ta = nullptr;
        g_initialized = false;
    }

    std::vector<uint8_t> kb = jbyteArrayToVector(env, keyboxXml);
    if (kb.empty()) return JNI_FALSE;

    std::vector<uint8_t> vbk = jbyteArrayToVector(env, vbKey);
    std::vector<uint8_t> vbh = jbyteArrayToVector(env, vbHash);

    TsDeviceIds ids;
    fillDeviceIds(env, deviceIds, &ids);

    g_ta = teesim_km_init_ex(
        kb.data(), kb.size(),
        securityLevel,
        (uint32_t)osVersion,
        (uint32_t)osPatchLevel,
        (uint32_t)vendorPatchLevel,
        (uint32_t)bootPatchLevel,
        vbk.empty() ? nullptr : vbk.data(), vbk.size(),
        vbh.empty() ? nullptr : vbh.data(), vbh.size(),
        (bool)deviceLocked,
        (int32_t)verifiedBootState,
        (int32_t)attestVersionTee,
        (int32_t)attestVersionStrongbox,
        &ids
    );

    freeDeviceIds(&ids);

    g_initialized = (g_ta != nullptr);
    return g_initialized ? JNI_TRUE : JNI_FALSE;
}

// ---------------------------------------------------------------------------
// JNI: Simple init (with defaults)
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jboolean JNICALL
Java_org_matrix_teesim_embedded_TeeSimEmbedded_nativeInitSimple(
    JNIEnv* env, jobject /*thiz*/,
    jbyteArray keyboxXml)
{
    std::lock_guard<std::mutex> lock(g_ta_mutex);

    if (g_ta) {
        teesim_km_destroy(g_ta);
        g_ta = nullptr;
        g_initialized = false;
    }

    std::vector<uint8_t> kb = jbyteArrayToVector(env, keyboxXml);
    if (kb.empty()) return JNI_FALSE;

    g_ta = teesim_km_init(kb.data(), kb.size());
    g_initialized = (g_ta != nullptr);
    return g_initialized ? JNI_TRUE : JNI_FALSE;
}

// ---------------------------------------------------------------------------
// JNI: Generate attested key (simplified API)
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jobjectArray JNICALL
Java_org_matrix_teesim_embedded_TeeSimEmbedded_nativeGenerateAttestation(
    JNIEnv* env, jobject /*thiz*/,
    jbyteArray challenge)
{
    if (!g_ta) return nullptr;

    std::lock_guard<std::mutex> lock(g_ta_mutex);
    if (!g_ta) return nullptr;

    // Build key parameters for an EC P-256 signing key with attestation.
    // This creates a standard Android KeyMint attestation key request.
    std::vector<KmParam> params;

    // Algorithm: EC (3) — tag 0x10000001 | 0 = ALGORITHM
    // Tag type ENUM | id=1 → 0x10000001
    params.push_back({0x10000001, 3, nullptr, 0});

    // KeyPurpose::SIGN = 2 — tag 0x10000001 | 1 = PURPOSE
    params.push_back({0x10000002, 2, nullptr, 0});
    // KeyPurpose::VERIFY = 3
    params.push_back({0x10000002, 3, nullptr, 0});

    // Digest::SHA_256 = 4 — tag is an ENUM_REP (type 0x2) | id=5
    // Tag: 0x20000000 | 5 = 0x20000005
    params.push_back({0x20000005, 4, nullptr, 0});

    // EcCurve::P_256 = 1 — tag 0x10000001 | 3 = EC_CURVE
    params.push_back({0x10000003, 1, nullptr, 0});

    // Attestation challenge — TAG_ATTESTATION_CHALLENGE = 6, type BYTES (0x9)
    // Tag: 0x90000000 | 6 = 0x90000006
    if (challenge) {
        std::vector<uint8_t> chal = jbyteArrayToVector(env, challenge);
        if (!chal.empty()) {
            params.push_back({0x90000006, 0, chal.data(), chal.size()});
        }
    }

    // No attestation key (we generate a fresh key directly under the keybox)
    TsCreationResult* result = nullptr;
    int32_t rc = teesim_km_generate_key(
        g_ta,
        params.data(), params.size(),
        nullptr, 0,   // no attest key blob
        nullptr, 0,   // no attest key params
        nullptr, 0,   // no issuer subject
        &result
    );

    if (rc != 0 || !result) return nullptr;

    // Read the result: key blob + certificate chain
    size_t numCerts = teesim_km_result_num_certs(result);

    // Create a Java List<byte[]> (actually a byte[][] array)
    jclass byteArrayClass = env->FindClass("[B");
    jobjectArray certArray = env->NewObjectArray(numCerts, byteArrayClass, nullptr);

    for (size_t i = 0; i < numCerts; i++) {
        const uint8_t* certData = nullptr;
        size_t certLen = 0;
        teesim_km_result_cert(result, i, &certData, &certLen);
        jbyteArray jCert = vectorToJByteArray(env, certData, certLen);
        env->SetObjectArrayElement(certArray, i, jCert);
        env->DeleteLocalRef(jCert);
    }

    teesim_km_free_result(result);
    return certArray;
}

// ---------------------------------------------------------------------------
// JNI: Patch an existing attestation
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jobjectArray JNICALL
Java_org_matrix_teesim_embedded_TeeSimEmbedded_nativePatchAttestation(
    JNIEnv* env, jobject /*thiz*/,
    jbyteArray leafDer)
{
    if (!g_ta) return nullptr;

    std::lock_guard<std::mutex> lock(g_ta_mutex);
    if (!g_ta) return nullptr;

    std::vector<uint8_t> leaf = jbyteArrayToVector(env, leafDer);
    if (leaf.empty()) return nullptr;

    TsCreationResult* result = nullptr;
    int32_t rc = teesim_km_patch_attestation(g_ta, leaf.data(), leaf.size(), &result);

    if (rc != 0 || !result) return nullptr;

    size_t numCerts = teesim_km_result_num_certs(result);

    jclass byteArrayClass = env->FindClass("[B");
    jobjectArray certArray = env->NewObjectArray(numCerts, byteArrayClass, nullptr);

    for (size_t i = 0; i < numCerts; i++) {
        const uint8_t* certData = nullptr;
        size_t certLen = 0;
        teesim_km_result_cert(result, i, &certData, &certLen);
        jbyteArray jCert = vectorToJByteArray(env, certData, certLen);
        env->SetObjectArrayElement(certArray, i, jCert);
        env->DeleteLocalRef(jCert);
    }

    teesim_km_free_result(result);
    return certArray;
}

// ---------------------------------------------------------------------------
// JNI: Check if a blob is one of ours
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jboolean JNICALL
Java_org_matrix_teesim_embedded_TeeSimEmbedded_nativeIsMarked(
    JNIEnv* env, jobject /*thiz*/,
    jbyteArray blob)
{
    std::vector<uint8_t> b = jbyteArrayToVector(env, blob);
    return teesim_km_is_marked(b.data(), b.size()) ? JNI_TRUE : JNI_FALSE;
}

// ---------------------------------------------------------------------------
// JNI: Delete a key
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jint JNICALL
Java_org_matrix_teesim_embedded_TeeSimEmbedded_nativeDeleteKey(
    JNIEnv* env, jobject /*thiz*/,
    jbyteArray keyBlob)
{
    if (!g_ta) return -1;

    std::lock_guard<std::mutex> lock(g_ta_mutex);
    if (!g_ta) return -1;

    std::vector<uint8_t> blob = jbyteArrayToVector(env, keyBlob);
    return (jint)teesim_km_delete_key(g_ta, blob.data(), blob.size());
}

// ---------------------------------------------------------------------------
// JNI: Destroy the TA
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT void JNICALL
Java_org_matrix_teesim_embedded_TeeSimEmbedded_nativeDestroy(
    JNIEnv* /*env*/, jobject /*thiz*/)
{
    std::lock_guard<std::mutex> lock(g_ta_mutex);
    if (g_ta) {
        teesim_km_destroy(g_ta);
        g_ta = nullptr;
        g_initialized = false;
    }
}

// ---------------------------------------------------------------------------
// JNI: Check if initialized
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jboolean JNICALL
Java_org_matrix_teesim_embedded_TeeSimEmbedded_nativeIsInitialized(
    JNIEnv* /*env*/, jobject /*thiz*/)
{
    std::lock_guard<std::mutex> lock(g_ta_mutex);
    return g_initialized && g_ta ? JNI_TRUE : JNI_FALSE;
}