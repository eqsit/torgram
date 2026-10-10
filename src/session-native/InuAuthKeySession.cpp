#include "InuAuthKeySession.h"
#include "ConnectionsManager.h"
#include "Datacenter.h"
#include "ByteArray.h"
#include "Handshake.h"
#include <openssl/sha.h>
#include <openssl/mem.h>
#include <array>
#include <cstring>
#include <memory>

namespace {
struct KeyCopy {
    std::array<uint8_t, 256> bytes{};
    ~KeyCopy() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};

struct Callback {
    jobject ref;
    jmethodID method;
    Callback(JNIEnv *env, jobject callback) : ref(env->NewGlobalRef(callback)) {
        jclass clazz = env->GetObjectClass(callback);
        method = env->GetMethodID(clazz, "onResult", "(IZ[BI)V");
        env->DeleteLocalRef(clazz);
    }
    void finish(int account, int dcId, bool test, ByteArray *key, int error) {
        JNIEnv *env = jniEnv[account];
        jbyteArray result = nullptr;
        if (key != nullptr) {
            result = env->NewByteArray(256);
            if (result != nullptr) env->SetByteArrayRegion(result, 0, 256, reinterpret_cast<jbyte *>(key->bytes));
        }
        if (result != nullptr || key == nullptr) env->CallVoidMethod(ref, method, dcId, test, result, error);
        if (result != nullptr) env->DeleteLocalRef(result);
        env->DeleteGlobalRef(ref);
    }
};
bool validAccount(int account) { return account >= 0 && account < MAX_ACCOUNT_COUNT; }
}

void InuAuthKeySession::exportSession(JNIEnv *env, jclass, jint account, jobject callback) {
    if (!validAccount(account) || callback == nullptr) return;
    auto completion = std::make_shared<Callback>(env, callback);
    auto &manager = ConnectionsManager::getInstance(account);
    manager.scheduleTask([&manager, account, completion] {
        auto *dc = manager.getDatacenterWithId(manager.currentDatacenterId);
        if (manager.currentUserId == 0 || dc == nullptr || dc->authKeyPerm == nullptr || dc->authKeyPerm->length != 256) {
            completion->finish(account, 0, manager.testBackend, nullptr, 1);
            return;
        }
        completion->finish(account, dc->getDatacenterId(), manager.testBackend, dc->authKeyPerm, 0);
    });
}

void InuAuthKeySession::resetLocalKeys(ConnectionsManager &manager) {
    // This is deliberately local: never send auth.logOut for a copied authorization.
    for (auto &entry : manager.datacenters) {
        auto *dc = entry.second;
        dc->suspendConnections(true);
        manager.clearRequestsForDatacenter(dc, HandshakeTypeAll);
        dc->clearAuthKey(HandshakeTypeAll);
        dc->recreateSessions(HandshakeTypeAll);
        dc->authorized = false;
    }
    manager.sessionsToDestroy.clear();
    manager.requestingSaltsForDc.clear();
    manager.sendingPing = false;
    manager.sendingPushPing = false;
    manager.movingToDatacenterId = DEFAULT_DATACENTER_ID;
    manager.movingAuthorization.reset();
    manager.registeredForInternalPush = false;
}

void InuAuthKeySession::importSession(JNIEnv *env, jclass, jint account, jint dcId, jboolean test, jbyteArray key, jobject callback) {
    if (!validAccount(account) || callback == nullptr) return;
    auto completion = std::make_shared<Callback>(env, callback);
    auto copy = std::make_shared<KeyCopy>();
    bool valid = key != nullptr && env->GetArrayLength(key) == 256;
    if (valid) env->GetByteArrayRegion(key, 0, 256, reinterpret_cast<jbyte *>(copy->bytes.data()));
    uint8_t nonzero = 0;
    for (auto byte : copy->bytes) nonzero |= byte;
    valid = valid && nonzero != 0 && dcId >= 1 && dcId <= (test ? 3 : 5);
    auto &manager = ConnectionsManager::getInstance(account);
    manager.scheduleTask([&manager, account, dcId, test, valid, copy, completion] {
        if (!valid || manager.testBackend != static_cast<bool>(test)) {
            completion->finish(account, dcId, test, nullptr, 2);
            return;
        }
        if (manager.currentUserId != 0) {
            completion->finish(account, dcId, test, nullptr, 3);
            return;
        }
        auto *dc = manager.getDatacenterWithId(dcId);
        if (dc == nullptr || dc->isCdnDatacenter) {
            completion->finish(account, dcId, test, nullptr, 2);
            return;
        }
        resetLocalKeys(manager);
        manager.currentDatacenterId = dcId;
        dc->authKeyPerm = new ByteArray(256);
        std::memcpy(dc->authKeyPerm->bytes, copy->bytes.data(), 256);
        uint8_t digest[SHA_DIGEST_LENGTH];
        SHA1(copy->bytes.data(), 256, digest);
        std::memcpy(&dc->authKeyPermId, digest + 12, 8);
        OPENSSL_cleanse(digest, sizeof(digest));
        OPENSSL_cleanse(copy->bytes.data(), copy->bytes.size());
        dc->authorized = true;
        manager.saveConfig();
        // Generate and bind fresh temporary keys; keep Android's PFS enabled.
        dc->beginHandshake(HandshakeTypeAll, true);
        completion->finish(account, dcId, test, nullptr, 0);
        manager.processRequestQueue(AllConnectionTypes, dcId);
    });
}

void InuAuthKeySession::discardImport(JNIEnv *, jclass, jint account) {
    if (!validAccount(account)) return;
    auto &manager = ConnectionsManager::getInstance(account);
    manager.scheduleTask([&manager] {
        if (manager.currentUserId != 0) return;
        resetLocalKeys(manager);
        manager.saveConfig();
        manager.processRequestQueue(AllConnectionTypes, manager.currentDatacenterId);
    });
}

bool InuAuthKeySession::registerNatives(JNIEnv *env) {
    jclass clazz = env->FindClass("desu/inugram/helpers/security/AuthKeySessionNative");
    if (clazz == nullptr) return false;
    JNINativeMethod methods[] = {
        {"exportSession", "(ILdesu/inugram/helpers/security/AuthKeySessionNative$Callback;)V", reinterpret_cast<void *>(exportSession)},
        {"importSession", "(IIZ[BLdesu/inugram/helpers/security/AuthKeySessionNative$Callback;)V", reinterpret_cast<void *>(importSession)},
        {"discardImport", "(I)V", reinterpret_cast<void *>(discardImport)},
    };
    bool ok = env->RegisterNatives(clazz, methods, 3) == 0;
    env->DeleteLocalRef(clazz);
    return ok;
}
