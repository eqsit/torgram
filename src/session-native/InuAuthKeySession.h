#pragma once
#include <jni.h>

class ConnectionsManager;

class InuAuthKeySession {
public:
    static bool registerNatives(JNIEnv *env);
private:
    static void exportSession(JNIEnv *env, jclass, jint account, jobject callback);
    static void importSession(JNIEnv *env, jclass, jint account, jint dcId, jboolean test, jbyteArray key, jobject callback);
    static void discardImport(JNIEnv *env, jclass, jint account);
    static void resetLocalKeys(ConnectionsManager &manager);
};
