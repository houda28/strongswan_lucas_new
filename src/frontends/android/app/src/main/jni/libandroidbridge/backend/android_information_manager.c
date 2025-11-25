/*
 * Copyright (C) 2025 Lucas Shu
 *
 * This file implements a JNI bridge to call into the Android UI to get information from the dialogue.
 */

#include "android_information_manager.h"
#include "../android_jni.h"

typedef struct private_android_information_manager_t private_android_information_manager_t;

/**
 * Private data of an android_information_manager_t object.
 */
struct private_android_information_manager_t {

    /**
     * Public interface.
     */
    android_information_manager_t public;
};



METHOD(android_information_manager_t, destroy, void,
       private_android_information_manager_t *this)
{
    JNIEnv *env;

    androidjni_attach_thread(&env);
    //(*env)->DeleteGlobalRef(env, ???);// there are no global references in this class.
    androidjni_detach_thread();
    free(this);
}

METHOD(android_information_manager_t, get_password, char *,
       private_android_information_manager_t *this, char *label)
{

    JNIEnv *env;
    char *password = NULL;
    jmethodID method_id;

    androidjni_attach_thread(&env);

    jstring jlabel = (*env)->NewStringUTF(env, label);
    if (!jlabel)
    {
        androidjni_exception_occurred(env);
        goto detach;
    }

    method_id = (*env)->GetStaticMethodID(env, android_information_manager_class, "requestPasswordFromUi",
                                    "(Ljava/lang/String;)Ljava/lang/String;");

    jstring jpassword =  (*env)->CallStaticObjectMethod(env, android_information_manager_class, method_id, jlabel);

    (*env)->DeleteLocalRef(env, jlabel);

    if (androidjni_exception_occurred(env))
    {
        goto detach;
    }

    if (jpassword != NULL)
    {
        const char *native_pass = (*env)->GetStringUTFChars(env, jpassword, 0);
        password = strdup(native_pass);
        (*env)->ReleaseStringUTFChars(env, jpassword, native_pass);
        (*env)->DeleteLocalRef(env, jpassword);
    }

    detach:
    androidjni_detach_thread();
    return password;

}

/**
 * See header.
 */
android_information_manager_t *android_information_manager_create()
{
    private_android_information_manager_t *this;
    INIT(this,
         .public = {
                 .get_password = _get_password,
         },
    );
    return &this->public;
}
