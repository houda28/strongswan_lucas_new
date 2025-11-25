/*
 * Copyright (C) 2024 Your Name
 *
 * This file implements a JNI bridge to call into the Android UI.
 */

#include "android_information_manager.h"
#include "../android_jni.h" /* For androidjni_attach/detach_thread, etc. */

#include <threading/mutex.h>
#include <utils/debug.h>


typedef struct private_android_bridge_t private_android_bridge_t;

/**
 * Private data of an android_bridge_t object.
 */
struct private_android_bridge_t {

    /**
     * Public interface.
     */
    android_bridge_t public;

    /**
     * Lock to protect access to this object.
     */
    mutex_t *mutex;

    jobject obj;
    /**
 * Java class for Scheduler.
 */
    jclass cls;

    /**
     * Cached method ID for the requestPasswordFromUi() Java method.
     */
    jmethodID m_request_password_mid;
};

///**
// * Destructor for an android_bridge_t object.
// */
//static void destroy(private_android_bridge_t *this)
//{
//    JNIEnv *env;
//
//    if (androidjni_attach_thread(&env))
//    {
//        (*env)->DeleteGlobalRef(env, this->m_class);
//        androidjni_detach_thread();
//    }
//    this->mutex->destroy(this->mutex);
//    free(this);
//}

METHOD(android_bridge_t, get_password, char *,
       private_android_bridge_t *this, char *label)
{

    JNIEnv *env;
    char *password = NULL;
    jmethodID method_id;


    (androidjni_attach_thread(&env));

    {
        jstring jlabel = (*env)->NewStringUTF(env, label);
        if (!jlabel)
        {
            androidjni_exception_occurred(env);
            goto detach;
        }

        method_id = (*env)->GetMethodID(env, this->cls, "requestPasswordFromUi",
                                        "(Ljava/lang/String;)Ljava/lang/String;");


        jstring jpassword =  (*env)->CallObjectMethod(env, this->obj, method_id, jlabel);

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
    }

    detach:
    androidjni_detach_thread();
    return password;

}

/**
 * See header.
 */
android_bridge_t *android_bridge_create(jobject context)
{
    private_android_bridge_t *this;
    JNIEnv *env;
    jmethodID method_id;
    jobject obj;
    jclass cls;

    INIT(this,
         .public = {
                 .get_password = _get_password,
    /* Define public methods if any are needed, otherwise leave empty */
         },
    );
    androidjni_attach_thread(&env);
    cls = (*env)->FindClass(env, JNI_PACKAGE_STRING "/InformationManager");
    if (!cls)
    {
        goto failed;
    }
    this->cls = (*env)->NewGlobalRef(env, cls);
    method_id = (*env)->GetMethodID(env, cls, "<init>",
                                    "(Landroid/content/Context;)V");
    if (!method_id)
    {
        goto failed;
    }
    obj = (*env)->NewObject(env, cls, method_id, context);
    if (!obj)
    {
        goto failed;
    }
    this->obj = (*env)->NewGlobalRef(env, obj);
    androidjni_detach_thread();
    return &this->public;

    failed:
    DBG1(DBG_JOB, "failed to create Scheduler object");
    androidjni_exception_occurred(env);
    androidjni_detach_thread();
    return NULL;
}
