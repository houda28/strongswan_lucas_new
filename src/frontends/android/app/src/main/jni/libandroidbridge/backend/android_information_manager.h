/*
 * Copyright (C) 2024 Your Name
 *
 * This file provides a JNI bridge to call into the Android UI.
 */

#ifndef ANDROID_BRIDGE_H_
#define ANDROID_BRIDGE_H_

#include <library.h>
#include <jni.h>
/**
 * An object providing a bridge to the Android UI.
 */
//typedef struct android_bridge_t android_bridge_t;
//
//struct android_bridge_t {
//
//    /**
//     * Adds a event to the queue, using a relative time offset in s.
//     *
//     * @param job			job to schedule
//     * @param time			relative time to schedule job, in s
//     */
//    char * (*get_password)(android_bridge_t *this, char *label);
//};

/**
 * Create an instance of the android_bridge_t.
 *
 * This function finds the Java JniBridge class and its methods, and prepares
 * it for future calls from native code.
 *
 * @return a new android_bridge_t object, NULL on failure.
 */
android_bridge_t *android_bridge_create(jobject context);

#endif /* ANDROID_BRIDGE_H_ */
