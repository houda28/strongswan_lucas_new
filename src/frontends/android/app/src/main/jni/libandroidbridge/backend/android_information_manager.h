/*
 * Copyright (C) 2024 Your Name
 *
 * This file provides a JNI bridge to call into the Android UI.
 */

#ifndef ANDROID_INFORMATION_MANAGER_H_
#define ANDROID_INFORMATION_MANAGER_H_

#include <library.h>
#include <jni.h>
/**
 * An object providing a bridge to the Android UI.
 */

typedef struct android_information_manager_t android_information_manager_t;

struct android_information_manager_t {

    /**
     * Adds a event to the queue, using a relative time offset in s.
     *
     * @param job			job to schedule
     * @param time			relative time to schedule job, in s
     */
    char * (*get_password)(android_information_manager_t *this, char *label);
};

/**
 * Create an instance of the android_information_manager_t.
 *
 * This function finds the Java JniBridge class and its methods, and prepares
 * it for future calls from native code.
 *
 * @return a new android_information_manager_t object, NULL on failure.
 */
android_information_manager_t *android_information_manager_create();

#endif /* ANDROID_INFORMATION_MANAGER_H_ */
