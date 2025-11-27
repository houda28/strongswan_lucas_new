
#ifndef PROMPT_CREDS_H_
#define PROMPT_CREDS_H_

#include <library.h>

typedef struct prompt_creds_t prompt_creds_t;

/**
 * Credential backend providing shared secrets or otp.
 */
struct prompt_creds_t {

    void (*add_username_password)(prompt_creds_t *this, char *username,
                                  char *password);
    /**
	 * Destroy a prompt_creds_t.
	 */
	void (*destroy)(prompt_creds_t *this);
};

/**
 * Create a prompt_creds instance.
 */
prompt_creds_t *prompt_creds_create();

#endif /** PROMPT_CREDS_H_ @}*/
