
#include "prompt_creds.h"
#include <unistd.h>
#include <utils/debug.h>
#include <credentials/sets/mem_cred.h>
#include <credentials/containers/pkcs12.h>
#include <credentials/sets/callback_cred.h>

typedef struct private_prompt_creds_t private_prompt_creds_t;

/**
 * Private data of an prompt_creds_t object.
 */
struct private_prompt_creds_t {

	/**
	 * Public prompt_creds_t interface.
	 */
	prompt_creds_t public;

	/**
	 * Reused in-memory credential set
	 */
	mem_cred_t *creds;

	/**
	 * Callback credential set to get secrets
	 */
	callback_cred_t *cb;

	/**
	 * Kind of secret we recently prompted
	 */
	shared_key_type_t prompted;

};

#include "android_information_manager.h"
/**
 * Callback function to prompt for secret
 */
static shared_key_t* callback_shared(private_prompt_creds_t *this,
								shared_key_type_t type,
								identification_t *me, identification_t *other,
								id_match_t *match_me, id_match_t *match_other)
{
	shared_key_t *shared;
	char *label, *pwd = NULL;

	if (type == this->prompted)
	{
		return NULL;
	}

	switch (type)
	{
		case SHARED_EAP:
			label = "EAP password: ";
			break;
		case SHARED_IKE:
			label = "Preshared Key: ";
			break;
		case SHARED_PRIVATE_KEY_PASS:
			label = "Password: ";
			break;
		case SHARED_PIN:
			label = "PIN: ";
			break;
		default:
			return NULL;
	}

    android_information_manager_t *android_information_manager = android_information_manager_create();
    pwd = android_information_manager->get_password(android_information_manager, label);

#ifdef HAVE_GETPASS
	pwd = getpass(label);
#endif

	if (!pwd || strlen(pwd) == 0)
	{
		return NULL;
	}
	this->prompted = type;
	if (match_me)
	{
		*match_me = ID_MATCH_PERFECT;
	}
	if (match_other)
	{
		*match_other = ID_MATCH_PERFECT;
	}
	shared = shared_key_create(type, chunk_clone(chunk_from_str(pwd)));
	memwipe(pwd, strlen(pwd));
	/* cache password in case it is required more than once */
	this->creds->add_shared(this->creds, shared, NULL);
	return shared->get_ref(shared);
}

METHOD(prompt_creds_t, destroy, void,
	private_prompt_creds_t *this)
{
	lib->credmgr->remove_set(lib->credmgr, &this->creds->set);
	lib->credmgr->remove_set(lib->credmgr, &this->cb->set);
	this->creds->destroy(this->creds);
	this->cb->destroy(this->cb);
	free(this);
}

METHOD(prompt_creds_t, add_username_password, void,
       private_prompt_creds_t *this, char *username, char *password)
{
    shared_key_t *shared_key;
    identification_t *id;
    chunk_t secret;

    if (username && password)
    {
        secret = chunk_create(password, strlen(password));
        shared_key = shared_key_create(SHARED_EAP, chunk_clone(secret));
        id = identification_create_from_string(username);

        this->creds->add_shared(this->creds, shared_key, id, NULL);
        this->prompted = SHARED_EAP;
    }
}

/**
 * See header
 */
prompt_creds_t *prompt_creds_create()
{
	private_prompt_creds_t *this;

	INIT(this,
		.public = {
            .add_username_password = _add_username_password,
			.destroy = _destroy,
		},
		.creds = mem_cred_create(),
		.prompted = SHARED_ANY,
	);
	this->cb = callback_cred_create_shared((void*)callback_shared, this);

	lib->credmgr->add_set(lib->credmgr, &this->creds->set);
	lib->credmgr->add_set(lib->credmgr, &this->cb->set);

    shared_key_t *shared1, *shared2 = NULL;
    identification_t *owner1, *owner2;
    mem_cred_t *set1, *set2 = NULL;

//    shared1 = shared_key_create(SHARED_EAP, chunk_clone(chunk_from_str("sonicwall")));
//    owner1 = identification_create_from_string("vpnsecure");
//    set1 = mem_cred_create();
//    set1->add_shared(set1, shared1->get_ref(shared1), owner1, NULL);
//    lib->credmgr->add_set(lib->credmgr, &set1->set);
//
//    shared2 = shared_key_create(SHARED_IKE, chunk_clone(chunk_from_str("sonicwall")));
//    owner2 = identification_create_from_string("vpn.example.com");
//    set2 = mem_cred_create();
//    set2->add_shared(set2, shared2->get_ref(shared2), owner2, NULL);
//    lib->credmgr->add_set(lib->credmgr, &set2->set);


//    if (username && password)
//    {
//        shared1 = shared_key_create(SHARED_EAP, chunk_clone(chunk_from_str(password)));
//        owner1 = identification_create_from_string(username);
//        set1 = mem_cred_create();
//        set1->add_shared(set1, shared1->get_ref(shared1), owner1, NULL);
//        lib->credmgr->add_set(lib->credmgr, &set1->set);
//        this->prompted = SHARED_EAP;
//    }

//    shared2 = shared_key_create(SHARED_IKE, chunk_clone(chunk_from_str("12345678")));
//
//    //shared2 = shared_key_create(SHARED_IKE, chunk_clone(chunk_from_str("S0nicwall")));
//    owner2 = identification_create_from_string("18C241825BEA");
//    set2 = mem_cred_create();
//    set2->add_shared(set2, shared2->get_ref(shared2), owner2, NULL);
//    lib->credmgr->add_set(lib->credmgr, &set2->set);

	return &this->public;
}
