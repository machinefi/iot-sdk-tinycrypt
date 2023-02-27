#include <stdio.h>
#include "psa/crypto.h"
// #include "psa_shim/crypto_values.h"
#include "tinycrypt/constants.h"
#include "tinycrypt/ctr_prng.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "tinycrypt/ctr_prng.h"
#include "tinycrypt/constants.h"
#include "tinycrypt/ctr_prng.h"
#include "tinycrypt/hmac.h"
#include "tinycrypt/cbc_mode.h"
#include "tinycrypt/ctr_mode.h"
#include "tinycrypt/ecc.h"

/****************************************************************/
/* Type declarations and preprocessor macros */
/****************************************************************/

#define PSA_ALG_ASSYM_GET_SIGN_TYPE(alg)  ( ((alg) & 0x0000ff00) >> 8 )




/****************************************************************/
/* Global variables and state */
/****************************************************************/

static tc_psa_global_data_t global_data;

static TCCtrPrng_t ctx;

 
/****************************************************************/
/* Utility funcions */
/****************************************************************/

static void print_hex(uint8_t* buf, size_t size)
{
    for (int i=0; i<size; i++)
    {
        printf("%02x", buf[i]);
    }
}

static void zeroize(void *buf, size_t size)
{
    if (buf != NULL && size >0)
    {
        memset(buf, 0, size);
    }
}

psa_status_t tc_to_psa_status(int tc_status)
{
    switch(tc_status)
    {
        case TC_CRYPTO_SUCCESS:
            return PSA_SUCCESS;
        default:
            return PSA_ERROR_GENERIC_ERROR;
    }
}

uint32_t get_free_key_id()
{
    return global_data.next_key_handle;
}

psa_key_slot_t* get_key_slot(uint32_t handle)
{
    for (int i=0; i<PSA_KEY_SLOT_COUNT; i++)
    {
        if (global_data.key_slots[i].handle == handle)
        {
            return &(global_data.key_slots[i]);
        }
    }
    return NULL;
}

bool has_free_keyslot()
{
    return global_data.key_slots_used != PSA_KEY_SLOT_COUNT;
}

psa_status_t lock_key_slot(uint32_t handle)
{
    printf("Locking key slot %d\n", handle);
    for (int i=0; i<PSA_KEY_SLOT_COUNT; i++)
    {
        if (!global_data.key_slots[i].in_use)
        {
            psa_key_slot_t* slot = &(global_data.key_slots[i]);
            slot->in_use = true;
            slot->handle = handle;
            global_data.key_slots_used++;
            global_data.next_key_handle++;
            return PSA_SUCCESS;
        }
    }
    return PSA_ERROR_INSUFFICIENT_MEMORY;
}

void free_key_slot(uint32_t handle)
{
    printf("Freeing key slot %d\n", handle);
    psa_key_slot_t* slot = get_key_slot(handle);

    zeroize((void*)slot->key.data, slot->key.bytes);
    free(slot->key.data);
    slot->key.data = NULL;
    zeroize((void*)slot, sizeof(psa_key_slot_t));
    global_data.key_slots_used--;
    global_data.invalid_key_handles[global_data.invalid_key_handles_count++] = handle;
}

bool key_slot_is_valid(uint32_t handle)
{
    for (int i=0; i<global_data.invalid_key_handles_count; i++)
    {
        if (global_data.invalid_key_handles[i] == handle)
        {
            return false;
        }
    }
    return true;
}

bool key_slot_is_in_use(uint32_t handle)
{
    psa_key_slot_t* slot = get_key_slot(handle);
    return slot ? slot->in_use : false;
}

psa_status_t validate_algorithm_hash(psa_algorithm_t alg)
{
    switch (alg & PSA_ALG_HASH_MASK)
    {
        case PSA_ALG_NONE:
        case PSA_ALG_MD5:
        case PSA_ALG_RIPEMD160:
        case PSA_ALG_SHA_1:
        case PSA_ALG_SHA_224:
        case PSA_ALG_SHA_384:
        case PSA_ALG_SHA_512:
        case PSA_ALG_SHA_512_224:
        case PSA_ALG_SHA_512_256:
        case PSA_ALG_SHA3_224:
        case PSA_ALG_SHA3_256:
        case PSA_ALG_SHA3_384:
        case PSA_ALG_SHA3_512:
        case PSA_ALG_SHAKE256_512:
            return PSA_ERROR_NOT_SUPPORTED;

        case PSA_ALG_SHA_256:
        case PSA_ALG_ANY_HASH:
            return PSA_SUCCESS;
    }
}

psa_status_t validate_algorithm_mac(psa_algorithm_t alg)
{
    if ( (alg & PSA_ALG_MAC_TRUNCATION_MASK) != 0)
    {
        // TODO support truncated MAC
        return PSA_ERROR_NOT_SUPPORTED;
    }

    // TODO Validate W flag
    
    if (PSA_ALG_IS_HMAC(alg))
    {
        if (alg != PSA_ALG_HMAC(PSA_ALG_SHA_256))
        {
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }

    // TODO support AES_CMAC

    return PSA_SUCCESS;
}

psa_status_t validate_algorithm_cipher(psa_algorithm_t alg)
{
    switch (alg)
    {
        case PSA_ALG_CTR:
        case PSA_ALG_OFB:
        case PSA_ALG_CBC_NO_PADDING:
        case PSA_ALG_CCM:
            return PSA_SUCCESS; 

        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t validate_algorithm_aead(psa_algorithm_t alg)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t validate_algorithm_key_derivation(psa_algorithm_t alg)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t validate_algorithm_ecdsa(psa_algorithm_t alg)
{
    uint32_t sign_type = PSA_ALG_ASSYM_GET_SIGN_TYPE(alg);
    switch (sign_type)
    {
        case 0x06: /* Randomized ECDSA */
            return PSA_SUCCESS;

        default:
            return false;
    }
}

psa_status_t validate_algorithm_signature(psa_algorithm_t alg)
{
    uint32_t sign_type = PSA_ALG_ASSYM_GET_SIGN_TYPE(alg);
    if (sign_type == 0x06)
    {
        return PSA_SUCCESS;
    }
    
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t validate_algorithm_encryption(psa_algorithm_t alg)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t validate_algorithm_key_agreement(psa_algorithm_t alg)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t validate_algorithm(psa_algorithm_t alg)
{
    switch ((alg) & PSA_ALG_CATEGORY_MASK)
    {
        case PSA_ALG_CATEGORY_HASH:
            return validate_algorithm_hash(alg);
        case PSA_ALG_CATEGORY_MAC:
            return validate_algorithm_mac(alg);
        case PSA_ALG_CATEGORY_CIPHER:
            return validate_algorithm_cipher(alg);
        case PSA_ALG_CATEGORY_AEAD:
            return validate_algorithm_aead(alg);
        case PSA_ALG_CATEGORY_SIGN:
            return validate_algorithm_signature(alg);
        case PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION:
            return validate_algorithm_encryption(alg);
        case PSA_ALG_CATEGORY_KEY_DERIVATION:
            return validate_algorithm_key_derivation(alg);
        case PSA_ALG_CATEGORY_KEY_AGREEMENT:
            return validate_algorithm_key_agreement(alg);
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t validate_key_type(psa_key_type_t type)
{
    /**
     Key Types list:
        - PSA_KEY_TYPE_NONE
        - PSA_KEY_TYPE_RAW_DATA
        - PSA_KEY_TYPE_HMAC: supported
        - PSA_KEY_TYPE_DERIVE: supported?
        - PSA_KEY_TYPE_AES: supported
        - PSA_KEY_TYPE_CAMELLIA
        - PSA_KEY_TYPE_ARC4
        - PSA_KEY_TYPE_CHACHA20
        - PSA_KEY_TYPE_RSA_KEY_PAIR
        - PSA_KEY_TYPE_RSA_PUBLIC_KEY
        - PSA_KEY_TYPE_ECC_KEY_PAIR: supported
        - PSA_KEY_TYPE_ECC_PUBLIC_KEY: supported
        - PSA_KEY_TYPE_VENDOR_FLAG
     */

    if (PSA_KEY_TYPE_IS_VENDOR_DEFINED(type))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (type == PSA_KEY_TYPE_NONE)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (type & 0x0001)
    {
        // Invalid parity bit
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (PSA_KEY_TYPE_IS_ECC(type))
    {
        if (type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) && 
            type != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1))
        {
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }
    
    // TODO
    // Return success if HMAC, DERIVE, AES

    return PSA_SUCCESS;
}

psa_status_t validate_key_lifetime(psa_key_lifetime_t lifetime)
{
    if (!PSA_KEY_LIFETIME_IS_VOLATILE(lifetime))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    return PSA_SUCCESS;
}

psa_status_t validate_key_location(psa_key_location_t location)
{
    if (location != PSA_KEY_LOCATION_LOCAL_STORAGE)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    return PSA_SUCCESS;
}

psa_status_t validate_key_size_for_algorithm(psa_algorithm_t alg, size_t key_bits)
{
    // TODO Validate the key size is OK for the algorithm
    return PSA_SUCCESS;
}

psa_status_t validate_key_usage(psa_key_attributes_t *attributes)
{
    // TODO Validate the key size is OK for the algorithm
    return PSA_SUCCESS;
}

bool key_supports_algorith(psa_algorithm_t alg, psa_key_slot_t *slot)
{
    // TODO Validate the key at this slot supports the algorithm
    return true;
}
bool key_usage_flag_is_set(const psa_key_usage_t usage, psa_key_usage_t flag)
{
    return (usage & flag) == flag;
}

struct psa_hash_operation_s* get_hash_operation(uint32_t handle)
{
    if (handle >= PSA_OPERATION_COUNT)
    {
        return NULL;
    }
    return &global_data.hash_operations[handle];
}

/****************************************************************/
/* Module setup */
/****************************************************************/

psa_status_t tc_psa_crypto_init( void )
{
    /* Double initialization is explicitly allowed. */
    if( global_data.initialized != 0 )
        return( PSA_SUCCESS );

    /* Initialize and seed the random generator. */
    // TODO find entropy. Mbed keeps a list of entropy sources
    uint8_t entropy[32U] = {0U};
    int tc_status = tc_ctr_prng_init(&global_data.rng, entropy, sizeof entropy, 0, 0U);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        goto exit;
    }
    global_data.rng_state = TC_RNG_INITIALIZED;

    /* Initialize key slots */
    global_data.key_slots_used = 0;
    global_data.invalid_key_handles_count = 0;
    global_data.next_key_handle = 1;
    for (int i=0; i<PSA_KEY_SLOT_COUNT; i++)
    {
        zeroize((void*)&(global_data.key_slots[i]), sizeof(psa_key_slot_t));
    }
    zeroize(global_data.invalid_key_handles, sizeof(global_data.invalid_key_handles[0]));

    // Initialize hash_operations
    for (int i=0; i<PSA_OPERATION_COUNT; i++)
    {
        zeroize((void*)&(global_data.hash_operations[i]), sizeof(psa_hash_operation_t));
    }

    global_data.initialized = true;

    exit:
        return tc_to_psa_status(tc_status);
}




/****************************************************************/
/* Random generation */
/****************************************************************/

psa_status_t tc_psa_generate_random( uint8_t *output,
                                  size_t output_size )
{
    GUARD_MODULE_INITIALIZED
    int tc_status = 0;

    // TODO Assert enough entropy
    tc_status = tc_ctr_prng_generate(&ctx, 0, 0, output, output_size);
    return tc_to_psa_status(tc_status);
}




/****************************************************************/
/* Key management */
/****************************************************************/

psa_status_t tc_psa_close_key( psa_key_handle_t handle )
{
    GUARD_MODULE_INITIALIZED
    
    // Removed from PSA spec in 1.0.0
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t tc_psa_open_key( psa_key_handle_t key,
                           psa_key_handle_t *handle )
{
    GUARD_MODULE_INITIALIZED

    // Removed from PSA spec in 1.0.0
    return PSA_ERROR_NOT_SUPPORTED;
}

static void tc_psa_set_key_id(psa_key_attributes_t *attributes,
                           psa_key_id_t key)
{
    attributes->id = key;
}

void rtc_psa_set_key_lifetime(psa_key_attributes_t *attributes,
                                 psa_key_lifetime_t lifetime)
{
    attributes->lifetime = lifetime;
}    

psa_key_id_t tc_psa_get_key_id(const psa_key_attributes_t *attributes)
{
    return attributes->id;
}

psa_key_lifetime_t tc_psa_get_key_lifetime(
    const psa_key_attributes_t *attributes)
{
    return attributes->lifetime;
}

void tc_psa_set_key_usage_flags(psa_key_attributes_t *attributes,
                                    psa_key_usage_t usage_flags)
{
    attributes->usage = usage_flags;
}

psa_key_usage_t tc_psa_get_key_usage_flags(
    const psa_key_attributes_t *attributes)
{
    return attributes->usage;
}

void tc_psa_set_key_algorithm(psa_key_attributes_t *attributes,
                                  psa_algorithm_t alg)
{
    attributes->alg = alg;
}

psa_algorithm_t tc_psa_get_key_algorithm(
    const psa_key_attributes_t *attributes)
{
    return attributes->alg;
}

void tc_psa_set_key_type(psa_key_attributes_t *attributes,
                             psa_key_type_t type)
{
    attributes->type = type;
}

psa_key_type_t tc_psa_get_key_type(const psa_key_attributes_t *attributes)
{
    return attributes->type;
}

void tc_psa_set_key_bits(psa_key_attributes_t *attributes,
                             size_t bits)
{
    if( bits > PSA_MAX_KEY_BITS )
    {
        attributes->bits = PSA_KEY_BITS_TOO_LARGE;
    }
    else
    {
        attributes->bits = (psa_key_bits_t) bits;
    }
}

size_t tc_psa_get_key_bits(const psa_key_attributes_t *attributes)
{
    return attributes->bits;
}

psa_status_t tc_psa_get_key_attributes(psa_key_id_t key,
                                    psa_key_attributes_t *attributes)
{
    GUARD_MODULE_INITIALIZED

    psa_key_slot_t *key_slot = get_key_slot(key);
    if (!key_slot)
    {
        return PSA_ERROR_INVALID_HANDLE;
    }

    /* Copy the attributes */
    memset(attributes, 0, sizeof(psa_key_attributes_t));
    attributes->lifetime = key_slot->attr.lifetime;
    attributes->type = key_slot->attr.type;
    attributes->bits = key_slot->attr.bits;
    attributes->alg = key_slot->attr.alg;
    attributes->usage = key_slot->attr.usage;
    
    memcpy(attributes, &(key_slot->attr), sizeof(psa_key_attributes_t));
    return PSA_SUCCESS;
}
                                
void tc_psa_reset_key_attributes(psa_key_attributes_t *attributes)
{
    memset( attributes, 0, sizeof( *attributes ) );
}

psa_status_t tc_psa_purge_key(psa_key_id_t key)
{
    GUARD_MODULE_INITIALIZED

    // This should simply clear all cache copies of the key
    // Because cache is not used, there is nothing to do.
    return PSA_SUCCESS;
}

psa_status_t tc_psa_generate_key(const psa_key_attributes_t *attributes,
                              psa_key_id_t *key)
{
    GUARD_MODULE_INITIALIZED

    psa_status_t status = PSA_SUCCESS;
    *key = PSA_KEY_ID_NULL;
    
    /* Reject any attempt to create a zero-length key so that we don't
     * risk tripping up later, e.g. on a malloc(0) that returns NULL. */
    if (psa_get_key_bits(attributes) == 0)
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = validate_key_type(psa_get_key_type(attributes));
    if (status != PSA_SUCCESS)
    {
        goto exit;
    }

    if (PSA_KEY_TYPE_IS_PUBLIC_KEY(psa_get_key_type(attributes)))
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = validate_algorithm(psa_get_key_algorithm(attributes));
    if (status != PSA_SUCCESS)
    {
        goto exit;
    }

    status = validate_key_lifetime(psa_get_key_lifetime(attributes));
    if (status != PSA_SUCCESS)
    {
        goto exit;
    }

    status = validate_key_location(PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(attributes)));
    if (status != PSA_SUCCESS)
    {
        goto exit;
    }

    status = validate_key_size_for_algorithm(psa_get_key_algorithm(attributes),
                                              psa_get_key_bits(attributes));
    if (status != PSA_SUCCESS)
    {
        goto exit;
    }
   
    {
        // Create a buffer with enough size to hold the key and fill it with random data
        uint8_t buf[attributes->bits/8];
        psa_generate_random(buf, sizeof(buf));
        return tc_psa_import_key(attributes, buf, sizeof(buf), key);  
    }

    exit:
        return status;
}

psa_status_t tc_psa_import_key(const psa_key_attributes_t *attributes,
                            const uint8_t *data,
                            size_t data_length,
                            psa_key_id_t *key)
{
    GUARD_MODULE_INITIALIZED

    psa_status_t status;
    size_t bits;
    size_t storage_size = data_length;

    *key = (psa_key_id_t)0;

    /* Reject zero-length symmetric keys (including raw data key objects).
     * This also rejects any key which might be encoded as an empty string,
     * which is never valid. */
    if( data_length == 0 || !data)
    {
        return( PSA_ERROR_INVALID_ARGUMENT );
    }
    
    /* Ensure that the bytes-to-bits conversion cannot overflow. */
    if( data_length > SIZE_MAX / 8 )
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }    

    // Check there are free slots
    if (!has_free_keyslot())
    {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    if (psa_get_key_bits(attributes) == 0 || psa_get_key_bits(attributes) > PSA_MAX_KEY_BITS || data_length >= PSA_MAX_KEY_BITS / 8)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = validate_key_type(attributes->type);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    status = validate_key_lifetime(attributes->lifetime);
    if (status != PSA_SUCCESS)
    {
        return status;
    }
    
    status = validate_key_location(PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime));
    if (status != PSA_SUCCESS)
    {
        return status;
    }
    
    status = validate_key_usage(attributes);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    status = validate_algorithm(attributes->alg);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    // Copy the key attributes to key store
    uint32_t handle = get_free_key_id();
    status = lock_key_slot(handle);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    psa_key_slot_t* slot = get_key_slot(handle);
    slot->attr.type = psa_get_key_type(attributes);
    slot->attr.bits = psa_get_key_bits(attributes);
    slot->attr.lifetime = psa_get_key_lifetime(attributes);
    slot->attr.usage = psa_get_key_usage_flags(attributes);
    slot->attr.alg = psa_get_key_algorithm(attributes);

    // Dynamically allocate data
    slot->key.data = (uint8_t*)malloc(data_length);
    slot->key.bytes = data_length;
    memcpy(slot->key.data, data, data_length);

    // Set the out key value to the key id
    *key = handle;

    return PSA_SUCCESS;
}

psa_status_t tc_psa_copy_key(psa_key_id_t source_key,
                          const psa_key_attributes_t *attributes,
                          psa_key_id_t *target_key)
{
    GUARD_MODULE_INITIALIZED

    if (!key_slot_is_valid(source_key) || !key_slot_is_in_use(source_key))
    {
        return PSA_ERROR_INVALID_HANDLE;
    }
    
    psa_key_slot_t* slot = get_key_slot(source_key);
    if( !key_usage_flag_is_set( slot->attr.usage, PSA_KEY_USAGE_COPY ) )
    {
        return(PSA_ERROR_NOT_PERMITTED);
    }
    
    if (validate_key_lifetime(psa_get_key_lifetime(attributes)) != PSA_SUCCESS)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (psa_get_key_bits(attributes) && (psa_get_key_bits(attributes) != slot->attr.bits))
    {
        // Number of bits has to be either equal or zero (not specified).
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (psa_get_key_type(attributes) && (psa_get_key_type(attributes) != slot->attr.type))
    {
        // Key type has to be either equal or zero (not specified).
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    psa_key_attributes_t new_attributes;
    new_attributes.type = slot->attr.type;
    new_attributes.bits = slot->attr.bits;
    new_attributes.alg = slot->attr.alg;
    // The key location is used directly from attributes
    new_attributes.lifetime = attributes->lifetime;
    // The key usage flags are combined from the source key and attributes
    new_attributes.usage = attributes->usage & slot->attr.usage;

    return tc_psa_import_key(&new_attributes, slot->key.data, slot->key.bytes, target_key);
}

psa_status_t tc_psa_destroy_key(psa_key_id_t key)
{
    GUARD_MODULE_INITIALIZED

    if (key == PSA_KEY_ID_NULL)
    {
        return PSA_SUCCESS; 
    }

    if (!key_slot_is_valid(key) || !key_slot_is_in_use(key))
    {
        return PSA_ERROR_INVALID_HANDLE;
    }

    free_key_slot(key);
    return PSA_SUCCESS;
}

psa_status_t tc_psa_export_key(psa_key_id_t key,
                            uint8_t *data,
                            size_t data_size,
                            size_t *data_length)
{
    GUARD_MODULE_INITIALIZED

    // Check that the key handle is valid and in use
    if (!key_slot_is_valid(key) || !key_slot_is_in_use(key))
    {
        return PSA_ERROR_INVALID_HANDLE;
    }

    // Check that the key is permitted to be exported
    if (!key_usage_flag_is_set(get_key_slot(key)->attr.usage, PSA_KEY_USAGE_EXPORT))
    {
        return PSA_ERROR_NOT_PERMITTED;
    }
    
    // Check that the buffer is large enough to hold the key
    if (data_size < get_key_slot(key)->key.bytes)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    // Copy the key data to the buffer
    memcpy(data, get_key_slot(key)->key.data, get_key_slot(key)->key.bytes);
    *data_length = get_key_slot(key)->key.bytes;

    return PSA_SUCCESS;
}

psa_status_t tc_psa_export_public_key(psa_key_id_t key,
                                   uint8_t *data,
                                   size_t data_size,
                                   size_t *data_length)
{
    GUARD_MODULE_INITIALIZED

    // Check that the key handle is valid and in use
    if (!key_slot_is_valid(key) || !key_slot_is_in_use(key))
    {
        return PSA_ERROR_INVALID_HANDLE;
    }

    // Check that the key is permitted to be exported
    if (!key_usage_flag_is_set(get_key_slot(key)->attr.usage, PSA_KEY_USAGE_EXPORT))
    {
        return PSA_ERROR_NOT_PERMITTED;
    }
    
    // Check that the buffer is large enough to hold the key
    size_t public_key_size = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(get_key_slot(key)->attr.type, get_key_slot(key)->attr.bits);
    if (data_size < public_key_size)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    int res = uECC_compute_public_key(get_key_slot(key)->key.data, data, uECC_secp256r1());
    if (res != TC_CRYPTO_SUCCESS)
    {
        zeroize(data, data_size);
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    
    *data_length = public_key_size;

    return PSA_SUCCESS;
}
    


/****************************************************************/
/* Hash */
/****************************************************************/

psa_status_t tc_psa_hash_compute(psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *hash,
                              size_t hash_size,
                              size_t *hash_length)
{
    GUARD_MODULE_INITIALIZED

    *hash_length = 0;
    
    if (!PSA_ALG_IS_HASH(alg))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if( alg != PSA_ALG_SHA_256)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (hash_size < PSA_HASH_LENGTH(alg))
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    psa_status_t status;

    struct tc_sha256_state_struct state;
    int tc_status = tc_sha256_init(&state);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    tc_status = tc_sha256_update(&state, (const uint8_t *) input, input_length);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    tc_status = tc_sha256_final(hash, &state);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    
    *hash_length = PSA_HASH_MAX_SIZE;

    return PSA_SUCCESS;
}

psa_status_t tc_psa_hash_compare(psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              const uint8_t *hash,
                              size_t hash_length)
{
    GUARD_MODULE_INITIALIZED

    if( !PSA_ALG_IS_HASH( alg ) )
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if( alg != PSA_ALG_SHA_256 )
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if (hash_length < PSA_HASH_LENGTH(alg))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t actual_hash[PSA_HASH_LENGTH(alg)];
    size_t actual_hash_length;

    psa_status_t status = tc_psa_hash_compute(
                            alg, input, input_length,
                            actual_hash, sizeof(actual_hash),
                            &actual_hash_length );
    
    if( status != PSA_SUCCESS )
    {
        return status;
    }
    
    if( actual_hash_length != hash_length )
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if (memcmp(hash, actual_hash, actual_hash_length) != 0)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;
}

psa_status_t tc_psa_hash_setup(psa_hash_operation_t *operation,
                            psa_algorithm_t alg)
{
    GUARD_MODULE_INITIALIZED

    if( !PSA_ALG_IS_HASH( alg ) )
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if( alg != PSA_ALG_SHA_256 )
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if (!operation)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // Get the operation from the operations array
    // psa_hash_operation_s* op = get_hash_operation(operation);
    operation->op_state = HASH_OPERATION_STATE_INITIALISED;
    int tc_status = tc_sha256_init(&operation->state);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t tc_psa_hash_update(psa_hash_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length)
{
    GUARD_MODULE_INITIALIZED

    /* Don't require hash implementations to behave correctly on a
     * zero-length input, which may have an invalid pointer. */
    if( input_length == 0 || !input && input_length == 0)
    {
        return PSA_SUCCESS;
    }
    
    if (!operation || !input)
    {
        tc_psa_hash_abort(operation);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if(operation->op_state != HASH_OPERATION_STATE_INITIALISED && operation->op_state != HASH_OPERATION_STATE_INPROGRESS)
    {
        tc_psa_hash_abort(operation);
        return PSA_ERROR_BAD_STATE;
    }

    
    int tc_status = tc_sha256_update(&operation->state, (const uint8_t *) input, input_length);
    if(tc_status == TC_CRYPTO_SUCCESS)
    {
        return PSA_SUCCESS;
    }
    else
    {
        tc_psa_hash_abort(operation);
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t tc_psa_hash_finish(psa_hash_operation_t *operation,
                             uint8_t *hash,
                             size_t hash_size,
                             size_t *hash_length)
{
    GUARD_MODULE_INITIALIZED

    if (!operation || !hash || !hash_length)
    {
        tc_psa_hash_abort(operation);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if(operation->op_state != HASH_OPERATION_STATE_INITIALISED && operation->op_state != HASH_OPERATION_STATE_INPROGRESS)
    {
        tc_psa_hash_abort(operation);
        return PSA_ERROR_BAD_STATE;
    }

    if (hash_size < PSA_HASH_LENGTH(PSA_ALG_SHA_256))
    {
        tc_psa_hash_abort(operation);
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    int tc_status = tc_sha256_final(hash, &operation->state);
    if(tc_status == TC_CRYPTO_SUCCESS)
    {
        *hash_length = PSA_HASH_LENGTH(PSA_ALG_SHA_256);
    }
    else
    {
        tc_psa_hash_abort(operation);
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    operation->op_state = HASH_OPERATION_STATE_FREE;
    return PSA_SUCCESS;
}

psa_status_t tc_psa_hash_verify(psa_hash_operation_t *operation,
                             const uint8_t *hash,
                             size_t hash_length)
{
    GUARD_MODULE_INITIALIZED

    if (!operation || !hash)
    {
        tc_psa_hash_abort(operation);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

     if(operation->op_state != HASH_OPERATION_STATE_INITIALISED && operation->op_state != HASH_OPERATION_STATE_INPROGRESS)
    {
        tc_psa_hash_abort(operation);
        return PSA_ERROR_BAD_STATE;
    }

    if (hash_length < PSA_HASH_LENGTH(PSA_ALG_SHA_256))
    {
        tc_psa_hash_abort(operation);
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    uint8_t actual_hash[PSA_HASH_MAX_SIZE];
    size_t actual_hash_length;

    psa_status_t status = tc_psa_hash_finish(
                            operation,
                            actual_hash, sizeof( actual_hash ),
                            &actual_hash_length );

    if( status != PSA_SUCCESS )
    {
        tc_psa_hash_abort(operation);
        return status;
    }

    if( actual_hash_length != hash_length )
    {
        tc_psa_hash_abort(operation);
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if( memcmp(hash, actual_hash, actual_hash_length) != 0 )
    {
        tc_psa_hash_abort(operation);
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;
}

psa_status_t tc_psa_hash_abort(psa_hash_operation_t *operation)
{
    GUARD_MODULE_INITIALIZED

    if(operation->op_state != HASH_OPERATION_STATE_INITIALISED && operation->op_state != HASH_OPERATION_STATE_INPROGRESS)
    {
        return PSA_SUCCESS;
    }

    // Call tc_sha256_final() so that it frees any internal data
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    tc_sha256_final(hash, &operation->state);

    // Set state to free so the operation can be reused
    operation->op_state = HASH_OPERATION_STATE_FREE;

    return PSA_SUCCESS;
}

psa_status_t tc_psa_hash_clone(const psa_hash_operation_t *source_operation,
                            psa_hash_operation_t *target_operation)
{
    GUARD_MODULE_INITIALIZED
    
    psa_status_t status = tc_psa_hash_setup(target_operation, PSA_ALG_SHA_256);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    target_operation->op_state = source_operation->op_state;
    target_operation->state.bits_hashed = target_operation->state.bits_hashed;
    target_operation->state.leftover_offset = source_operation->state.leftover_offset;
    memcpy(target_operation->state.iv, source_operation->state.iv, sizeof(source_operation->state.iv));
    memcpy(target_operation->state.leftover, source_operation->state.leftover, sizeof(source_operation->state.leftover));

    return PSA_SUCCESS;
}




/****************************************************************/
/* MAC */
/* Tinycrypt supports the following MAC: */
/*      HMAC-SHA256 */
/****************************************************************/

psa_status_t tc_psa_mac_compute(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t *input,
                             size_t input_length,
                             uint8_t *mac,
                             size_t mac_size,
                             size_t *mac_length)
{
    GUARD_MODULE_INITIALIZED

    if (!PSA_ALG_IS_MAC(alg))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (alg != PSA_ALG_HMAC(PSA_ALG_SHA_256))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if( mac_size < TC_SHA256_DIGEST_SIZE )
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (!key_slot_is_valid(key) || !key_slot_is_in_use(key))
    {
        return PSA_ERROR_INVALID_HANDLE;
    }

    psa_key_slot_t *key_slot = get_key_slot(key);
    if (!key_usage_flag_is_set(key_slot->attr.usage, PSA_KEY_USAGE_SIGN_HASH))
    {
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (!key_supports_algorith(alg, key_slot))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    struct tc_hmac_state_struct ctx;
    int tc_status = tc_hmac_set_key(&ctx, key_slot->key.data, key_slot->key.bytes);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    
    tc_status = tc_hmac_init(&ctx);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    tc_status = tc_hmac_update(&ctx, input, input_length);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    tc_status = tc_hmac_final(mac, mac_size, &ctx);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    // Set the output value 
    *mac_length = TC_SHA256_DIGEST_SIZE;

    return PSA_SUCCESS;
}

psa_status_t tc_psa_mac_verify(psa_key_id_t key,
                            psa_algorithm_t alg,
                            const uint8_t *input,
                            size_t input_length,
                            const uint8_t *mac,
                            size_t mac_length)
{
    GUARD_MODULE_INITIALIZED

    if (!PSA_ALG_IS_MAC(alg))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (alg != PSA_ALG_HMAC(PSA_ALG_SHA_256))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if( mac_length != TC_SHA256_DIGEST_SIZE )
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!key_slot_is_valid(key) || !key_slot_is_in_use(key))
    {
        return PSA_ERROR_INVALID_HANDLE;
    }

    psa_key_slot_t *key_slot = get_key_slot(key);
    if (!key_usage_flag_is_set(key_slot->attr.usage, PSA_KEY_USAGE_VERIFY_MESSAGE))
    {
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (!key_supports_algorith(alg, key_slot))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t actual_mac[TC_SHA256_DIGEST_SIZE];
    size_t actual_mac_length;

    struct tc_hmac_state_struct ctx;
    int tc_status = tc_hmac_set_key(&ctx, key_slot->key.data, key_slot->key.bytes);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    
    tc_status = tc_hmac_init(&ctx);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    tc_status = tc_hmac_update(&ctx, input, input_length);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    tc_status = tc_hmac_final(actual_mac, sizeof(actual_mac), &ctx);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    if (memcmp(actual_mac, mac, TC_SHA256_DIGEST_SIZE))
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;
}

psa_status_t tc_psa_mac_sign_setup(psa_mac_operation_t *operation,
                                psa_key_id_t key,
                                psa_algorithm_t alg)
{
    GUARD_MODULE_INITIALIZED

    if (!PSA_ALG_IS_MAC(alg))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (alg != PSA_ALG_HMAC(PSA_ALG_SHA_256))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (!key_slot_is_valid(key) || !key_slot_is_in_use(key))
    {
        return PSA_ERROR_INVALID_HANDLE;
    }

    psa_key_slot_t *key_slot = get_key_slot(key);
    if (!key_usage_flag_is_set(key_slot->attr.usage, PSA_KEY_USAGE_SIGN_MESSAGE))
    {
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (!key_supports_algorith(alg, key_slot))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (operation->state != MAC_OPERATION_STATE_FREE)
    {
        return PSA_ERROR_BAD_STATE;
    }

    int tc_status = tc_hmac_set_key(&operation->ctx, key_slot->key.data, key_slot->key.bytes);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    
    tc_status = tc_hmac_init(&operation->ctx);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    operation->state = MAC_OPERATION_STATE_INITIALISED;

    return PSA_SUCCESS;
    
}

psa_status_t tc_psa_mac_verify_setup(psa_mac_operation_t *operation,
                                  psa_key_id_t key,
                                  psa_algorithm_t alg)
{
    GUARD_MODULE_INITIALIZED

    if (!PSA_ALG_IS_MAC(alg))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (alg != PSA_ALG_HMAC(PSA_ALG_SHA_256))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (!key_slot_is_valid(key) || !key_slot_is_in_use(key))
    {
        return PSA_ERROR_INVALID_HANDLE;
    }

    psa_key_slot_t *key_slot = get_key_slot(key);
    if (!key_usage_flag_is_set(key_slot->attr.usage, PSA_KEY_USAGE_VERIFY_MESSAGE))
    {
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (!key_supports_algorith(alg, key_slot))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (operation->state != MAC_OPERATION_STATE_FREE)
    {
        return PSA_ERROR_BAD_STATE;
    }

    int tc_status = tc_hmac_set_key(&operation->ctx, key_slot->key.data, key_slot->key.bytes);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    tc_status = tc_hmac_init(&operation->ctx);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    operation->state = MAC_OPERATION_STATE_INITIALISED;

    return PSA_SUCCESS;
}

psa_status_t tc_psa_mac_update(psa_mac_operation_t *operation,
                            const uint8_t *input,
                            size_t input_length)
{
    GUARD_MODULE_INITIALIZED

    if (operation->state != MAC_OPERATION_STATE_INITIALISED)
    {
        return PSA_ERROR_BAD_STATE;
    }

    int tc_status = tc_hmac_update(&operation->ctx, input, input_length);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t tc_psa_mac_sign_finish(psa_mac_operation_t *operation,
                                 uint8_t *mac,
                                 size_t mac_size,
                                 size_t *mac_length)
{
    GUARD_MODULE_INITIALIZED

    if (operation->state != MAC_OPERATION_STATE_INITIALISED)
    {
        return PSA_ERROR_BAD_STATE;
    }

    if (mac_size < TC_SHA256_DIGEST_SIZE)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    int tc_status = tc_hmac_final(mac, mac_size, &operation->ctx);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    *mac_length = TC_SHA256_DIGEST_SIZE;

    return PSA_SUCCESS;
}

psa_status_t tc_psa_mac_verify_finish(psa_mac_operation_t *operation,
                                   const uint8_t *mac,
                                   size_t mac_length)
{
    GUARD_MODULE_INITIALIZED

    if (operation->state != MAC_OPERATION_STATE_INITIALISED)
    {
        return PSA_ERROR_BAD_STATE;
    }

    if (mac_length != TC_SHA256_DIGEST_SIZE)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    uint8_t calculated_mac[TC_SHA256_DIGEST_SIZE];
    int tc_status = tc_hmac_final(calculated_mac, sizeof(calculated_mac), &operation->ctx);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    if (memcmp(calculated_mac, mac, mac_length) != 0)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;
}

psa_status_t tc_psa_mac_abort(psa_mac_operation_t *operation)
{
    GUARD_MODULE_INITIALIZED

    operation->state = MAC_OPERATION_STATE_FREE;

    // Call tc_hmac_final to make sure it clears the operation internal state
    uint8_t buf[TC_SHA256_DIGEST_SIZE];
    tc_hmac_final(buf, sizeof(buf), &operation->ctx);

    return PSA_SUCCESS;
}




/****************************************************************/
/* Symmetric cipher */
/****************************************************************/

psa_status_t tc_psa_cipher_encrypt(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t *input,
                                size_t input_length,
                                uint8_t *output,
                                size_t output_size,
                                size_t *output_length)
{
    GUARD_MODULE_INITIALIZED

    if (!key_slot_is_valid(key) || !key_slot_is_in_use(key))
    {
        return PSA_ERROR_INVALID_HANDLE;
    }

    psa_key_slot_t* slot = get_key_slot(key);
    if( !key_usage_flag_is_set( slot->attr.usage, PSA_KEY_USAGE_ENCRYPT ) )
    {
        return(PSA_ERROR_NOT_PERMITTED);
    }

    psa_status_t status = validate_algorithm(alg);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    if (!key_supports_algorith(alg, slot))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (output_size < PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(slot->attr.type, alg, input_length))
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    uint8_t iv_buf[16] = {0};
    psa_generate_random(iv_buf, sizeof(iv_buf));
    memcpy(output, iv_buf, sizeof(iv_buf));
    
    struct tc_aes_key_sched_struct ctx;
    int tc_status = tc_aes128_set_encrypt_key(&ctx, slot->key.data);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    switch ( alg )
    {
        // NOTE: output_size is 16 bytes bigger than input_length because it includes the iv
        // We pass input_length as outlen to tinycrypt because it expects the output buffer to be the same size as the input buffer
        case PSA_ALG_CBC_NO_PADDING:
            tc_status = tc_cbc_mode_encrypt(output+16, input_length,
				input, input_length, iv_buf, &ctx);
            break;
        case PSA_ALG_CTR:
            tc_status = tc_ctr_mode(output+16, input_length,
				input, input_length, iv_buf, &ctx);
            break;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    *output_length = PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(slot->attr.type, alg, input_length);

   return PSA_SUCCESS;
}

psa_status_t tc_psa_cipher_decrypt(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t *input,
                                size_t input_length,
                                uint8_t *output,
                                size_t output_size,
                                size_t *output_length)
{
    GUARD_MODULE_INITIALIZED

    if (!key_slot_is_valid(key) || !key_slot_is_in_use(key))
    {
        return PSA_ERROR_INVALID_HANDLE;
    }

    psa_key_slot_t* slot = get_key_slot(key);
    if( !key_usage_flag_is_set( slot->attr.usage, PSA_KEY_USAGE_DECRYPT ) )
    {
        return(PSA_ERROR_NOT_PERMITTED);
    }

    psa_status_t status = validate_algorithm(alg);
    if (status != PSA_SUCCESS)
    {
        return status;
    }
    
    if (!key_supports_algorith(alg, slot))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // Note: output size needs at least 16 bytes extra containing the iv as this is a single part operation
    if (input_length < 16)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    // The first 16 bytes of the cipher text are the iv as this is a single part operation
    const uint8_t* iv = input;
    const uint8_t* cipher = input + 16;    
    struct tc_aes_key_sched_struct ctx;
    int tc_status = tc_aes128_set_decrypt_key(&ctx, slot->key.data);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    switch ( alg )
    {
        // NOTE: output_size is 16 bytes bigger than input_length because it includes the iv
        // We pass input_length as outlen to tinycrypt because it expects the output buffer to be the same size as the input buffer
        case PSA_ALG_CBC_NO_PADDING:
            tc_status = tc_cbc_mode_decrypt(output, input_length,
				cipher, input_length-16, iv, &ctx);
            break;
        case PSA_ALG_CTR:
            // TODO The iv param is discarding const qualifier
            // What should we pass here? What is it used for? If replaced with NULL then the test fails
            // Try passing an empty buffer, alternatively copy the value of iv to a local buffer
            {
                uint8_t buf[input_length];
                memcpy(buf, iv, input_length);
                tc_status = tc_ctr_mode(output, input_length-16,
				    cipher, input_length-16, buf, &ctx);

            }
            break;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
     
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    *output_length = input_length - 16;

   return PSA_SUCCESS;
}

psa_status_t tc_psa_cipher_encrypt_setup(psa_cipher_operation_t *operation,
                                      psa_key_id_t key,
                                      psa_algorithm_t alg)
{
    GUARD_MODULE_INITIALIZED

    if (operation->state != CIPHER_OPERATION_STATE_FREE)
    {
        return PSA_ERROR_BAD_STATE;
    }

    if (!key_slot_is_valid(key) || !key_slot_is_in_use(key))
    {
        return PSA_ERROR_INVALID_HANDLE;
    }

    psa_key_slot_t* slot = get_key_slot(key);
    if( !key_usage_flag_is_set( slot->attr.usage, PSA_KEY_USAGE_ENCRYPT ) )
    {
        return(PSA_ERROR_NOT_PERMITTED);
    }

    psa_status_t status = validate_algorithm(alg);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    if (!key_supports_algorith(alg, slot))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    struct tc_aes_key_sched_struct ctx;
    int tc_status = tc_aes128_set_encrypt_key(&ctx, slot->key.data);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    operation->state = CIPHER_OPERATION_STATE_NO_IV;
    operation->type = CIPHER_OPERATION_TYPE_ENCRYPT;
    operation->alg = alg;

    return PSA_SUCCESS;
}

psa_status_t tc_psa_cipher_decrypt_setup(psa_cipher_operation_t *operation,
                                      psa_key_id_t key,
                                      psa_algorithm_t alg)
{
    GUARD_MODULE_INITIALIZED

    if (operation->state != CIPHER_OPERATION_STATE_FREE)
    {
        return PSA_ERROR_BAD_STATE;
    }

    if (!key_slot_is_valid(key) || !key_slot_is_in_use(key))
    {
        return PSA_ERROR_INVALID_HANDLE;
    }

    psa_key_slot_t* slot = get_key_slot(key);
    if( !key_usage_flag_is_set( slot->attr.usage, PSA_KEY_USAGE_DECRYPT ) )
    {
        return(PSA_ERROR_NOT_PERMITTED);
    }

    psa_status_t status = validate_algorithm(alg);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    if (!key_supports_algorith(alg, slot))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    struct tc_aes_key_sched_struct ctx;
    int tc_status = tc_aes128_set_decrypt_key(&ctx, slot->key.data);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    operation->state = CIPHER_OPERATION_STATE_NO_IV;
    operation->type = CIPHER_OPERATION_TYPE_DECRYPT;
    operation->alg = alg;

    return PSA_SUCCESS;
}

psa_status_t tc_psa_cipher_generate_iv(psa_cipher_operation_t *operation,
                                    uint8_t *iv,
                                    size_t iv_size,
                                    size_t *iv_length)
{
    GUARD_MODULE_INITIALIZED

    if (operation->state != CIPHER_OPERATION_STATE_NO_IV)
    {
        return PSA_ERROR_BAD_STATE;
    }

    if (!iv)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (iv_size < 16)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    memset(iv, 0, 16);
    *iv_length = 16;
    tc_psa_generate_random(iv, 16);
    memcpy(operation->iv, iv, 16);
    operation->state = CIPHER_OPERATION_STATE_ACTIVE;

    return PSA_SUCCESS;                        
}

psa_status_t tc_psa_cipher_set_iv(psa_cipher_operation_t *operation,
                               const uint8_t *iv,
                               size_t iv_length)
{
    GUARD_MODULE_INITIALIZED

    if (!iv)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (operation->state != CIPHER_OPERATION_STATE_NO_IV)
    {
        return PSA_ERROR_BAD_STATE;
    }

    if (iv_length != 16)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    memcpy(operation->iv, iv, 16);
    operation->state = CIPHER_OPERATION_STATE_ACTIVE;

    return PSA_SUCCESS;
}

psa_status_t tc_psa_cipher_update(psa_cipher_operation_t *operation,
                               const uint8_t *input,
                               size_t input_length,
                               uint8_t *output,
                               size_t output_size,
                               size_t *output_length)
{
    GUARD_MODULE_INITIALIZED

    if (!input || !output || !output_length)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (operation->state != CIPHER_OPERATION_STATE_NO_IV)
    {
        return PSA_ERROR_BAD_STATE;
    }

    if (output_size < input_length)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (input_length % 16 != 0 || output_size % 16 != 0)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    int tc_status;
    if (operation->type == CIPHER_OPERATION_TYPE_ENCRYPT)
    {
        switch ( operation->alg )
        {
            case PSA_ALG_CBC_NO_PADDING:
                tc_status = tc_cbc_mode_encrypt(output, input_length,
                    input, input_length, operation->iv, operation->ctx);
                break;
            case PSA_ALG_CTR:
                tc_status = tc_ctr_mode(output+16, input_length,
                    input, input_length, operation->iv, operation->ctx);
            default:
                return PSA_ERROR_NOT_SUPPORTED;
        }
    }
    else
    {
        switch ( operation->alg )
        {
            case PSA_ALG_CBC_NO_PADDING:
                tc_status = tc_cbc_mode_decrypt(output, input_length,
                    input, input_length, operation->iv, operation->ctx);
                break;
            case PSA_ALG_CTR:
                tc_status = tc_ctr_mode(output+16, input_length,
                    input, input_length, operation->iv, operation->ctx);
            default:
                return PSA_ERROR_NOT_SUPPORTED;
        }
    }

    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    *output_length = input_length;

    return PSA_SUCCESS;
}

psa_status_t tc_psa_cipher_finish(psa_cipher_operation_t *operation,
                               uint8_t *output,
                               size_t output_size,
                               size_t *output_length) {};

psa_status_t tc_psa_cipher_abort(psa_cipher_operation_t *operation) {};



/****************************************************************/
/* Aead */
/****************************************************************/
 
// Use AES_CCM algorithm for authenticated encryption
psa_status_t tc_psa_aead_encrypt(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t *nonce,
                              size_t nonce_length,
                              const uint8_t *additional_data,
                              size_t additional_data_length,
                              const uint8_t *plaintext,
                              size_t plaintext_length,
                              uint8_t *ciphertext,
                              size_t ciphertext_size,
                              size_t *ciphertext_length)
                              {};

psa_status_t tc_psa_aead_decrypt(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t *nonce,
                              size_t nonce_length,
                              const uint8_t *additional_data,
                              size_t additional_data_length,
                              const uint8_t *ciphertext,
                              size_t ciphertext_length,
                              uint8_t *plaintext,
                              size_t plaintext_size,
                              size_t *plaintext_length) {};

psa_aead_operation_t tc_psa_aead_operation_init(void) {};

psa_status_t tc_psa_aead_encrypt_setup(psa_aead_operation_t *operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg) {};

psa_status_t tc_psa_aead_decrypt_setup(psa_aead_operation_t *operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg) {};

psa_status_t tc_psa_aead_generate_nonce(psa_aead_operation_t *operation,
                                     uint8_t *nonce,
                                     size_t nonce_size,
                                     size_t *nonce_length) {};

psa_status_t tc_psa_aead_set_nonce(psa_aead_operation_t *operation,
                                const uint8_t *nonce,
                                size_t nonce_length) {};

psa_status_t tc_psa_aead_set_lengths(psa_aead_operation_t *operation,
                                  size_t ad_length,
                                  size_t plaintext_length) {};

psa_status_t tc_psa_aead_update_ad(psa_aead_operation_t *operation,
                                const uint8_t *input,
                                size_t input_length) {};

psa_status_t tc_psa_aead_update(psa_aead_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length,
                             uint8_t *output,
                             size_t output_size,
                             size_t *output_length) {};

psa_status_t tc_psa_aead_finish(psa_aead_operation_t *operation,
                             uint8_t *ciphertext,
                             size_t ciphertext_size,
                             size_t *ciphertext_length,
                             uint8_t *tag,
                             size_t tag_size,
                             size_t *tag_length) {};

psa_status_t tc_psa_aead_verify(psa_aead_operation_t *operation,
                             uint8_t *plaintext,
                             size_t plaintext_size,
                             size_t *plaintext_length,
                             const uint8_t *tag,
                             size_t tag_length) {};

psa_status_t tc_psa_aead_abort(psa_aead_operation_t *operation) {};




/****************************************************************/
/* Message sign and verify */
/****************************************************************/

psa_status_t tc_psa_sign_message( psa_key_id_t key,
                               psa_algorithm_t alg,
                               const uint8_t * input,
                               size_t input_length,
                               uint8_t * signature,
                               size_t signature_size,
                               size_t * signature_length ) {};

psa_status_t tc_psa_verify_message( psa_key_id_t key,
                                 psa_algorithm_t alg,
                                 const uint8_t * input,
                                 size_t input_length,
                                 const uint8_t * signature,
                                 size_t signature_length ) {};

psa_status_t tc_psa_sign_hash(psa_key_id_t key,
                           psa_algorithm_t alg,
                           const uint8_t *hash,
                           size_t hash_length,
                           uint8_t *signature,
                           size_t signature_size,
                           size_t *signature_length) {};

psa_status_t tc_psa_verify_hash(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t *hash,
                             size_t hash_length,
                             const uint8_t *signature,
                             size_t signature_length) {};




/****************************************************************/
/* Asymetric encrypt and decrypt */
/****************************************************************/

psa_status_t tc_psa_asymmetric_encrypt(psa_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *input,
                                    size_t input_length,
                                    const uint8_t *salt,
                                    size_t salt_length,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *output_length) {};

psa_status_t tc_psa_asymmetric_decrypt(psa_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *input,
                                    size_t input_length,
                                    const uint8_t *salt,
                                    size_t salt_length,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *output_length) {};

psa_status_t tc_psa_raw_key_agreement(psa_algorithm_t alg,
                                   psa_key_id_t private_key,
                                   const uint8_t *peer_key,
                                   size_t peer_key_length,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_length) {};




/****************************************************************/
/* Test helpers */
/****************************************************************/

#ifdef UNIT_TEST_BUILD
bool global_data_is_initialized(void)
{
    return global_data.initialized;
}

size_t global_data_get_key_slots_used(void)
{
    return global_data.key_slots_used;
}

void global_data_set_key_slots_used(size_t slots)
{
    global_data.key_slots_used = slots;
}

void reset_global_data(void)
{
    memset(&global_data, 0, sizeof(global_data));
}

void global_data_fill_all_key_slots()
{
    global_data.key_slots_used = PSA_KEY_SLOT_COUNT;
}

bool is_handle_invalidated(uint32_t handle)
{
    for (int i=0; i<global_data.invalid_key_handles_count; i++)
    {
        if (global_data.invalid_key_handles[i] == handle)
        {
            return true;
        }
    }
    return false;
}

#endif