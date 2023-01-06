#include "psa/crypto.h"
// #include "psa_shim/crypto_values.h"
#include "tinycrypt/constants.h"
#include "tinycrypt/ctr_prng.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "tinycrypt/ctr_prng.h"
#include "tinycrypt/constants.h"
#include "tinycrypt/ctr_prng.h"
#include "tinycrypt/hmac.h"
#include "tinycrypt/cbc_mode.h"
#include "tinycrypt/ctr_mode.h"

/*
TODO Remove this
Following constants are here only for initial development purposes, so we have some sample keys to test
They must be removed and the values for keys must be read from key storage once key storage is imlemented  
*/ 

static const uint8_t hmac_key[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66 };
uint8_t aes_cbc_key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t aes_ctr_key[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
uint8_t iv_buf_cbc[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
uint8_t iv_buf_ctr[] = { 0x22, 0x22, 0x1a, 0x70, 0x22, 0x22, 0x1a, 0x70, 0x22, 0x22, 0x1a, 0x70, 0x22, 0x22, 0x1a, 0x70 };

/****************************************************************/
/* Type declarations and preprocessor macros */
/****************************************************************/




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
 
    /* Initialize drivers */

    /* If PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS load transactions etc. not sure what this is  */

    global_data.initialized = true;

    exit:
        if (tc_status != TC_CRYPTO_SUCCESS)
        {
            // TODO free any resources
        }
        return tc_to_psa_status(tc_status);
}




/****************************************************************/
/* Random generation */
/****************************************************************/

psa_status_t tc_psa_generate_random( uint8_t *output,
                                  size_t output_size )
{
    GUARD_MODULE_INITIALIZED

    // TODO Support external RNG

    // TODO Assert enough entropy

    int tc_status = tc_ctr_prng_generate(&ctx, 0, 0, output, output_size);
    return tc_to_psa_status(tc_status);
}




/****************************************************************/
/* Key management */
/****************************************************************/

psa_status_t tc_psa_generate_key(const psa_key_attributes_t *attributes,
                              psa_key_id_t *key)
{
    psa_status_t status;
    size_t key_buffer_size;

    // TODO Secure element support
    *key = 0;

    /* Reject any attempt to create a zero-length key so that we don't
     * risk tripping up later, e.g. on a malloc(0) that returns NULL. */
    if( psa_get_key_bits( attributes ) == 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    return PSA_SUCCESS;
}

psa_status_t tc_psa_close_key( psa_key_handle_t handle )
{
    psa_status_t status;

    if( psa_key_handle_is_null( handle ) )
        return( PSA_SUCCESS );

    // Get the slot and check if it needs wiped
}

psa_status_t tc_psa_open_key( psa_key_handle_t key,
                           psa_key_handle_t *handle )
{
    // TODO Open key
    psa_status_t status;
}

static void tc_psa_set_key_id(psa_key_attributes_t *attributes,
                           psa_key_id_t key)
{
    psa_key_lifetime_t lifetime = attributes->lifetime;

    attributes->id = key;

    if( PSA_KEY_LIFETIME_IS_VOLATILE( lifetime ) )
    {
        attributes->lifetime =
            PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
                PSA_KEY_LIFETIME_PERSISTENT,
                PSA_KEY_LIFETIME_GET_LOCATION( lifetime ) );
    }
}

void rtc_psa_set_key_lifetime(psa_key_attributes_t *attributes,
                                 psa_key_lifetime_t lifetime)
{
    attributes->lifetime = lifetime;
    if( PSA_KEY_LIFETIME_IS_VOLATILE( lifetime ) )
    {
        attributes->id = 0;
    }
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
    tc_psa_reset_key_attributes( attributes );
    // TODO psa_get_key_attributes
}
                                
void tc_psa_reset_key_attributes(psa_key_attributes_t *attributes)
{
    // Free any dynamically allocated attributes
    memset( attributes, 0, sizeof( *attributes ) );
}

psa_status_t tc_psa_purge_key(psa_key_id_t key)
{
    // TODO psa_purge_key
}

psa_status_t tc_psa_copy_key(psa_key_id_t source_key,
                          const psa_key_attributes_t *attributes,
                          psa_key_id_t *target_key)
{
    // TODO psa_copy_key
}

psa_status_t tc_psa_destroy_key(psa_key_id_t key)
{
    // TODO psa_destroy key
}

psa_status_t tc_psa_import_key(const psa_key_attributes_t *attributes,
                            const uint8_t *data,
                            size_t data_length,
                            psa_key_id_t *key)
{
    // TODO psa_import key
}

psa_status_t tc_psa_export_key(psa_key_id_t key,
                            uint8_t *data,
                            size_t data_size,
                            size_t *data_length)
{
    // TODO psa_export_key
}

psa_status_t tc_psa_export_public_key(psa_key_id_t key,
                                   uint8_t *data,
                                   size_t data_size,
                                   size_t *data_length)
{
    // TODO psa_export_public_key
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
    *hash_length = 0;
    
    if( alg != PSA_ALG_SHA_256)
        return( PSA_ERROR_NOT_SUPPORTED );
    
    if (hash_size < PSA_HASH_MAX_SIZE)
        return( PSA_ERROR_INVALID_ARGUMENT );

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    struct tc_sha256_state_struct state;
    (void)tc_sha256_init(&state);
    tc_sha256_update(&state, (const uint8_t *) input, input_length);
    (void)tc_sha256_final(hash, &state);
    *hash_length = PSA_HASH_MAX_SIZE;
    // printf("Computed hash: ");
    // print_hex(hash, *hash_length);
    // printf("\n");
    return PSA_SUCCESS;
}

psa_status_t tc_psa_hash_compare(psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              const uint8_t *hash,
                              size_t hash_length)
{
    if( !PSA_ALG_IS_HASH( alg ) )
        return( PSA_ERROR_NOT_SUPPORTED );
    
    uint8_t actual_hash[PSA_HASH_MAX_SIZE];
    size_t actual_hash_length;

    psa_status_t status = tc_psa_hash_compute(
                            alg, input, input_length,
                            actual_hash, sizeof(actual_hash),
                            &actual_hash_length );
    
    if( status != PSA_SUCCESS )
        goto exit;
    
    if( actual_hash_length != hash_length )
    {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

    if (memcmp(hash, actual_hash, actual_hash_length) != 0)
        status = PSA_ERROR_INVALID_SIGNATURE;

    exit:
        zeroize( actual_hash, sizeof( actual_hash ) );
        return( status );
}

psa_status_t tc_psa_hash_setup(psa_hash_operation_t *operation,
                            psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    /* A context must be freshly initialized before it can be set up. */
    if( operation->op_state != HASH_OPERATION_STATE_INITIALISED )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if(!PSA_ALG_IS_HASH( alg ))
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    if(alg != PSA_ALG_SHA_256)
    {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }

    operation->op_state = HASH_OPERATION_STATE_INITIALISED;
    (void)tc_sha256_init(&operation->state);
    exit:
        if( status != PSA_SUCCESS )
            tc_psa_hash_abort( operation );

    return status;
}

psa_status_t tc_psa_hash_update(psa_hash_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    
    if(operation->op_state != HASH_OPERATION_STATE_INITIALISED && operation->op_state != HASH_OPERATION_STATE_INPROGRESS)
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit; 
    }

    /* Don't require hash implementations to behave correctly on a
     * zero-length input, which may have an invalid pointer. */
    if( input_length == 0 )
        return( PSA_SUCCESS );
    
    int tc_status = tc_sha256_update(&operation->state, (const uint8_t *) input, input_length);
    if(tc_status == TC_CRYPTO_SUCCESS)
    {
        status = PSA_SUCCESS;
    }
    else
    {
        status = PSA_ERROR_COMMUNICATION_FAILURE;
        goto exit;
    }
    
    exit:
        if( status != PSA_SUCCESS )
            tc_psa_hash_abort( operation );

    return( status );
}

psa_status_t tc_psa_hash_finish(psa_hash_operation_t *operation,
                             uint8_t *hash,
                             size_t hash_size,
                             size_t *hash_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (hash_size < PSA_HASH_MAX_SIZE)
        return PSA_ERROR_INVALID_ARGUMENT;
        
    if(operation->op_state != HASH_OPERATION_STATE_INITIALISED && operation->op_state != HASH_OPERATION_STATE_INPROGRESS)
    {
        return PSA_ERROR_BAD_STATE;
    }

    int tc_status = tc_sha256_final(hash, &operation->state);
    if(tc_status == TC_CRYPTO_SUCCESS)
    {
        hash_size = PSA_HASH_MAX_SIZE;
        status = PSA_SUCCESS;
    }
    else
    {
        status = PSA_ERROR_COMMUNICATION_FAILURE;
        goto exit;
    }
    
    exit:
        if( status != PSA_SUCCESS )
            tc_psa_hash_abort( operation );

    return(status);
}

psa_status_t tc_psa_hash_verify(psa_hash_operation_t *operation,
                             const uint8_t *hash,
                             size_t hash_length)
{
    uint8_t actual_hash[PSA_HASH_MAX_SIZE];
    size_t actual_hash_length;

    psa_status_t status = tc_psa_hash_finish(
                            operation,
                            actual_hash, sizeof( actual_hash ),
                            &actual_hash_length );

    if( status != PSA_SUCCESS )
        goto exit;

    if( actual_hash_length != hash_length )
    {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

    if( memcmp(hash, actual_hash, actual_hash_length) != 0 )
        status = PSA_ERROR_INVALID_SIGNATURE;
    
    exit:
        zeroize( actual_hash, sizeof( actual_hash ) );
        if( status != PSA_SUCCESS )
            tc_psa_hash_abort(operation);

    return( status );
}

psa_status_t tc_psa_hash_abort(psa_hash_operation_t *operation)
{
    if(operation->op_state != HASH_OPERATION_STATE_INITIALISED && operation->op_state != HASH_OPERATION_STATE_INPROGRESS)
    {
        return PSA_SUCCESS;
    }

    operation->op_state = HASH_OPERATION_STATE_ABORTED;

    return PSA_SUCCESS;
}

psa_status_t tc_psa_hash_clone(const psa_hash_operation_t *source_operation,
                            psa_hash_operation_t *target_operation)
{
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

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;

    if (alg != PSA_ALG_HMAC(PSA_ALG_SHA_256))
    {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }

    if( mac_size < TC_SHA256_DIGEST_SIZE )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    struct tc_hmac_state_struct ctx;

    // TODO Set the key. Need to get it from storage, hardcoding for now
    
    int tc_status = tc_hmac_set_key(&ctx, hmac_key, sizeof(hmac_key));
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        status = PSA_ERROR_COMMUNICATION_FAILURE;
        goto exit;
    }
    
    // Compute MAC
    tc_status = tc_hmac_init(&ctx);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        status = PSA_ERROR_COMMUNICATION_FAILURE;
        goto exit;
    }
    tc_status = tc_hmac_update(&ctx, input, input_length);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        status = PSA_ERROR_COMMUNICATION_FAILURE;
        goto exit;
    }
    tc_status = tc_hmac_final(mac, mac_size, &ctx);
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        status = PSA_ERROR_COMMUNICATION_FAILURE;
        goto exit;
    }

    // Set the output value 
    *mac_length = TC_SHA256_DIGEST_SIZE;

    status = PSA_SUCCESS;

    exit:
        // unlock_status = psa_unlock_key_slot( slot );
        // return( ( status == PSA_SUCCESS ) ? unlock_status : status );
        return status;
}

psa_status_t tc_psa_mac_verify(psa_key_id_t key,
                            psa_algorithm_t alg,
                            const uint8_t *input,
                            size_t input_length,
                            const uint8_t *mac,
                            size_t mac_length)
{
    GUARD_MODULE_INITIALIZED

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t actual_mac[TC_SHA256_DIGEST_SIZE];
    size_t actual_mac_length;

    status = psa_mac_compute( key, alg,
                            input, input_length,
                            actual_mac, sizeof( actual_mac ),
                            &actual_mac_length);
    if( status != PSA_SUCCESS )
        goto exit;
    
    if (memcmp(actual_mac, mac, TC_SHA256_DIGEST_SIZE))
    {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

    exit:
        memset( actual_mac, 0, sizeof( actual_mac ) );

        return ( status );
}

psa_status_t tc_psa_mac_sign_setup(psa_mac_operation_t *operation,
                                psa_key_id_t key,
                                psa_algorithm_t alg) {};

psa_status_t tc_psa_mac_verify_setup(psa_mac_operation_t *operation,
                                  psa_key_id_t key,
                                  psa_algorithm_t alg) {};

psa_status_t tc_psa_mac_update(psa_mac_operation_t *operation,
                            const uint8_t *input,
                            size_t input_length) {};

psa_status_t tc_psa_mac_sign_finish(psa_mac_operation_t *operation,
                                 uint8_t *mac,
                                 size_t mac_size,
                                 size_t *mac_length) {};

psa_status_t tc_psa_mac_verify_finish(psa_mac_operation_t *operation,
                                   const uint8_t *mac,
                                   size_t mac_length) {};

psa_status_t tc_psa_mac_abort(psa_mac_operation_t *operation) {};




/****************************************************************/
/* Symmetric cipher */
/* Tinycrypt supports following cyphers: */
/*      AES128-CBC */
/*      AES128-CCM */
/*      AES128-CMAC */
/*      AES128-CTR */
/****************************************************************/

psa_status_t tc_psa_cipher_encrypt(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t *input,
                                size_t input_length,
                                uint8_t *output,
                                size_t output_size,
                                size_t *output_length)
{
    /*
        Tinycrypt supports following cyphers:
        AES128-CBC
        AES128-CCM
        AES128-CMAC
        AES128-CTR
    */

    // TODO Get key from slot
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( ! PSA_ALG_IS_CIPHER( alg ) )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    if ( alg != PSA_ALG_CBC_NO_PADDING &&
        alg != PSA_ALG_CCM &&
        alg != PSA_ALG_CMAC &&
        alg != PSA_ALG_CTR
    )
    {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }

    // TODO Generate rando iv_buf and get key from slot
    
    struct tc_aes_key_sched_struct ctx;
    int tc_status;
    switch ( alg )
    {
        case PSA_ALG_CBC_NO_PADDING:
            (void)tc_aes128_set_encrypt_key(&ctx, aes_cbc_key);
            tc_status = tc_cbc_mode_encrypt(output, output_size,
				input, input_length, iv_buf_cbc, &ctx);
            break;
        case PSA_ALG_CTR:
            (void)tc_aes128_set_encrypt_key(&ctx, aes_ctr_key);
            tc_status = tc_ctr_mode(output, output_size,
				input, input_length, iv_buf_ctr, &ctx);
    }
     
    if (tc_status != TC_CRYPTO_SUCCESS)
    {
        status = PSA_ERROR_COMMUNICATION_FAILURE;
        goto exit;
    }

    status = PSA_SUCCESS;

    exit:
        if( status != PSA_SUCCESS )
        {
            *output_length = 0;
        }

        return( status );
}

psa_status_t tc_psa_cipher_decrypt(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t *input,
                                size_t input_length,
                                uint8_t *output,
                                size_t output_size,
                                size_t *output_length) {};

// psa_cipher_operation_t tc_psa_cipher_operation_init(void) {};

psa_status_t tc_psa_cipher_encrypt_setup(psa_cipher_operation_t *operation,
                                      psa_key_id_t key,
                                      psa_algorithm_t alg) {};

psa_status_t tc_psa_cipher_decrypt_setup(psa_cipher_operation_t *operation,
                                      psa_key_id_t key,
                                      psa_algorithm_t alg) {};

psa_status_t tc_psa_cipher_generate_iv(psa_cipher_operation_t *operation,
                                    uint8_t *iv,
                                    size_t iv_size,
                                    size_t *iv_length) {};

psa_status_t tc_psa_cipher_set_iv(psa_cipher_operation_t *operation,
                               const uint8_t *iv,
                               size_t iv_length) {};

psa_status_t tc_psa_cipher_update(psa_cipher_operation_t *operation,
                               const uint8_t *input,
                               size_t input_length,
                               uint8_t *output,
                               size_t output_size,
                               size_t *output_length) {};

psa_status_t tc_psa_cipher_finish(psa_cipher_operation_t *operation,
                               uint8_t *output,
                               size_t output_size,
                               size_t *output_length) {};

psa_status_t tc_psa_cipher_abort(psa_cipher_operation_t *operation) {};



/****************************************************************/
/* Aead */
/****************************************************************/

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
                              size_t *ciphertext_length){};

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




