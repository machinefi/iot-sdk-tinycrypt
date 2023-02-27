/*
 * Copyright (c) 2018-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
/**
 * \file psa/crypto_struct.h
 *
 * \brief PSA cryptography module: structured type implementations
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file contains the definitions of some data structures with
 * implementation-specific definitions.
 *
 * In implementations with isolation between the application and the
 * cryptography module, it is expected that the front-end and the back-end
 * would have different versions of this file.
 */

#ifndef PSA_CRYPTO_STRUCT_H
#define PSA_CRYPTO_STRUCT_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Note that the below structures are different from the decalrations in
 * mbed-crypto. This is because TF-M maintains 'front-end' and 'back-end'
 * versions of this header. In the front-end version, exported to NS
 * clients in interface/include/psa, a crypto operation is defined as an
 * opaque handle to a context in the Crypto service. The back-end
 * version, directly included from the mbed-crypto repo by the Crypto
 * service, contains the full definition of the operation structs.
 *
 * One of the functions of the Crypto service is to allocate the back-end
 * operation contexts in its own partition memory (in crypto_alloc.c),
 * and then do the mapping between front-end operation handles passed by
 * NS clients and the corresponding back-end operation contexts. The
 * advantage of doing it this way is that internal mbed-crypto state is never
 * exposed to the NS client.
 */

#include <stdbool.h>

#include "tinycrypt/ctr_prng.h"
#include "tinycrypt/sha256.h"
#include "tinycrypt/hmac.h"
#include "tinycrypt/aes.h"

#ifndef MAX_KEY_HANDLES
    #define MAX_KEY_HANDLES 64
#endif
#ifndef PSA_KEY_SLOT_COUNT
    #define PSA_KEY_SLOT_COUNT 32
#endif
#ifndef PSA_OPERATION_COUNT
    #define PSA_OPERATION_COUNT 32
#endif

typedef enum
{
    TC_RNG_NOT_INITIALIZED,
    TC_RNG_INITIALIZED,
    TC_RNG_RESEEDED
} tc_rng_state_t;

#define KEY_ID_INVALID 0xFFFFFFFF;

typedef struct 
{
    struct
    {
        uint16_t type;
        uint16_t bits;
        uint32_t lifetime;
        uint32_t usage;
        uint32_t alg;
    } attr;
    uint32_t handle;
    bool in_use;  // If 0 then the slot is free
    /* Dynamically allocated key data buffer.
     * Format as specified in psa_export_key(). */
    struct key_data
    {
        uint8_t *data;
        size_t bytes;
    } key;
} psa_key_slot_t;

#define GUARD_MODULE_INITIALIZED        \
    if( global_data.initialized == 0 )  \
        return( PSA_ERROR_BAD_STATE );

typedef enum
{
    PSA_KEY_CREATION_IMPORT, /**< During psa_import_key() */
    PSA_KEY_CREATION_GENERATE, /**< During psa_generate_key() */
    PSA_KEY_CREATION_DERIVE, /**< During psa_key_derivation_output_key() */
    PSA_KEY_CREATION_COPY, /**< During psa_copy_key() */
} psa_key_creation_method_t;

typedef enum
{
    HASH_OPERATION_STATE_FREE,
    HASH_OPERATION_STATE_INITIALISED,
    HASH_OPERATION_STATE_INPROGRESS,
    HASH_OPERATION_STATE_ABORTED
} tc_psa_hash_operation_state_t;

struct psa_hash_operation_s
{
    tc_psa_hash_operation_state_t op_state;
    struct tc_sha256_state_struct state;
};

static inline struct psa_hash_operation_s psa_hash_operation_init( void )
{
    struct psa_hash_operation_s op;
    op.op_state = HASH_OPERATION_STATE_INITIALISED;
    (void)tc_sha256_init(&op.state);
    return op;
}

#ifndef PSA_MAX_OPERATIONS
    #define PSA_MAX_OPERATIONS 8
#endif

typedef enum
{
    MAC_OPERATION_STATE_FREE,
    MAC_OPERATION_STATE_INITIALISED,
    MAC_OPERATION_STATE_INPROGRESS
} tc_psa_mac_operation_state_t;

struct psa_mac_operation_s
{
    tc_psa_mac_operation_state_t state;
    struct tc_hmac_state_struct ctx;
};

#define PSA_MAC_OPERATION_INIT {0}
static inline struct psa_mac_operation_s psa_mac_operation_init( void )
{
    const struct psa_mac_operation_s v = PSA_MAC_OPERATION_INIT;
    return( v );
}

typedef enum
{
    CIPHER_OPERATION_STATE_FREE,
    CIPHER_OPERATION_STATE_NO_IV,
    CIPHER_OPERATION_STATE_ACTIVE
} tc_psa_cipher_operation_state_t;

typedef enum
{
    CIPHER_OPERATION_TYPE_ENCRYPT,
    CIPHER_OPERATION_TYPE_DECRYPT
} tc_psa_cipher_operation_type_t;

struct psa_cipher_operation_s
{
    tc_psa_cipher_operation_state_t state;
    tc_psa_cipher_operation_type_t type;
    uint32_t alg;
    TCAesKeySched_t ctx;
    uint8_t iv[16];
};

#define PSA_CIPHER_OPERATION_INIT {0}
static inline struct psa_cipher_operation_s psa_cipher_operation_init( void )
{
    const struct psa_cipher_operation_s v = PSA_CIPHER_OPERATION_INIT;
    return( v );
}

struct psa_aead_operation_s
{
    uint32_t handle;
};

#define PSA_AEAD_OPERATION_INIT {0}
static inline struct psa_aead_operation_s psa_aead_operation_init( void )
{
    const struct psa_aead_operation_s v = PSA_AEAD_OPERATION_INIT;
    return( v );
}

struct psa_key_derivation_s
{
    uint32_t handle;
};

#define PSA_KEY_DERIVATION_OPERATION_INIT {0}
static inline struct psa_key_derivation_s psa_key_derivation_operation_init( void )
{
    const struct psa_key_derivation_s v = PSA_KEY_DERIVATION_OPERATION_INIT;
    return( v );
}

typedef struct
{
    bool initialized;
    tc_rng_state_t rng_state;
    TCCtrPrng_t rng;
    uint32_t invalid_key_handles[MAX_KEY_HANDLES];
    uint32_t invalid_key_handles_count;
    uint32_t next_key_handle;
    psa_key_slot_t key_slots[PSA_KEY_SLOT_COUNT];
    size_t key_slots_used;
    struct psa_hash_operation_s hash_operations[PSA_OPERATION_COUNT];
} tc_psa_global_data_t;

/* The type used internally for key sizes.
 * Public interfaces use size_t, but internally we use a smaller type. */
typedef uint16_t psa_key_bits_t;
/* The maximum value of the type used to represent bit-sizes.
 * This is used to mark an invalid key size. */
#define PSA_KEY_BITS_TOO_LARGE ( (psa_key_bits_t) ( -1 ) )
/* The maximum size of a key in bits.
 * Currently defined as the maximum that can be represented, rounded down
 * to a whole number of bytes.
 * This is an uncast value so that it can be used in preprocessor
 * conditionals. */
#define PSA_MAX_KEY_BITS 0xfff8

#define PSA_KEY_ATTRIBUTES_INIT PSA_CLIENT_KEY_ATTRIBUTES_INIT

static inline struct psa_client_key_attributes_s psa_key_attributes_init( void )
{
    const struct psa_client_key_attributes_s v = PSA_KEY_ATTRIBUTES_INIT;
    return( v );
}

static inline void psa_set_key_id(psa_key_attributes_t *attributes,
                                  psa_key_id_t key)
{
    psa_key_lifetime_t lifetime = attributes->lifetime;

    attributes->id = key;

    if( PSA_KEY_LIFETIME_IS_VOLATILE(lifetime))
    {
        attributes->lifetime =
            PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
                PSA_KEY_LIFETIME_PERSISTENT,
                PSA_KEY_LIFETIME_GET_LOCATION(lifetime));
    }
}

static inline psa_key_id_t psa_get_key_id(
    const psa_key_attributes_t *attributes)
{
    return( attributes->id );
}

static inline void psa_set_key_lifetime(psa_key_attributes_t *attributes,
                                        psa_key_lifetime_t lifetime)
{
    attributes->lifetime = lifetime;
    if(PSA_KEY_LIFETIME_IS_VOLATILE(lifetime))
    {
        attributes->id = 0;
    }
}

static inline psa_key_lifetime_t psa_get_key_lifetime(
    const psa_key_attributes_t *attributes)
{
    return( attributes->lifetime );
}

static inline void psa_extend_key_usage_flags(psa_key_usage_t *usage_flags)
{
    if (*usage_flags & PSA_KEY_USAGE_SIGN_HASH)
        *usage_flags |= PSA_KEY_USAGE_SIGN_MESSAGE;

    if (*usage_flags & PSA_KEY_USAGE_VERIFY_HASH)
        *usage_flags |= PSA_KEY_USAGE_VERIFY_MESSAGE;
}

static inline void psa_set_key_usage_flags(psa_key_attributes_t *attributes,
                                           psa_key_usage_t usage_flags)
{
    psa_extend_key_usage_flags(&usage_flags);
    attributes->usage = usage_flags;
}

static inline psa_key_usage_t psa_get_key_usage_flags(
    const psa_key_attributes_t *attributes)
{
    return( attributes->usage );
}

static inline void psa_set_key_algorithm(psa_key_attributes_t *attributes,
                                         psa_algorithm_t alg)
{
    attributes->alg = alg;
}

static inline psa_algorithm_t psa_get_key_algorithm(
    const psa_key_attributes_t *attributes)
{
    return( attributes->alg );
}

static inline void psa_set_key_type(psa_key_attributes_t *attributes,
                                    psa_key_type_t type)
{
    attributes->type = type;
}

static inline psa_key_type_t psa_get_key_type(
    const psa_key_attributes_t *attributes)
{
    return( attributes->type );
}

static inline void psa_set_key_bits(psa_key_attributes_t *attributes,
                                    size_t bits)
{
    if( bits > PSA_MAX_KEY_BITS )
        attributes->bits = PSA_KEY_BITS_TOO_LARGE;
    else
        attributes->bits = bits;
}

static inline size_t psa_get_key_bits(
    const psa_key_attributes_t *attributes)
{
    return( attributes->bits );
}

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_STRUCT_H */
