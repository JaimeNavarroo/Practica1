/*
 * aes_crc_custom_layer.h
 *
 * This layer provides Integrity Validation of messages via CRC 32
 * It also provides message encryption via AES128
 *
 *      Author: James
 */

#ifndef AES_CRC_CUSTOM_LAYER_H_
#define AES_CRC_CUSTOM_LAYER_H_

//-----------------Includes-----------------
#include "fsl_debug_console.h"
#include "aes.h"
#include "fsl_crc.h"

#include <math.h>

//----------------Definitions---------------

//This structure allows us to return both the encrypted message and the length of the array from a function
typedef struct crypt_msg_t{
	uint8_t* encrypted_msg;
	size_t padded_len;
}crypt_msg_t;



//-----------------Prototypes--------------
/*!
 * @brief Init for CRC-32.
 * @details Init CRC peripheral module for CRC-32 protocol.
 *          width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xcbf43926
 *          name="CRC-32"
 *          http://reveng.sourceforge.net/crc-catalogue/
 */
void InitCrc32(CRC_Type *base, uint32_t seed);


/*!
 * @brief Test function for AES and CRC
 * @details This function validates the AES and CRC functionality
 *
 */

void aescrc_test_task(void *arg);

/*!
 * @brief Encrypt a message with AES
 * @details AES
 *
 */
crypt_msg_t aes_encrypt_message(uint8_t message[]);

/*!
 * @brief Decrypts a message with AES
 * @details AES
 *
 */
crypt_msg_t aes_decrypt_message(uint8_t message[]);

/*!
 * @brief Calculate CRC332
 * @details CRC
 *
 */
uint32_t calculate_crc32(crypt_msg_t msg);

/*!
 * @brief Decode incoming packet
 * @details Decrypts incoming packet
 */

crypt_msg_t decode_message(crypt_msg_t msg);

/*!
 * @brief Encode outgoing packet
 * @details Encode outgoing packet
 */

crypt_msg_t encode_message(crypt_msg_t msg);

#endif /* AES_CRC_CUSTOM_LAYER_H_ */
