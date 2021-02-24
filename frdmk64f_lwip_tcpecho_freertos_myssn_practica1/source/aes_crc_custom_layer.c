/*
 * aes_crc_custom_layer.c
 *
 * This layer provides Integrity Validation of messages via CRC 32
 * It also provides message encryption via AES128
 *
 *      Author: James
 */

//------------------Includes---------------------

#include "aes_crc_custom_layer.h"

//------------------Variables--------------------

/* AES data */
uint8_t key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
uint8_t iv[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
struct AES_ctx ctx;
size_t test_string_len,padded_len;
uint8_t padded_msg[512] = {0};


/*!
 * @brief Init for CRC-32.
 * @details Init CRC peripheral module for CRC-32 protocol.
 *          width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xcbf43926
 *          name="CRC-32"
 *          http://reveng.sourceforge.net/crc-catalogue/
 */
void InitCrc32(CRC_Type *base, uint32_t seed)
{
    crc_config_t config;

    config.polynomial         = 0x04C11DB7U;
    config.seed               = seed;
    config.reflectIn          = true;
    config.reflectOut         = true;
    config.complementChecksum = true;
    config.crcBits            = kCrcBits32;
    config.crcResult          = kCrcFinalChecksum;

    CRC_Init(base, &config);
}

/*!
 * @brief Test function for AES and CRC
 * @details This function validates the AES and CRC functionality*/
void aescrc_test_task(void *arg)
{

	uint8_t test_string[] = {"01234567890123456789"};
	crypt_msg_t test_crypt_msg, test_decrypt_msg;
	uint32_t test_checksum32;

	PRINTF("Testing AES and CRC with the test string 01234567890123456789\r\n\n");
	PRINTF("\nTesting AES128\r\n\n");

	test_crypt_msg = aes_encrypt_message(test_string);

	PRINTF("Encrypted Message: ");
	for(int i=0; i<test_crypt_msg.padded_len; i++) {
		PRINTF("0x%02x,", test_crypt_msg.encrypted_msg[i]);
	}
	PRINTF("\r\n");


	PRINTF("\nTesting CRC32\r\n\n");

	test_checksum32 = calculate_crc32(test_crypt_msg);

    PRINTF("CRC-32: 0x%08x\r\n", test_checksum32);
    PRINTF("AES encryption and CRC test successful\r\n\n");

    PRINTF("Testing decryption..\r\n\n");

    test_decrypt_msg = aes_decrypt_message(test_crypt_msg.encrypted_msg);

	PRINTF("Decrypted Message: ");
	for(int i=0; i<test_decrypt_msg.padded_len; i++) {
		PRINTF("0x%02x,", test_decrypt_msg.encrypted_msg[i]);
	}
	PRINTF("\r\n");

}

/*!
 * @brief aes_encrypt_message
 * @details This function encrypts a message with AES
 */

crypt_msg_t aes_encrypt_message(uint8_t message[])
{
	crypt_msg_t new_message;
	/* Init the AES context structure */
	AES_init_ctx_iv(&ctx, key, iv);

	/* To encrypt an array its length must be a multiple of 16 so we add zeros */
	test_string_len = strlen(message);
	padded_len = test_string_len + (16 - (test_string_len%16) );
	memcpy(padded_msg, message, test_string_len);

	/*Encrypt the buffer */
	AES_CBC_encrypt_buffer(&ctx, padded_msg, padded_len);

	new_message.encrypted_msg = padded_msg;
	new_message.padded_len =  padded_len;

	return new_message;
}

/*!
 * @brief aes_encrypt_message
 * @details This function encrypts a message with AES
 */

crypt_msg_t aes_decrypt_message(uint8_t message[])
{
	crypt_msg_t new_message;
	uint8_t message_len = 0;
	/* Init the AES context structure */
	AES_init_ctx_iv(&ctx, key, iv);



	test_string_len = strlen(message);
	padded_len = test_string_len;// + (16 - (test_string_len%16) );
	memcpy(padded_msg, message, test_string_len);

	/*Decrypt the buffer */
	AES_CBC_decrypt_buffer(&ctx, padded_msg, padded_len);

	for(uint8_t i = 0; i < padded_len; i++ )
	{
		if(padded_msg[i] == 0)
		{
			message_len = i;
			break;
		}
	}

	new_message.encrypted_msg = padded_msg;
	new_message.padded_len = message_len;

	return new_message;
}

/*!
 * @brief calculate_crc32
 * @details This function calculates the crc32
 */
uint32_t calculate_crc32(crypt_msg_t msg)
{
	/* CRC data */
	CRC_Type *base = CRC0;
	uint32_t checksum32;

	InitCrc32(base, 0xFFFFFFFFU);
	CRC_WriteData(base, msg.encrypted_msg, msg.padded_len);
	checksum32 = CRC_Get32bitResult(base);

	return checksum32;
}

/*!
 * @brief Decode incoming packet
 * @details Decrypts incoming packet
 */

crypt_msg_t decode_message(crypt_msg_t msg)
{
	uint8_t body_bytes[128];
	uint8_t crc_bytes[4];
	uint8_t counter = 0;
	crypt_msg_t split_msg_crc;
	crypt_msg_t split_msg_aes;
	uint32_t checksum_original =  0;
	uint32_t checksum_calc =  0;

	//Get the message body bytes
	for(uint8_t i = 0; i < msg.padded_len - 4; i++)
	{
		body_bytes[i] = msg.encrypted_msg[i];
	}

	//Get the CRC bytes
	for(uint8_t i = msg.padded_len - 4; i < msg.padded_len; i++)
	{
		crc_bytes[counter] = msg.encrypted_msg[i];
		counter++;
	}

	//Convert the CRC bytes from the message to int
	for (uint8_t i = 0; i < 4; i++)
	{
		checksum_original = checksum_original + ( crc_bytes[i] *  pow(256,i) );
	}


	split_msg_crc.encrypted_msg = body_bytes;
	split_msg_crc.padded_len =  msg.padded_len - 4;;

	checksum_calc = calculate_crc32(split_msg_crc);

	if(checksum_original == checksum_calc)
	{
		PRINTF("Calculated Checksum: %u, Original checksum: %u \r\n\n",checksum_calc, checksum_original);
		PRINTF("Checksum match! Decrypting message..\r\n\n");

		split_msg_aes = aes_decrypt_message(body_bytes);

		PRINTF("Decrypted Message: ");
		for(int i=0; i<split_msg_aes.padded_len; i++)
		{
			PRINTF("%c", split_msg_aes.encrypted_msg[i]);
		}
		PRINTF("\r\n");
	}
	else
	{
		PRINTF("Calculated Checksum: %u, Original checksum: %u \r\n\n",checksum_calc, checksum_original);
		PRINTF("Checksum mismmatch! \r\n\n");
	}

	return split_msg_aes;
}

crypt_msg_t encode_message(crypt_msg_t msg)
{
	crypt_msg_t encoded_msg;
	uint32_t crc_calc = 0;
	uint8_t crc_bytes[4];

	//Encrypt the message
	encoded_msg = aes_encrypt_message(msg.encrypted_msg);

	//Calculate the CRC of the encrypted mesage
	crc_calc = calculate_crc32(encoded_msg);

	//Convert the CRC int to a 4 byte array
	crc_bytes[0] = crc_calc  & 0xFF;
	crc_bytes[1] = (crc_calc >> 8) & 0xFF;
	crc_bytes[2] = (crc_calc >> 16) & 0xFF;
	crc_bytes[3] = (crc_calc >> 24) & 0xFF;

	//Add the 4 byte CRC array to the end of the message array
	encoded_msg.encrypted_msg[encoded_msg.padded_len + 0] = crc_bytes[0];
	encoded_msg.encrypted_msg[encoded_msg.padded_len + 1] = crc_bytes[1];
	encoded_msg.encrypted_msg[encoded_msg.padded_len + 2] = crc_bytes[2];
	encoded_msg.encrypted_msg[encoded_msg.padded_len + 3] = crc_bytes[3];

	//Update the message length
	encoded_msg.padded_len = encoded_msg.padded_len + 4;

	return encoded_msg;
}
