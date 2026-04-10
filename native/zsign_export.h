#pragma once

#ifdef __cplusplus
extern "C" {
#endif

const char* zsign_version();
int zsign_set_log_level(int level);

// Return 0 on success, non-zero on failure.
int zsign_sign_macho(
	const char* input_macho,
	const char* output_macho,
	const char* cert_file,
	const char* pkey_file,
	const char* prov_file,
	const char* password,
	const char* entitlements_file,
	int adhoc,
	int sha256_only,
	int force_sign);

// Bundle interface. input_folder can be app folder or its parent (e.g. Payload/).
// Return 0 on success, non-zero on failure.
int zsign_sign_bundle(
	const char* input_folder,
	const char* cert_file,
	const char* pkey_file,
	const char* prov_file,
	const char* password,
	const char* entitlements_file,
	const char* bundle_id,
	const char* bundle_version,
	const char* display_name,
	int adhoc,
	int sha256_only,
	int force_sign,
	int weak_inject,
	int enable_cache);

// Memory interface. Inputs may be NULL/0 when not needed.
// On success:
//   *output_data points to a newly allocated buffer
//   *output_len contains output length
// Caller must free by zsign_free_buffer(*output_data).
int zsign_sign_macho_mem(
	const unsigned char* input_data,
	unsigned int input_len,
	const unsigned char* cert_data,
	unsigned int cert_len,
	const unsigned char* pkey_data,
	unsigned int pkey_len,
	const unsigned char* prov_data,
	unsigned int prov_len,
	const char* password,
	const unsigned char* entitlements_data,
	unsigned int entitlements_len,
	int adhoc,
	int sha256_only,
	int force_sign,
	unsigned char** output_data,
	unsigned int* output_len);

void zsign_free_buffer(void* p);

#ifdef __cplusplus
}
#endif
