#include "common.h"
#include "bundle.h"
#include "macho.h"
#include "openssl.h"
#include "zsign_export.h"

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#define ZSIGN_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define ZSIGN_EXPORT
#endif

#define ZSIGN_VERSION "0.7"

static string SafeString(const char* value)
{
	return value ? string(value) : string();
}

static string SafePath(const char* value)
{
	if (!value || value[0] == '\0') {
		return "";
	}
	return ZFile::GetFullPath(value);
}

static bool PrepareTargetPath(const string& inputFile, const string& outputFile, string& targetFile)
{
	targetFile = inputFile;
	if (outputFile.empty() || outputFile == inputFile) {
		return true;
	}
	if (!ZFile::CopyFile(inputFile.c_str(), outputFile.c_str())) {
		ZLog::ErrorV(">>> Copy input Mach-O failed: %s -> %s\n", inputFile.c_str(), outputFile.c_str());
		return false;
	}
	targetFile = outputFile;
	return true;
}

static string GetTempRoot()
{
	static string sTempRoot = "/zsign_tmp";
	static once_flag sOnce;
	call_once(sOnce, []() {
		ZFile::CreateFolder(sTempRoot.c_str());
	});
	return sTempRoot;
}

static string BuildTempFilePath(const char* prefix, const char* suffix)
{
	static uint64_t sSeq = 0;
	uint64_t seq = ++sSeq;
	return ZFile::GetRealPathV("%s/%s_%llu_%llu%s",
		GetTempRoot().c_str(),
		prefix,
		ZUtil::GetMicroSecond(),
		(unsigned long long)seq,
		suffix ? suffix : "");
}

static bool WriteBlobToTempFile(const char* prefix, const char* suffix, const unsigned char* data, unsigned int len, string& outPath)
{
	outPath.clear();
	if (!data || len == 0) {
		return false;
	}

	string tmp = BuildTempFilePath(prefix, suffix);
	if (!ZFile::WriteFile(tmp.c_str(), (const char*)data, (size_t)len)) {
		return false;
	}
	outPath = tmp;
	return true;
}

static void RemoveTempFiles(const vector<string>& files)
{
	for (const string& f : files) {
		if (!f.empty()) {
			ZFile::RemoveFile(f.c_str());
		}
	}
}

extern "C" {

ZSIGN_EXPORT const char* zsign_version()
{
	return ZSIGN_VERSION;
}

ZSIGN_EXPORT int zsign_set_log_level(int level)
{
	if (level < ZLog::E_NONE) {
		level = ZLog::E_NONE;
	}
	if (level > ZLog::E_DEBUG) {
		level = ZLog::E_DEBUG;
	}
	ZLog::SetLogLever(level);
	return 0;
}

ZSIGN_EXPORT int zsign_sign_macho(
	const char* input_macho,
	const char* output_macho,
	const char* cert_file,
	const char* pkey_file,
	const char* prov_file,
	const char* password,
	const char* entitlements_file,
	int adhoc,
	int sha256_only,
	int force_sign)
{
	string inputMachO = SafePath(input_macho);
	if (inputMachO.empty() || !ZFile::IsFileExists(inputMachO.c_str()) || ZFile::IsFolder(inputMachO.c_str())) {
		ZLog::ErrorV(">>> Invalid Mach-O path! %s\n", inputMachO.c_str());
		return -1;
	}

	string outputMachO = SafePath(output_macho);
	string certFile = SafePath(cert_file);
	string pkeyFile = SafePath(pkey_file);
	string provFile = SafePath(prov_file);
	string entitlementsFile = SafePath(entitlements_file);
	string passwd = SafeString(password);

	bool bAdhoc = (adhoc != 0);
	bool bSHA256Only = (sha256_only != 0);
	bool bForceSign = (force_sign != 0);

	if (!bAdhoc && (pkeyFile.empty() || provFile.empty())) {
		ZLog::Error(">>> Non ad-hoc mode needs private key and provisioning profile.\n");
		return -2;
	}

	if (ZLog::IsDebug()) {
		ZFile::CreateFolder("./.zsign_debug");
	}

	string targetMachO;
	if (!PrepareTargetPath(inputMachO, outputMachO, targetMachO)) {
		return -3;
	}

	ZMachO macho;
	if (!macho.Init(targetMachO.c_str())) {
		ZLog::ErrorV(">>> Invalid mach-o file! %s\n", targetMachO.c_str());
		return -4;
	}

	ZSignAsset zsa;
	if (!zsa.Init(certFile, pkeyFile, provFile, entitlementsFile, passwd, bAdhoc, bSHA256Only, true)) {
		return -5;
	}

	string strInfoSHA1;
	string strInfoSHA256;
	string strCodeResourcesData;
	bool bRet = macho.Sign(&zsa, bForceSign, "", strInfoSHA1, strInfoSHA256, strCodeResourcesData);
	return bRet ? 0 : -6;
}

ZSIGN_EXPORT int zsign_sign_bundle(
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
	int enable_cache)
{
	string inputFolder = SafePath(input_folder);
	if (inputFolder.empty() || !ZFile::IsFolder(inputFolder.c_str())) {
		ZLog::ErrorV(">>> Invalid bundle folder path! %s\n", inputFolder.c_str());
		return -201;
	}

	string certFile = SafePath(cert_file);
	string pkeyFile = SafePath(pkey_file);
	string provFile = SafePath(prov_file);
	string entitlementsFile = SafePath(entitlements_file);
	string passwd = SafeString(password);
	string bundleId = SafeString(bundle_id);
	string bundleVersion = SafeString(bundle_version);
	string displayName = SafeString(display_name);

	bool bAdhoc = (adhoc != 0);
	bool bSHA256Only = (sha256_only != 0);
	bool bForceSign = (force_sign != 0);
	bool bWeakInject = (weak_inject != 0);
	bool bEnableCache = (enable_cache != 0);

	if (!bAdhoc && (pkeyFile.empty() || provFile.empty())) {
		ZLog::Error(">>> Non ad-hoc mode needs private key and provisioning profile.\n");
		return -202;
	}

	if (ZLog::IsDebug()) {
		ZFile::CreateFolder("./.zsign_debug");
	}

	ZSignAsset zsa;
	if (!zsa.Init(certFile, pkeyFile, provFile, entitlementsFile, passwd, bAdhoc, bSHA256Only, false)) {
		return -203;
	}

	ZBundle bundle;
	vector<string> arrDylibFiles;
	bool bRet = bundle.SignFolder(
		&zsa,
		inputFolder,
		bundleId,
		bundleVersion,
		displayName,
		arrDylibFiles,
		bForceSign,
		bWeakInject,
		bEnableCache);
	return bRet ? 0 : -204;
}

ZSIGN_EXPORT int zsign_sign_macho_mem(
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
	unsigned int* output_len)
{
	if (!output_data || !output_len) {
		return -101;
	}

	*output_data = NULL;
	*output_len = 0;

	if (!input_data || input_len == 0) {
		return -102;
	}

	vector<string> tempFiles;
	string inputFile = BuildTempFilePath("input", ".macho");
	string outputFile = BuildTempFilePath("output", ".macho");
	tempFiles.push_back(inputFile);
	tempFiles.push_back(outputFile);

	if (!ZFile::WriteFile(inputFile.c_str(), (const char*)input_data, (size_t)input_len)) {
		RemoveTempFiles(tempFiles);
		return -103;
	}

	string certFile;
	if (cert_data && cert_len > 0) {
		if (!WriteBlobToTempFile("cert", ".bin", cert_data, cert_len, certFile)) {
			RemoveTempFiles(tempFiles);
			return -104;
		}
		tempFiles.push_back(certFile);
	}

	string pkeyFile;
	if (pkey_data && pkey_len > 0) {
		if (!WriteBlobToTempFile("pkey", ".bin", pkey_data, pkey_len, pkeyFile)) {
			RemoveTempFiles(tempFiles);
			return -105;
		}
		tempFiles.push_back(pkeyFile);
	}

	string provFile;
	if (prov_data && prov_len > 0) {
		if (!WriteBlobToTempFile("prov", ".mobileprovision", prov_data, prov_len, provFile)) {
			RemoveTempFiles(tempFiles);
			return -106;
		}
		tempFiles.push_back(provFile);
	}

	string entitlementsFile;
	if (entitlements_data && entitlements_len > 0) {
		if (!WriteBlobToTempFile("entitlements", ".plist", entitlements_data, entitlements_len, entitlementsFile)) {
			RemoveTempFiles(tempFiles);
			return -107;
		}
		tempFiles.push_back(entitlementsFile);
	}

	int ret = zsign_sign_macho(
		inputFile.c_str(),
		outputFile.c_str(),
		certFile.c_str(),
		pkeyFile.c_str(),
		provFile.c_str(),
		password ? password : "",
		entitlementsFile.c_str(),
		adhoc,
		sha256_only,
		force_sign);
	if (ret != 0) {
		RemoveTempFiles(tempFiles);
		return ret;
	}

	string outData;
	if (!ZFile::ReadFile(outputFile.c_str(), outData)) {
		RemoveTempFiles(tempFiles);
		return -108;
	}

	unsigned char* out = (unsigned char*)malloc(outData.size());
	if (!out) {
		RemoveTempFiles(tempFiles);
		return -109;
	}

	memcpy(out, outData.data(), outData.size());
	*output_data = out;
	*output_len = (unsigned int)outData.size();

	RemoveTempFiles(tempFiles);
	return 0;
}

ZSIGN_EXPORT void zsign_free_buffer(void* p)
{
	if (p) {
		free(p);
	}
}

}
