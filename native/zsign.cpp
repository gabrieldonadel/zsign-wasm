#include "common.h"
#include "macho.h"
#include "openssl.h"
#include "timer.h"

#ifdef _WIN32
#include "common_win32.h"
#endif

#define ZSIGN_VERSION "0.7"

const struct option options[] = {
	{"debug", no_argument, NULL, 'd'},
	{"adhoc", no_argument, NULL, 'a'},
	{"cert", required_argument, NULL, 'c'},
	{"pkey", required_argument, NULL, 'k'},
	{"prov", required_argument, NULL, 'm'},
	{"password", required_argument, NULL, 'p'},
	{"entitlements", required_argument, NULL, 'e'},
	{"output", required_argument, NULL, 'o'},
	{"sha256_only", no_argument, NULL, '2'},
	{"quiet", no_argument, NULL, 'q'},
	{"force", no_argument, NULL, 'f'},
	{"help", no_argument, NULL, 'h'},
	{}
};

int usage()
{
	ZLog::PrintV("zsign (v%s) macho signer mode.\n\n", ZSIGN_VERSION);
	ZLog::Print("Usage: zsign [-options] -k privkey.pem -m dev.prov [-c cert.pem] [-o output_macho] input_macho\n");
	ZLog::Print("options:\n");
	ZLog::Print("-k, --pkey\t\tPath to private key or p12 file. (PEM/DER/P12)\n");
	ZLog::Print("-m, --prov\t\tPath to mobile provisioning profile.\n");
	ZLog::Print("-c, --cert\t\tPath to certificate file. (PEM or DER format)\n");
	ZLog::Print("-a, --adhoc\t\tPerform ad-hoc signature only.\n");
	ZLog::Print("-o, --output\t\tOutput Mach-O path. Defaults to signing in-place.\n");
	ZLog::Print("-p, --password\t\tPassword for private key or p12 file.\n");
	ZLog::Print("-e, --entitlements\tPath to entitlements plist (mainly for ad-hoc).\n");
	ZLog::Print("-2, --sha256_only\tSerialize a single code directory that uses SHA256.\n");
	ZLog::Print("-d, --debug\t\tGenerate debug output files. (.zsign_debug folder)\n");
	ZLog::Print("-f, --force\t\tForce sign even if already signed.\n");
	ZLog::Print("-q, --quiet\t\tQuiet operation.\n");
	ZLog::Print("-v, --version\t\tShows version.\n");
	ZLog::Print("-h, --help\t\tShows help (this message).\n");

	return -1;
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

int main(int argc, char* argv[])
{
	ZTimer gtimer;
	ZTimer stimer;

	bool bForce = false;
	bool bAdhoc = false;
	bool bSHA256Only = false;

	string strCertFile;
	string strPKeyFile;
	string strProvFile;
	string strPassword;
	string strOutputFile;
	string strEntitleFile;

	int opt = 0;
	int argslot = -1;
	while (-1 != (opt = getopt_long(argc, argv, "dfa2hqvc:k:m:o:p:e:",
		options, &argslot))) {
		switch (opt) {
		case 'd':
			ZLog::SetLogLever(ZLog::E_DEBUG);
			break;
		case 'f':
			bForce = true;
			break;
		case 'c':
			strCertFile = ZFile::GetFullPath(optarg);
			break;
		case 'k':
			strPKeyFile = ZFile::GetFullPath(optarg);
			break;
		case 'm':
			strProvFile = ZFile::GetFullPath(optarg);
			break;
		case 'a':
			bAdhoc = true;
			break;
		case 'p':
			strPassword = optarg;
			break;
		case 'e':
			strEntitleFile = ZFile::GetFullPath(optarg);
			break;
		case 'o':
			strOutputFile = ZFile::GetFullPath(optarg);
			break;
		case '2':
			bSHA256Only = true;
			break;
		case 'q':
			ZLog::SetLogLever(ZLog::E_NONE);
			break;
		case 'v': {
			printf("version: %s\n", ZSIGN_VERSION);
			return 0;
			}
			break;
		case 'h':
		case '?':
			return usage();
			break;
		}

		ZLog::DebugV(">>> Option:\t-%c, %s\n", opt, optarg);
	}

	if (optind >= argc) {
		return usage();
	}

	string strInputMachO = ZFile::GetFullPath(argv[optind]);
	if (!ZFile::IsFileExists(strInputMachO.c_str()) || ZFile::IsFolder(strInputMachO.c_str())) {
		ZLog::ErrorV(">>> Invalid Mach-O path! %s\n", strInputMachO.c_str());
		return -1;
	}

	if (!bAdhoc && (strPKeyFile.empty() || strProvFile.empty())) {
		ZLog::Error(">>> Non ad-hoc mode needs --pkey and --prov.\n");
		return -1;
	}

	if (ZLog::IsDebug()) {
		ZFile::CreateFolder("./.zsign_debug");
	}

	string strTargetMachO;
	if (!PrepareTargetPath(strInputMachO, strOutputFile, strTargetMachO)) {
		return -1;
	}

	ZMachO macho;
	if (!macho.Init(strTargetMachO.c_str())) {
		ZLog::ErrorV(">>> Invalid mach-o file! %s\n", strTargetMachO.c_str());
		return -1;
	}

	ZSignAsset zsa;
	if (!zsa.Init(strCertFile, strPKeyFile, strProvFile, strEntitleFile, strPassword, bAdhoc, bSHA256Only, true)) {
		return -1;
	}

	stimer.Reset();
	ZLog::PrintV(">>> Signing:\t%s %s\n", strTargetMachO.c_str(), bAdhoc ? "(Ad-hoc)" : "");
	string strInfoSHA1;
	string strInfoSHA256;
	string strCodeResourcesData;
	bool bRet = macho.Sign(&zsa, bForce, "", strInfoSHA1, strInfoSHA256, strCodeResourcesData);
	stimer.PrintResult(bRet, ">>> Signed %s!", bRet ? "OK" : "Failed");

	gtimer.Print(">>> Done.");
	return bRet ? 0 : -1;
}
