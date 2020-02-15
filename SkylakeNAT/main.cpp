#include "env.h"
#include "nat.h"
#if !defined(_USE_RC4_SIMPLE_ENCIPHER)
#include "encryptor.h"
#endif

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "WinMM.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "dbghelp.lib")
#if !defined(_USE_RC4_SIMPLE_ENCIPHER)
#pragma comment (lib, "libeay32.lib" )
#pragma comment (lib, "ssleay32.lib" )
#endif
inline std::string carg(const char* name, int argc, const char* argv[])
{
	if (argc <= 1)
		return "";
	for (int i = 1; i < argc; i++) {
		char* p = (char*)strstr(argv[i], name);
		if (!p)
			continue;
		p = strchr(p, '=');
		if (!p)
			continue;
		return 1 + p;
	}
	return "";
}

LONG WINAPI ApplicationCrashHandler(
	_In_ struct _EXCEPTION_POINTERS *ExceptionInfo
)
{
	char szFileName[MAX_PATH * 4];
	std::string strExecutionFileName = GetFullExecutionFilePath();
	if (!strExecutionFileName.empty()) {
		size_t dwPos = strExecutionFileName.rfind('.');
		if (dwPos != std::string::npos) {
			((char*)strExecutionFileName.data())[dwPos] = '\x0';
		}
	}
	sprintf(szFileName, "%s-%s.dmp", 
		strExecutionFileName.data(),
		GetCurrentTimeCrt("%02d-%02d-%02d %02d-%02d-%02d").data());
	WriteDumpFile(szFileName, ExceptionInfo);
	return EXCEPTION_EXECUTE_HANDLER;
}

int main(int argc, const char* argv[])
{
	SetUnhandledExceptionFilter(ApplicationCrashHandler);
	SetConsoleTitle(TEXT("SkylakeNAT-cli"));
	
#if !defined(_USE_RC4_SIMPLE_ENCIPHER)
	Encryptor::Initialize();
#endif
	if (argc < 5) {
		std::string server = "172.8.8.8";
		auto ni = Tap::GetPreferredNetworkInterface();
		if (ni.get()) 
			server = ni->Address;
		printf("usage: %s --server=%s --port=7521 --key=123456 --subtract=25 --max-concurrent=1\n", 
			GetExecutionFileName().data(),
			server.data());
		getchar();
	}
	else {
		std::string server			= carg("--server", argc, argv);
		int			port			= atoi(carg("--port", argc, argv).data());
		std::string key				= carg("--key", argc, argv);
		int			subtract		= atoi(carg("--subtract", argc, argv).data());
		int			maxconcurrent	= atoi(carg("--max-concurrent", argc, argv).data());
		maxconcurrent				= maxconcurrent <= 0 ? 1: maxconcurrent;

		auto nat = std::make_shared<NAT>(Tap::FindNetworkInterface(Tap::GetDefaultComponentId()),
			GetApplicationId(), server, port, maxconcurrent, key, subtract);
		nat->Listen();
	}
	return 0;
}