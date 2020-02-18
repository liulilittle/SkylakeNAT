#pragma once

#include <stdio.h>
#include <string>
#include <WinSock2.h>
#include <Windows.h>
#include <dbghelp.h>

std::string				CPUID();
std::string				GetPreferredVolumelabel();
std::string				GetVolumelabelNumber(const std::string& volumelabel);
std::string				CreateGuid();
std::string				ComputeMD5(const std::string& s);
void					ComputeMD5(const std::string& s, const unsigned char* md5, int& md5len);
int						GetMacFromNetbios(const char* mac);
std::string&			GetApplicationKey();
int						GetApplicationId();
int						GetHashCode(const std::string& s);
int						GetHashCode(const void* data, int datalen);
int						GetProcessorCount();
unsigned long long		GetTickCount(bool microseconds);
std::string				GetCurrentTimeCrt(const char* fmt = NULL);
std::string				GetAddressText(unsigned int address);
std::string				GetExecutionFileName();
std::string				GetFullExecutionFilePath();
std::string				GetApplicationStartupPath();
std::string				ToString(int value, int radix = 10);
bool					WriteDumpFile(const char* dumpFilePathName, EXCEPTION_POINTERS *exception);
#ifndef _DEBUG
#define					PrintTraceToScreen(...)
#define					PrintTraceEthernetInput(...)
#else 
template<typename...Args>
inline void				PrintTraceToScreen(const char* fmt, const Args& ...args)
{
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hStdOut) {
		char szFmt[570];
		szFmt[0] = '\x0';
		sprintf(szFmt, fmt, args...);
		if (*szFmt) {
			char sz[65535];
			sprintf(sz, "[%s] %s\n", GetCurrentTimeCrt().c_str(), szFmt);
			if (*sz) {
				DWORD dwBytesWritten;
				WriteConsoleA(hStdOut, sz, (DWORD)strlen(sz), &dwBytesWritten, NULL);
			}
		}
	}
}
#ifdef __NO_PRINT_TRACE_ETHERNET_INPUT_MESSAGE
#define					PrintTraceEthernetInput(...)
#else
template<typename T>
inline void				PrintTraceEthernetInput(T packet, int wlan, int success) {
	if (!packet)
		return;
	std::string src = GetAddressText(packet->_src);
	std::string dest = GetAddressText(packet->_dest);
	if (wlan)
		PrintTraceToScreen("WLAN [%d] %.2d LINK %-16s -> %-16s", success, packet->_proto, src.c_str(), dest.c_str());
	else
		PrintTraceToScreen("LAN  [%d] %.2d LINK %-16s -> %-16s", success, packet->_proto, src.c_str(), dest.c_str());
}
#endif
#endif