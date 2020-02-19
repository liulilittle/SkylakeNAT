#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <WinSock2.h>
#include <Windows.h>
#include <iphlpapi.h>

#include <string>
#include <memory>
#include <sstream>
#include <exception>

#include "env.h"
#include "tap.h"
#include "tap-windows.h"

#define 	M_DEBUG_LEVEL   (0x0F) /* debug level mask */
#define 	M_FATAL   (1<<4) /* exit program */
#define 	M_NONFATAL   (1<<5) /* non-fatal error */
#define 	M_WARN   (1<<6) /* call syslog with LOG_WARNING */
#define 	M_DEBUG   (1<<7)
#define 	M_ERRNO   (1<<8) /* show errno description */
#define 	M_NOMUTE   (1<<11) /* don't do mute processing */
#define 	M_NOPREFIX   (1<<12) /* don't show date/time prefix */
#define 	M_USAGE_SMALL   (1<<13) /* fatal options error, call usage_small */
#define 	M_MSG_VIRT_OUT   (1<<14) /* output message through msg_status_output callback */
#define 	M_OPTERR   (1<<15) /* print "Options error:" prefix */
#define 	M_NOLF   (1<<16) /* don't print new line */
#define 	M_NOIPREFIX   (1<<17) /* don't print instance prefix */
#define 	M_ERR   (M_FATAL | M_ERRNO)
#define 	M_USAGE   (M_USAGE_SMALL | M_NOPREFIX | M_OPTERR)
#define 	M_CLIENT   (M_MSG_VIRT_OUT | M_NOMUTE | M_NOIPREFIX)
#define 	EXIT_FATAL(flags)   do { if ((flags) & M_FATAL) {_exit(1);}} while (false)
#define 	HAVE_VARARG_MACROS

inline static BOOL
synchronized_deviceiocontrol(
	_In_ HANDLE hDevice,
	_In_ DWORD dwIoControlCode,
	_In_reads_bytes_opt_(nInBufferSize) LPVOID lpInBuffer,
	_In_ DWORD nInBufferSize,
	_Out_writes_bytes_to_opt_(nOutBufferSize, *lpBytesReturned) LPVOID lpOutBuffer,
	_In_ DWORD nOutBufferSize,
	_Out_opt_ LPDWORD lpBytesReturned
) {
	OVERLAPPED overlapped{ 0 };
	overlapped.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);

	BOOL status = DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, &overlapped);
	if (!status) {
		if (GetLastError() == ERROR_IO_PENDING) {
			if (WAIT_OBJECT_0 != WaitForSingleObject(overlapped.hEvent, INFINITE)) {
				assert(false);
			}
			CloseHandle(overlapped.hEvent);
			status = (overlapped.Internal == ERROR_SUCCESS);
		}
		else
			status = FALSE;
	}
	CloseHandle(overlapped.hEvent);
	return status;
}

Tap::Tap(std::string componentId)
    : _disposed(false)
    , _tap(NULL)
    , _pullUp(0)
    , _asyncsending(false) {
    if (componentId.empty())
        throw std::invalid_argument("You cannot provide an empty ethernet device componentId");
    _interfaces = Tap::FindNetworkInterface(componentId);
    if (!_interfaces.get())
        throw std::invalid_argument("The device you provide to componentId is not valid and it cannot go to the specified componentId in the system network device");
    std::stringstream ss;
    ss << USERMODEDEVICEDIR;
    ss << componentId.data();
    ss << TAP_WIN_SUFFIX;
    _tap = CreateFileA(
        ss.str().c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_SYSTEM,
        NULL);
    if (NULL == _tap)
        throw std::system_error(std::make_error_code(std::errc::no_such_device_or_address), "Unable to open drive handle for ethernet tap device");
}

Tap::~Tap() {
	Close();
}

void Tap::Listen(uint32_t dhcp, uint32_t local) {
	this->PullUpEthernet();
	this->Dhcp(dhcp, local, 0);
	do {
		unsigned char packet[MFP];
		int size = 0;
		while (!this->_disposed) {
			OVERLAPPED overlapped{ 0 };
#ifdef _TAP_ASYNC_LISTEN_PACKET
			overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
			if (!overlapped.hEvent) {
				if (!ReadFile(_tap, packet, MFP, (LPDWORD)&size, &overlapped))
					size = NULL;
			}
			else {
				if (!ReadFile(_tap, packet, MFP, (LPDWORD)&size, &overlapped)) {
					DWORD dwWait = WaitForSingleObject(overlapped.hEvent, 1000);
					if (dwWait == WAIT_TIMEOUT)
						size = 0;
					else if (dwWait != WAIT_OBJECT_0)
						size = ~0;
					else if (!GetOverlappedResult(_tap, &overlapped, (LPDWORD)&size, FALSE))
						size = ~0;
				}
				CloseHandle(overlapped.hEvent);
			}
#else
			if (!ReadFile(_tap, packet, MFP, (LPDWORD)&size, &overlapped))
				if (!GetOverlappedResult(_tap, &overlapped, (LPDWORD)&size, TRUE))
					size = ~0;
#endif
			if (size <= 0)
				continue;
			ip_hdr* iphdr = ip_hdr::Parse(packet, size);
			if (iphdr)
				this->OnInput(iphdr, size);
		}
	} while (false);
}

void Tap::Dhcp(uint32_t dhcp, uint32_t local, uint32_t dns) {
	std::shared_ptr<Tap::NetworkInterface>& interfaces = GetNetworkInterface();
	if (!interfaces.get())
		throw std::runtime_error("The call to the \"GetNetworkInterface\" member function returns an unexpected reference to the network interface");

    if (0 == dns)
        dns = inet_addr("8.8.8.8");

	char commands[1000];
	sprintf(commands, "netsh interface ip set dns %u static %s", interfaces->IfIndex, GetAddressText(dns).data());
	if (!Tap::System(commands))
		throw std::runtime_error("Unable to execute overwrite ethernet tap network device static dns configuration");

	int size = 0;
	// TAP_WIN_IOCTL_CONFIG_TUN
	{
		uint32_t address[3] = {
			local,
			dhcp,
			inet_addr("255.255.0.0"),
		};
		memset(2 + (unsigned char*)&address[1], 0, 2); /* address[1] = htonl(dhcp_masq_addr(dhcp, address[2], 0));*/
		if (!synchronized_deviceiocontrol(_tap, TAP_WIN_IOCTL_CONFIG_TUN, &address, sizeof(address), &address,
			sizeof(address), (LPDWORD)&size))
			throw std::runtime_error("Unable to configure default ethernet ip settings");
	}
	//// TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT
	//{
	//	uint32_t address[2] = {
	//		local,
	//		inet_addr("255.255.0.0"),
	//	};
	//	if (!synchronized_deviceiocontrol(_tap, TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT, &address, sizeof(address), &address,
	//		sizeof(address), (LPDWORD)&size))
	//		throw std::runtime_error("The TAP-Windows driver rejected a DeviceIoControl call to set Point-to-Point mode");
	//}
	// TAP_WIN_IOCTL_CONFIG_DHCP_MASQ
	{
		uint32_t address[4] = {
			local,
			inet_addr("255.255.0.0"),
			dhcp,
			86400, /* lease time in seconds */
		};
		if (!synchronized_deviceiocontrol(_tap, TAP_WIN_IOCTL_CONFIG_DHCP_MASQ, &address, sizeof(address), &address,
			sizeof(address), (LPDWORD)&size))
			throw std::runtime_error("The TAP-Windows driver rejected a DeviceIoControl call to set TAP_WIN_IOCTL_CONFIG_DHCP_MASQ mode");
	}
}

void Tap::Close() {
	if (!_disposed) {
		_disposed = true;
		if (_tap) {
			CloseHandle(_tap);
			_tap = NULL;
		}
		EventInput = NULL;
	}
}

bool Tap::Output(const std::shared_ptr<ip_hdr>& packet, int size, boost::asio::io_context* context) {
	if (NULL == packet || size <= 0 || NULL == this)
		return false;
	if (this->_disposed)
		return false;
	DWORD bytesToWrite = 0;
	if (context) {
		do {
            auto self = shared_from_this();
			bool success = false;
			auto overlapped = std::make_shared<OVERLAPPED>(OVERLAPPED{ 0 });
			overlapped->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
			auto afo = std::make_shared<boost::asio::windows::object_handle>(*context, overlapped->hEvent);
			do {
				MonitorScope scope(_outsyncobj);
                if (_asyncsending) {
                    auto& syncobj = self->_outsyncobj;
                    syncobj.Enter();
                    {
                        Tap::Packet pkg;
                        {
                            pkg.packet = packet;
                            pkg.size = size;
                            pkg.context = context;
                        }
                        success = true;
                        _sendsqueue.push_back(pkg);
                    }
                    syncobj.Exit();
                    break;
                }
                else {
                    success = WriteFile(_tap, packet.get(), size, &bytesToWrite, overlapped.get());
                    if (success) {
                        NextOutput();
                    }
                    else {
                        if (ERROR_IO_PENDING != GetLastError())
                            break;
                        _asyncsending = true;
                        try {
                            afo->async_wait([self, packet, afo](const boost::system::error_code& err) {
                                afo->close();
                                self->NextOutput();
                            });
                            success = true;
                        }
                        catch (std::exception&) {
                            _asyncsending = false;
                            break;
                        }
                    }
                }
			} while (0);
			if (!success)
				if (afo)
					afo->close();
			return success;
		} while (0);
	}
	else {
		bool success = false;
		OVERLAPPED overlapped{ 0 };
		overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
		do {
			MonitorScope scope(_outsyncobj);
			success = WriteFile(_tap, packet.get(), size, &bytesToWrite, &overlapped);
			if (!success) {
				if (ERROR_IO_PENDING != GetLastError())
					break;
				if (!overlapped.hEvent) {
					if (!GetOverlappedResult(_tap, &overlapped, &bytesToWrite, TRUE))
						break;
					success = true;
				}
				else {
					DWORD dw = WaitForSingleObject(overlapped.hEvent, INFINITE);
					if (dw != WAIT_OBJECT_0)
						break;
					if (!GetOverlappedResult(_tap, &overlapped, &bytesToWrite, FALSE))
						break;
					success = true;
				}
			}
		} while (0);
		if (overlapped.hEvent)
			CloseHandle(overlapped.hEvent);
		return success;
	}
}

std::shared_ptr<Tap::NetworkInterface>& Tap::GetNetworkInterface() {
	return this->_interfaces;
}

void Tap::Configure(const std::string& ip, const std::string& mask, const std::string& dns) {
	std::shared_ptr<Tap::NetworkInterface>& interfaces = GetNetworkInterface();
	if (!interfaces.get())
		throw std::runtime_error("The call to the \"GetNetworkInterface\" member function returns an unexpected reference to the network interface");

	char commands[1000];
	sprintf(commands, "netsh interface ip set address %u static %s %s", interfaces->IfIndex, ip.data(), mask.data());
	if (!Tap::System(commands))
		throw std::runtime_error("Unable to execute overwrite ethernet tap network device static ip configuration");

	sprintf(commands, "netsh interface ip set dns %u static %s", interfaces->IfIndex, dns.data());
	if (!Tap::System(commands))
		throw std::runtime_error("Unable to execute overwrite ethernet tap network device static dns configuration");
}

bool Tap::IsPullUpEthernet() {
	return 0 != _pullUp;
}

std::string Tap::GetDefaultComponentId() {
	std::set<std::string> s;
	if (GetAllComponentId(s) <= 0)
		return std::string();
	return *s.begin();
}

int Tap::GetAllNetworkInterfaces(std::map<std::string, Tap::NetworkInterface>& s) {
	int interfaces = 0;
	ULONG adapter_size = 0;
	auto adapter = std::make_unique<char[]>(sizeof(IP_ADAPTER_INFO));
	if (GetAdaptersInfo((PIP_ADAPTER_INFO)(adapter.get()), &adapter_size)) {
		adapter.reset();
		adapter = std::make_unique<char[]>(adapter_size);
	}
	if (GetAdaptersInfo((PIP_ADAPTER_INFO)(adapter.get()), &adapter_size))
		return interfaces;
	auto padapter = (PIP_ADAPTER_INFO)adapter.get();
	std::string any = "0.0.0.0";
	while (padapter) {
		if (*padapter->AdapterName == '\x0')
			continue;
		else {
			std::string adapterId = padapter->AdapterName;
			std::map<std::string, NetworkInterface>::iterator i = s.find(adapterId);
			if (i != s.end())
				continue;
			Tap::NetworkInterface& interfacex = s[adapterId];
			interfacex.Id = adapterId;
			interfacex.IfIndex = padapter->Index;
			interfacex.Name = padapter->Description;
			interfacex.Address = padapter->IpAddressList.IpAddress.String;
			interfacex.Mask = padapter->IpAddressList.IpMask.String;
			interfacex.IfType = padapter->Type;
			interfacex.GatewayServer = padapter->GatewayList.IpAddress.String;
			if (padapter->DhcpEnabled)
				interfacex.DhcpServer = padapter->DhcpServer.IpAddress.String;
			if (padapter->HaveWins) {
				interfacex.PrimaryWinsServer = padapter->PrimaryWinsServer.IpAddress.String;
				interfacex.SecondaryWinsServer = padapter->SecondaryWinsServer.IpAddress.String;
			}
			if (interfacex.Address.empty()) interfacex.Address = any;
			if (interfacex.Mask.empty()) interfacex.Mask = any;
			if (interfacex.GatewayServer.empty()) interfacex.GatewayServer = any;
			if (interfacex.DhcpServer.empty()) interfacex.DhcpServer = any;
			if (interfacex.PrimaryWinsServer.empty()) interfacex.PrimaryWinsServer = any;
			if (interfacex.SecondaryWinsServer.empty()) interfacex.SecondaryWinsServer = any;
			char sz[MAX_ADAPTER_ADDRESS_LENGTH * 3 + 1];
			for (unsigned int i = 0; i < padapter->AddressLength; i++) {
				if ((1 + i) >= padapter->AddressLength)
					sprintf(sz + (i * 3), "%02X", padapter->Address[i]);
				else
					sprintf(sz + (i * 3), "%02X-", padapter->Address[i]);
			}
			interfacex.MacAddress = sz;
			if (interfacex.MacAddress.empty()) interfacex.MacAddress = "00-00-00-00-00-00";
			interfaces++;
		}
		padapter = padapter->Next;
	}
	return interfaces;
}

int Tap::GetAllComponentId(std::set<std::string>& s) {
	int components = 0;
	HKEY hOwnerKey = NULL; // {4d36e972-e325-11ce-bfc1-08002be10318}：类别：NSIS网卡驱动
	char* szDevComponentId = NULL;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0,
		KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE/*KEY_ALL_ACCESS*/, &hOwnerKey) == ERROR_SUCCESS) {
		char szClassName[MAX_PATH];
		DWORD dwIndex = 0;
		while (szDevComponentId == NULL && RegEnumKeyA(hOwnerKey, dwIndex++, szClassName, MAX_PATH) == ERROR_SUCCESS) {
			BYTE data[MAX_PATH];
			DWORD dwRegType = REG_NONE;
			DWORD dwSize = sizeof(data);
			HKEY hSubKey = NULL;
			char szSubKeyPath[MAX_PATH];
			sprintf(szSubKeyPath, "%s\\%s", ADAPTER_KEY, szClassName);
			if (RegOpenKeyA(HKEY_LOCAL_MACHINE, szSubKeyPath, &hSubKey) != ERROR_SUCCESS) {
				continue;
			}
			if (RegQueryValueExA(hSubKey, "ComponentId", NULL, &dwRegType, data, &dwSize) == ERROR_SUCCESS && dwRegType == REG_SZ) {
				dwSize = sizeof(data);
				if (strncmp("tap", (char*)data, 3) == 0 && RegQueryValueExA(hSubKey, "NetCfgInstanceId", NULL,
					&dwRegType, data, &dwSize) == ERROR_SUCCESS && dwRegType == REG_SZ) {
					std::string componentid = dwSize ? std::string((char*)data, dwSize - 1) : "";
					if (s.insert(componentid).second) {
						components++;
					}
				}
			}
			RegCloseKey(hSubKey);
		}
		RegCloseKey(hOwnerKey);
	}
	return components;
}

std::shared_ptr<Tap::NetworkInterface> Tap::FindNetworkInterface(const std::string& componentId)
{
	if (componentId.empty())
		return NULL;
	std::map<std::string, Tap::NetworkInterface> interfaces;
	if (GetAllNetworkInterfaces(interfaces) <= 0)
		return NULL;
	return FindNetworkInterface(interfaces, componentId);
}

std::shared_ptr<Tap::NetworkInterface> Tap::FindNetworkInterface(std::map<std::string, Tap::NetworkInterface>& interfaces, const std::string& componentId)
{
	if (componentId.empty() || interfaces.empty())
		return NULL;
	auto i = interfaces.find(componentId);
	auto l = interfaces.end();
	auto e = [](decltype(i) i, decltype(componentId) componentId) {
		auto& interfaceid = i->first;
		if (strnicmp(componentId.data(), interfaceid.data(), componentId.size()) == 0) {
			auto ni = std::make_shared<Tap::NetworkInterface>();
			*ni = i->second;
			return ni;
		}
		return std::shared_ptr<Tap::NetworkInterface>();
	};
	if (i != l)
		return e(i, componentId);
	i = interfaces.begin();
	for (; i != l; ++i) {
		std::shared_ptr<Tap::NetworkInterface> ni = e(i, componentId);
		if (ni)
			return ni;
	}
	return NULL;
}

bool Tap::System(const char* commands)
{
	if (NULL == commands || *commands == '\x0')
		return FALSE;

	SECURITY_ATTRIBUTES   sa;
	HANDLE   hRead, hWrite;

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;
	if (!CreatePipe(&hRead, &hWrite, &sa, 0))
		return FALSE;

	STARTUPINFOA   si;
	PROCESS_INFORMATION   pi;
	si.cb = sizeof(STARTUPINFO);
	GetStartupInfoA(&si);
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	//关键步骤，CreateProcess函数参数意义请查阅MSDN     
	if (!CreateProcessA(NULL, (LPSTR)commands, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi))
		return FALSE;

	CloseHandle(hWrite);

	char   buffer[4096] = { 0 };
	DWORD   bytesRead;
	while (true) {
		memset(buffer, 0, strlen(buffer));
		if (ReadFile(hRead, buffer, 4095, &bytesRead, NULL) == NULL)
			break;
		//buffer中就是执行的结果，可以保存到文本，也可以直接输出     
		//printf(buffer);//这行注释掉就可以了     
		Sleep(100);
	}
	return TRUE;
}

std::shared_ptr<Tap::NetworkInterface> Tap::GetPreferredNetworkInterface() {
	std::map<std::string, Tap::NetworkInterface> interfaces;
	if (Tap::GetAllNetworkInterfaces(interfaces) <= 0)
		return NULL;

	char mac[32 + 1];
	int err = GetMacFromNetbios(mac);

	std::map<std::string, Tap::NetworkInterface>::iterator i = interfaces.begin();
	std::map<std::string, Tap::NetworkInterface>::iterator l = interfaces.end();
	for (; i != l; ++i) {
		auto& ni = i->second;
		if (ni.IfType == MIB_IF_TYPE_ETHERNET) {
			uint32_t address = inet_addr(ni.Address.data());
			if (address) {
				if (err == 0)
					if (ni.MacAddress != mac)
						continue;
				auto ro = std::make_shared<Tap::NetworkInterface>();
				*ro = ni;
				return ro;
			}
		}
	}
	return NULL;
}

std::string Tap::GetAddressText(uint32_t address) {
	unsigned char* p = (unsigned char*)&address;
	char sz[100];
	sprintf(sz, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return sz;
}

void Tap::OnInput(ip_hdr* packet, int size) {
	TapInputEventHandler events = this->EventInput;
	if (events) {
		events(this, packet, size);
	}
}

static uint32_t
dhcp_masq_addr(const uint32_t local, const uint32_t netmask, const int offset) {
	int dsa; /* DHCP server addr */

	if (offset < 0)
		dsa = (local | (~netmask)) + offset;
	else
		dsa = (local & netmask) + offset;

	if (dsa == local)
		printf("There is a clash between the --ifconfig local address and the internal DHCP server address"
			"-- both are set to %s -- please use the --ip-win32 dynamic option to choose a different free address from the"
			" --ifconfig subnet for the internal DHCP server\n", Tap::GetAddressText(dsa).data());

	if ((local & netmask) != (dsa & netmask))
		printf("--ip-win32 dynamic [offset] : offset is outside of --ifconfig subnet\n");

	return htonl(dsa);
}

void Tap::PullUpEthernet() {
	if (!_tap) {
		throw std::runtime_error("Ethernet tap character driven handle lost as if you have closed tap");
	}
	int size = 0;
	// TAP_WIN_IOCTL_SET_MEDIA_STATUS
	if (!_pullUp) {
		_pullUp = 1;
		if (!synchronized_deviceiocontrol(_tap, TAP_WIN_IOCTL_SET_MEDIA_STATUS, &_pullUp, 4, &_pullUp, 4, (LPDWORD)&size))
			throw std::runtime_error("Unable to pull up ethernet device for work");
	}
}

void Tap::NextOutput()
{
    Packet pkg;
    pkg.size = 0;
    do {
        auto& syncobj = _outsyncobj;
        syncobj.Enter();
        {
            _asyncsending = false;
            if (!_sendsqueue.empty()) {
                pkg = _sendsqueue.front();
                _sendsqueue.pop_front();
            }
        }
        syncobj.Exit();
    } while (0, 0);
    if (pkg.size) {
        Output(pkg.packet, pkg.size, pkg.context);
    }
}
