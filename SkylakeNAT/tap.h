#pragma once

#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include <stdio.h>
#include <stdint.h>
#include <string>
#include <functional>
#include <set>
#include <map>
#include <list>
#include <boost/asio.hpp>

#include "ip.h"
#include "env.h"
#include "monitor.h"

class Tap : public std::enable_shared_from_this<Tap>
{
public:
	class NetworkInterface
	{
	public:
		std::string																		Id;
		std::string																		Name;
		std::string																		Address;
		std::string																		Mask;
		std::string																		GatewayServer;
		std::string																		DhcpServer;
		std::string																		PrimaryWinsServer;
		std::string																		SecondaryWinsServer;
		std::string																		MacAddress;
		uint32_t																		IfIndex;
		uint32_t																		IfType; // MIB_IF_TYPE
	};
	typedef std::function<void(Tap* tap, ip_hdr* packet, int size)>	TapInputEventHandler;

public:
	Tap(std::string componentId);
	virtual ~Tap();

public:
	virtual void																		Listen(uint32_t dhcp, uint32_t local);
	virtual void																		Dhcp(uint32_t dhcp, uint32_t local, uint32_t dns);
	virtual void																		Close();
	virtual bool																		Output(const std::shared_ptr<ip_hdr>& packet, int size, boost::asio::io_context* context);
	virtual std::shared_ptr<NetworkInterface>&											GetNetworkInterface();
	virtual void																		Configure(const std::string& ip, const std::string& mask, const std::string& dns);
	virtual bool																		IsPullUpEthernet();
    virtual void																		PullUpEthernet();

public:
	static std::string																	GetDefaultComponentId();
	static int																			GetAllNetworkInterfaces(std::map<std::string, NetworkInterface>& s);
	static int																			GetAllComponentId(std::set<std::string>& s);
	static std::shared_ptr<NetworkInterface>											FindNetworkInterface(const std::string& componentId);
	static std::shared_ptr<NetworkInterface>											FindNetworkInterface(std::map<std::string, Tap::NetworkInterface>& interfaces, const std::string& componentId);
	static bool																			System(const char* commands);
	static std::shared_ptr<NetworkInterface>											GetPreferredNetworkInterface();
	static std::string																	GetAddressText(uint32_t address);

protected:
	virtual void																		OnInput(ip_hdr* packet, int size);

private:
    void                                                                                NextOutput();

public:
	TapInputEventHandler																EventInput;

public:
	static const int MTU																= 1500;
	static const int MSS																= 1400;
    static const int MIP                                                                = 1486;
	static const int MFP																= 65535;

private:
	bool																				_disposed;
	void*																				_tap;
	std::shared_ptr<NetworkInterface>													_interfaces;
	int																					_pullUp;
	Monitor																				_outsyncobj;
    bool                                                                                _sendingoutput;
    struct Packet
    {
        std::shared_ptr<ip_hdr>                                                         packet;
        int                                                                             size;
        boost::asio::io_context*                                                        context;
    };
    std::list<Packet>                                                                   _sendsqueues;
};