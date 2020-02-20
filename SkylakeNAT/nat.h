#pragma once

#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "env.h"
#include "tap.h"
#include "socket.h"

#include <map>
#include <mutex>
#include <shared_mutex>

class NAT : public std::enable_shared_from_this<NAT>
{
public:
	NAT(const std::shared_ptr<Tap::NetworkInterface>& interfaces, int id, std::string server, int port, int maxconcurrent, const std::string& key, int subtract);

public:
	virtual void											Listen();
	virtual void											Close();

protected:
	virtual void											DoEvents();
	virtual void											OnOpen(const std::shared_ptr<Socket>& socket);
	virtual void											OnMessage(unsigned short commands, std::shared_ptr<unsigned char>& message, int message_size);
	virtual void											OnAbort();

protected:
	virtual bool											PublicInput(const std::shared_ptr<ip_hdr>& packet, int size);
	virtual bool											PrivateIntput(ip_hdr* packet, int size);
	virtual std::shared_ptr<Socket>							NextAvailableChannel();
    virtual void                                            CreateSocketChannel();

public:
	const int												Id;
	static const int										MAX_CONCURRENT = 32;

private:
	std::shared_ptr<Tap>									_tap;
	bool													_disposed;
	std::string												_server;
	int														_port;
	int														_maxconcurrent;
	int														_availableconcurrent;
	boost::asio::io_context									_context;
	boost::asio::io_context::work							_work;
	boost::asio::io_service::strand							_strand;
	unsigned long long										_ticks;
	std::map<Socket*, std::shared_ptr<Socket>>				_sockets;
	std::map<Socket*, std::shared_ptr<Socket>>::iterator	_currentsocket;
	std::recursive_mutex									_syncobj;
    std::string                                             _key;
    int                                                     _subtract;
#pragma pack(push, 1)
    struct NATAuthenticationResponse
    {
    public:
        struct Dhcp
        {
        public:
            uint32_t						local;
            uint32_t						dhcp;
            uint32_t						dns;
        } dhcp;
    public:
        inline NATAuthenticationResponse() {
            memset(this, 0, sizeof(*this));
        }
    };
#pragma pack(pop)
    NATAuthenticationResponse                               _dhcp;
};