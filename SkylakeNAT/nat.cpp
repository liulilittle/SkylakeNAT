#include <thread>
#include <iostream>
#include <functional>
#include <WinSock2.h>
#include <Windows.h>

#include "env.h"
#include "tap.h"
#include "nat.h"
#include "socket.h"
#include "nedmalloc/memory.h"

enum NATCommands
{
	NATCommands_kAuthentication,
	NATCommands_kEthernetInput,
	NATCommands_kEthernetOutput,
};

NAT::NAT(const std::shared_ptr<Tap::NetworkInterface>& interfaces, int id, std::string server, int port, int maxconcurrent, const std::string& key, int subtract)
	: enable_shared_from_this()
	, Id(id)
	, _disposed(false)
	, _server(server)
	, _port(port)
	, _maxconcurrent(maxconcurrent)
	, _availableconcurrent(0)
	, _work(_context)
	, _strand(_context)
	, _ticks(0)
	, _key(key)
	, _subtract(subtract)
{
	if (!interfaces)
		throw std::invalid_argument("Ethernet network interfaces are not allowed to be null references");
	if (maxconcurrent <= 0)
		maxconcurrent = 1;
	if (maxconcurrent > MAX_CONCURRENT)
		maxconcurrent = MAX_CONCURRENT;
	_tap = std::make_shared<Tap>(interfaces->Id);
	if (!_tap)
		throw std::runtime_error("Unable to build an instance of an ethernet tap character device");
	_currentsocket = _sockets.end();
}

void NAT::Listen() {
	auto self = shared_from_this();
	if (self->_disposed)
		throw std::runtime_error("The current state causes the operation to be invalid because the current object has been freed");
	int concurrents = min(4, GetProcessorCount());
	for (int i = 0; i < concurrents; i++) {
		std::thread([](std::shared_ptr<NAT> self) {
			self->_context.run();
		}, self).detach();
	}
	if (self->_tap)
		self->_tap->EventInput = [self](Tap* tap, ip_hdr* packet, int size) {
		self->PrivateIntput(packet, size);
	};
	std::thread([](std::shared_ptr<NAT> self) {
		int step = 0;
		while (!self->_disposed) {
			self->DoEvents();
			timeBeginPeriod(1);
			Sleep(1);
			timeEndPeriod(1);
		}
	}, self).detach();
	_tap->Listen(0, 0);
}

void NAT::Close() {
	auto self = shared_from_this();
	self->_syncobj.lock();
	{
		if (!self->_disposed) {

			self->_disposed = true;
			self->_context.stop();
			self->_tap->Close();
			self->_tap.reset();
			self->_sockets.clear();
			self->_currentsocket = self->_sockets.end();
		}
		_availableconcurrent = 0;
	}
	self->_syncobj.unlock();
}

void NAT::DoEvents() {
	auto self = shared_from_this();
	if (self->_disposed)
		return;
    long double ticks = (long double)GetTickCount(true);
#ifdef __USE_UDP_PAYLOAD_TAP_PACKET
    if (((ticks - self->_ticks) / 1000) >= 500) {
        self->_ticks = (unsigned long long)ticks;
        self->_syncobj.lock();
        {
            unsigned int* availableconcurrent = (unsigned int*)&self->_availableconcurrent;
            if (0 == InterlockedCompareExchange(availableconcurrent, 0, 0)) {
                CreateSocketChannel();
            }
        }
        self->_syncobj.unlock();
        self->OnOpen(self->NextAvailableChannel());
    }
#else
	if (((ticks - self->_ticks) / 1000) >= 10000) {
		self->_ticks = (unsigned long long)ticks;
		int concurrent = 0;
		self->_syncobj.lock();
		{
			unsigned int* availableconcurrent = (unsigned int*)&self->_availableconcurrent;
			concurrent = (int)InterlockedCompareExchange(availableconcurrent, 0, 0);
		}
		self->_syncobj.unlock();
        for (; concurrent < self->_maxconcurrent; concurrent++) {
            CreateSocketChannel();
        }
	}
#endif
}

void NAT::CreateSocketChannel() {
    auto self = shared_from_this();
    std::thread([](std::shared_ptr<NAT> self) {
        std::shared_ptr<Socket> socket = std::make_shared<Socket>(
            self->_context,
            self->Id,
            self->_server,
            self->_port,
            self->_key,
            self->_subtract);
        socket->AbortEvent = [self](const std::shared_ptr<Socket>& sender) {
            if (sender) {
                sender->Close();
                self->_syncobj.lock();
                {
                    auto availableconcurrent = (unsigned int*)&self->_availableconcurrent;
                    if (InterlockedCompareExchange(availableconcurrent, 0, 0) > 0) {
                        if (0 == InterlockedDecrement((unsigned int*)&self->_availableconcurrent))
                            self->OnAbort();
                    }
                    auto i = self->_sockets.find(sender.get());
                    if (i != self->_sockets.end()) {
                        if (i == self->_currentsocket)
                            ++self->_currentsocket;
                        self->_sockets.erase(i);
                    }
                }
                self->_syncobj.unlock();
            }
        };
        socket->MessageEvent = [self](const std::shared_ptr<Socket>& sender,
            unsigned short commands,
            std::shared_ptr<unsigned char>& message, int message_size) {
            self->OnMessage(commands, message, message_size);
        };
        if (!socket->TryOpen(5000)) {
            socket->Close();
            socket.reset();
        }
        else {
            self->_syncobj.lock();
            {
                Socket* key = NULL;
                if (self->_currentsocket != self->_sockets.end())
                    key = self->_currentsocket->first;
                self->_sockets[socket.get()] = socket;
                if (!key)
                    self->_currentsocket = self->_sockets.end();
                else
                    self->_currentsocket = self->_sockets.find(key);
                InterlockedIncrement((unsigned int*)&self->_availableconcurrent);
            }
            self->_syncobj.unlock();
            self->OnOpen(socket);
            while (1) {
                int size = 0;
                unsigned short commands = 0;
                auto packet = socket->ReadPacket(commands, size);
                if (size < 0)
                    break;
                self->OnMessage(commands, packet, size);
            }
        }
    }, self).detach();
}

void NAT::OnOpen(const std::shared_ptr<Socket>& socket) {
    if (!socket.get())
        return;
	socket->Send(NATCommands_kAuthentication, NULL, 0);
}

void NAT::OnMessage(unsigned short commands, std::shared_ptr<unsigned char>& message, int message_size) {
	if (_disposed)
		return;
	if (commands == NATCommands_kEthernetInput) {
		ip_hdr* packet = ip_hdr::Parse(message.get(), message_size);
		if (packet) {
			auto frame = std::shared_ptr<ip_hdr>((ip_hdr*)Memory::Alloc(message_size), [](ip_hdr* p) {
				if (p)
					Memory::Free(p);
			});
			if (frame) {
				memcpy(frame.get(), packet, message_size);
				PublicInput(frame, message_size);
			}
		}
	}
    else if (commands == NATCommands_kAuthentication) {
        NATAuthenticationResponse* response = (NATAuthenticationResponse*)message.get();
        if (response && message_size >= sizeof(NATAuthenticationResponse)) {
            PrintTraceToScreen("DHCP local[%s] dns[%s] from dhcp[%s]",
                GetAddressText(response->dhcp.local).data(),
                GetAddressText(response->dhcp.dns).data(),
                GetAddressText(response->dhcp.dhcp).data());
            if (0 != memcmp(response, &_dhcp, sizeof(_dhcp))) {
                memcpy(&_dhcp, response, sizeof(_dhcp));
                _tap->Dhcp(response->dhcp.dhcp, response->dhcp.local, response->dhcp.dns);
            }
        }
    }
}

void NAT::OnAbort() {

}

bool NAT::PublicInput(const std::shared_ptr<ip_hdr>& packet, int size) {
	bool success = false;
	if (!packet.get() || size <= 0)
		return success;
	do {
#ifdef _NOT_USE_ASIO_WRITE_TAP_PACKET
		success = _tap->Output(packet, size, NULL);
#else
		success = _tap->Output(packet, size, &_context);
#endif
	} while (0);
	PrintTraceEthernetInput(packet, 1, success);
	return success;
}

bool NAT::PrivateIntput(ip_hdr* packet, int size) {
	bool success = false;
	if (!packet || size <= 0)
		return success;
	int available_concurrent = (int)InterlockedCompareExchange((unsigned int*)&_availableconcurrent, 0, 0);
	for (int i = 0; i < available_concurrent; i++) {
		std::shared_ptr<Socket> socket = NextAvailableChannel();
		if (!socket)
			continue;
		auto message_data = std::shared_ptr<unsigned char>((unsigned char*)Memory::Alloc(size), [](unsigned char* p) {
			if (p)
				Memory::Free(p);
		});
		if (!message_data)
			break;
		memcpy(message_data.get(), packet, size);
		try {
			socket->Send(NATCommands_kEthernetOutput, message_data, size);
			success |= true;
		}
		catch (std::exception&) {
			socket->Close();
		}
	}
	PrintTraceEthernetInput(packet, 0, success);
	return success;
}

std::shared_ptr<Socket> NAT::NextAvailableChannel() {
	std::shared_ptr<Socket> socket = NULL;
	_syncobj.lock();
	do
	{
		int available_concurrent = (int)InterlockedCompareExchange((unsigned int*)&_availableconcurrent, 0, 0);
		if (available_concurrent <= 0 || _sockets.empty()) {
			_currentsocket = _sockets.end();
			break;
		}

		if (_currentsocket != _sockets.end())
			_currentsocket = ++_currentsocket;

		if (_currentsocket == _sockets.end())
			_currentsocket = _sockets.begin();

		if (_currentsocket != _sockets.end())
			socket = _currentsocket->second;
	} while (0);
	_syncobj.unlock();
	return socket;
}