#include <stdio.h>
#include <assert.h>
#include <winsock2.h>

#include "env.h"
#include "rc4.h"
#include "tap.h"
#include "socket.h"
#include "nedmalloc/memory.h"

Socket::Socket(boost::asio::io_context& context, int id, const std::string& server, int port, const std::string& key, int subtract)
	: Id(id)
	, _context(context)
	, _server(server)
	, _port(port)
	, _socket(context)
	, _resolver(context)
	, _strand(context)
	, _fhdr(false)
	, _fseek(0)
	, _key(key)
	, _subtract(subtract) {
	if (port <= 0 && port > 65535)
		throw std::out_of_range("The port used to connect to the server is less than or equal to 0 or greater than 65535");
	_phdr = std::shared_ptr<unsigned char>((unsigned char*)Memory::Alloc(sizeof(pkg_hdr)), [](unsigned char* p) {
		if (p)
			Memory::Free(p);
	});
#if !defined(_USE_RC4_SIMPLE_ENCIPHER)
	_encryptor = std::make_shared<Encryptor>(ENCRYPTOR_AES_256_CFB, key + ToString(subtract));
#endif
}

Socket::~Socket() {
    this->Close();
}

void Socket::Close() {
	boost::system::error_code ec;
	try {
		_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
	}
	catch (std::exception&) {
	}
	_socket.close();
	_phdr.reset();
	_messsage.reset();
	if (AbortEvent)
		AbortEvent = NULL;
	if (MessageEvent)
		MessageEvent = NULL;
#if !defined(_USE_RC4_SIMPLE_ENCIPHER)
	if (_encryptor)
		_encryptor = NULL;
#endif
}

void Socket::ReceiveAsync(const std::shared_ptr<unsigned char>& buffer, int offset, size_t len, const ReceiveCompletionRoutine& callback) {
	if (len && !buffer)
		throw std::invalid_argument("The buffer parameter is empty but specifies that its length is greater than zero");
	std::shared_ptr<Socket> self = shared_from_this();
	unsigned char* position = (offset + buffer.get());
	auto output_data = boost::asio::buffer(position, len);
	try {
		_socket.async_receive(output_data,
			_strand.wrap([self, callback](const boost::system::error_code& ec, std::size_t size) {
			if (callback)
				callback(self, ec, size);
			if (ec.failed() || 0 == size)
				self->OnAbort();
		}));
	}
	catch (std::exception&) {
		self->OnAbort();
	}
}

void Socket::SendAsync(const std::shared_ptr<unsigned char>& buffer, int offset, size_t len, const SendCompletionRoutine& callback) {
    if (len && !buffer)
        throw std::invalid_argument("The buffer parameter is empty but specifies that its length is greater than zero");
    std::shared_ptr<Socket> self = shared_from_this();
	std::shared_ptr<unsigned char> packet = buffer;
	auto output_data = boost::asio::buffer(buffer.get(), len);
	try {
		_socket.async_send(output_data, _strand.wrap([self, callback, packet](const boost::system::error_code& ec, std::size_t size) {
			if (callback)
				callback(self, ec, size);
			if (ec.failed())
				self->OnAbort();
		}));
	}
	catch (std::exception&) {
		self->OnAbort();
	}
}

void Socket::ReadPacketAsync() {
    try {
        if (!_fhdr)
            ReceiveAsync(_phdr, 0, sizeof(pkg_hdr), &Socket::ReceiveFrameLoopCompletion);
		else {
			pkg_hdr* pkg = (pkg_hdr*)_phdr.get();
			int surplus = (pkg->len - _fseek);
			if (surplus > Tap::MSS) {
				surplus = Tap::MSS;
			}
			assert(surplus > 0);
			ReceiveAsync(_messsage, _fseek, surplus, &Socket::ReceiveFrameLoopCompletion);
		}
    }
    catch (std::exception&) {
        this->Close();
    }
}

void Socket::OnAbort() {
    AbortEventHandler events = this->AbortEvent;
    if (events)
        events(shared_from_this());
}

void Socket::OnMessage(unsigned short commands, std::shared_ptr<unsigned char>& message, int message_size) {
    MessageEventHandler events = this->MessageEvent;
    if (events)
        events(shared_from_this(), commands, message, message_size);
}

void Socket::ReceiveFrameLoopCompletion(const std::shared_ptr<Socket>& sender, const boost::system::error_code& ec, std::size_t size) {
    bool aborting = true;
    do {
        if (ec.failed() || 0 == size) {
            break;
        }
        pkg_hdr* pkghdr = (pkg_hdr*)sender->_phdr.get();
        bool completion = false;
        if (!sender->_fhdr) {
            if (!pkghdr || size != sizeof(pkg_hdr) || pkghdr->fk != pkg_hdr::FK) {
                break;
            }
            if (!pkghdr->len)
                completion = true;
            else {
                sender->_fseek = 0;
                sender->_fhdr = true;
                sender->_messsage = std::shared_ptr<unsigned char>((unsigned char*)Memory::Alloc(pkghdr->len), [](unsigned char* p) {
                    if (p)
                        Memory::Free(p);
                });
            }
            aborting = false;
        }
        else {
            sender->_fseek += size;
            if (sender->_fseek >= pkghdr->len)
                completion = true;
            aborting = false;
        }
        if (completion) {
            aborting = false;
			int message_size = pkghdr->len;
			if (sender->_messsage.get() && message_size > 0) {
#if !defined(_USE_RC4_SIMPLE_ENCIPHER)
				int outlen = 0;
				sender->_messsage = sender->_encryptor->Decrypt(sender->_messsage.get(), message_size, outlen);
				if (outlen < 0) {
					aborting = true;
					break;
				}
				message_size = outlen;
#else
				rc4_crypt((unsigned char*)sender->_key.data(),
					sender->_key.length(),
					sender->_messsage.get(),
					message_size,
					sender->_subtract, 0);
#endif
			}
            sender->OnMessage(pkghdr->cmd, sender->_messsage, message_size);
            sender->_fseek = 0;
            sender->_fhdr = false;
            sender->_messsage.reset();
        }
    } while (0);
    if (aborting) {
        sender->OnAbort();
    }
    else {
        sender->ReadPacketAsync();
    }
}

bool Socket::Available() {
    if (!_socket.is_open())
        return false;
    int ndfs = _socket.native_handle();

    struct fd_set fd;
    FD_ZERO(&fd);
    FD_SET(ndfs, &fd);

    struct timeval tv { 0 };
    if (0 >= select(0, NULL, &fd, NULL, &tv) || !FD_ISSET(_socket.native_handle(), &fd))
        return false;
    return true;
}

void Socket::Open(int milliseconds) {
	boost::asio::ip::tcp::resolver::query q(_server, std::to_string(_port).c_str());
	auto results = _resolver.resolve(q);
	if (results.empty())
		throw std::exception("Unable to resolve and such a this server host");
	boost::system::error_code ec;
	_socket.open(boost::asio::ip::tcp::v4());
	_socket.non_blocking(true);
	_socket.connect(*results.begin(), ec);
	if (ec.failed()) {
		int err = WSAGetLastError();
		if (err != WSA_IO_PENDING) {
			this->Close();
			boost::asio::detail::throw_error(ec, "connect");
		}
	}
	struct fd_set fd;
	FD_ZERO(&fd);
	FD_SET(_socket.native_handle(), &fd);

	struct timeval tv { 0 };
	tv.tv_sec = milliseconds / 1000;
	tv.tv_usec = milliseconds % 1000;
	if (select(_socket.native_handle() + 1, NULL, &fd, NULL, NULL) <= 0 || !FD_ISSET(_socket.native_handle(), &fd)) {
		this->Close();
		throw std::exception("Unable to establish a valid connect with the target host");
	}

	_socket.non_blocking(false);
	_socket.set_option(boost::asio::ip::tcp::no_delay(true));
	_socket.set_option(boost::asio::socket_base::send_buffer_size(524288));
	_socket.set_option(boost::asio::socket_base::receive_buffer_size(524288));
}

void Socket::Send(unsigned short commands, const std::shared_ptr<unsigned char>& buffer, int offset, size_t len) {
	if (len && !buffer)
		throw std::invalid_argument("The buffer parameter is empty but specifies that its length is greater than zero");
	int payload_size = (int)len;
	std::shared_ptr<unsigned char> payload_segment = buffer;
#if !defined(_USE_RC4_SIMPLE_ENCIPHER)
	if (payload_size > 0) {
		int outlen = 0;
		payload_segment = _encryptor->Encrypt(buffer.get() + offset, payload_size, outlen);
		offset = 0;
		payload_size = outlen;
	}
#endif
	int packet_size = (payload_size + sizeof(pkg_hdr));
	unsigned char* frame = (unsigned char*)Memory::Alloc(packet_size);
	std::shared_ptr<unsigned char> packet = std::shared_ptr<unsigned char>(frame, [](unsigned char* p) {
		if (p) {
			Memory::Free(p);
		}
	});
	pkg_hdr* pkg = (pkg_hdr*)packet.get();
	pkg->cmd = (unsigned char)commands;
	pkg->fk = pkg_hdr::FK;
	pkg->len = (unsigned short)payload_size;
	pkg->id = this->Id;
	if (payload_size) {
		unsigned char* sources = (offset + payload_segment.get());
		unsigned char* payload = sizeof(pkg_hdr) + packet.get();
		memcpy(payload, sources, pkg->len);
	}
	return UnsafeTransmit(packet, 0, packet_size);
}

void Socket::UnsafeTransmit(const std::shared_ptr<unsigned char>& buffer, int offset, size_t len) {
    if (len && !buffer)
        throw std::invalid_argument("The buffer parameter is empty but specifies that its length is greater than zero");
#if defined(_USE_RC4_SIMPLE_ENCIPHER)
	if (buffer.get() && len > sizeof(pkg_hdr)) {
		unsigned char* packet = (offset + buffer.get());
		unsigned char* payload = packet + sizeof(pkg_hdr);
		rc4_crypt((unsigned char*)_key.data(), _key.length(), payload, (int)(len - sizeof(pkg_hdr)), _subtract, 1);
	}
#endif
    SendAsync(buffer, offset, len, NULL);
}

std::shared_ptr<unsigned char> Socket::ReadPacket(unsigned short& commands, int& size) {
	size = ~0;
	commands = ~0;
	if (!_phdr.get())
		return NULL;
	if (!ReadPacketStream(_phdr, 0, sizeof(pkg_hdr)))
		return NULL;
	pkg_hdr* pkg = (pkg_hdr*)_phdr.get();
	if (pkg->FK != pkg_hdr::FK)
		return NULL;
	std::shared_ptr<unsigned char> payload = NULL;
	int payload_size = pkg->len;
	if (payload_size > 0) {
		payload = std::shared_ptr<unsigned char>((unsigned char*)Memory::Alloc(payload_size), [](unsigned char* p) {
			if (p)
				Memory::Free(p);
		});
		if (!ReadPacketStream(payload, 0, payload_size))
			return NULL;
#if defined(_USE_RC4_SIMPLE_ENCIPHER)
		rc4_crypt((unsigned char*)_key.data(), _key.length(), payload.get(), payload_size, _subtract, 0);
#else
		int outlen = 0;
		payload = _encryptor->Decrypt(payload.get(), payload_size, outlen);
		if (outlen < 0) {
			OnAbort();
			return NULL;
		}
		payload_size = outlen;
#endif
	}
	size = payload_size;
	commands = pkg->cmd;
	return payload;
}

bool Socket::ReadPacketStream(std::shared_ptr<unsigned char>& buffer, int offset, size_t len) {
	if (!buffer.get() || offset < 0 || len < 0)
		return false;
	size_t bytes = 0;
	unsigned char* packet = buffer.get() + offset;
	try {
		while (len > bytes) {
			int sz = recv(_socket.native_handle(), (char*)packet, len, 0);
			if (sz <= 0) {
				OnAbort();
				return false;
			}
			bytes += (int)sz;
		}
		return true;
	}
	catch (std::exception&) {
		return false;
	}
}

bool Socket::TryOpen(int marcoseconds) {
    try {
        this->Open(marcoseconds);
        return this->Available();
    }
	catch (std::exception&) {
		PrintTraceToScreen("%s [%s:%d]", "Unable to open the connect to the server", _server.c_str(), _port);
	}
    return false;
}
