#pragma once

#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "env.h"
#if !defined(_USE_RC4_SIMPLE_ENCIPHER) || defined(__USE_UDP_PAYLOAD_TAP_PACKET)
#include "encryptor.h"
#endif

class Socket : public std::enable_shared_from_this<Socket>
{
public:
#pragma pack(push, 1)
	struct pkg_hdr
	{
	public:
		unsigned char	fk;
		unsigned char	cmd;
		unsigned short	len;
		unsigned int	id;

	public:
		static const int FK = 0x2A;
	};
#pragma pack(pop)

public:
	typedef std::function<void(const std::shared_ptr<Socket>& sender, const boost::system::error_code& ec, std::size_t size)>
																				ReceiveCompletionRoutine;
	typedef ReceiveCompletionRoutine											SendCompletionRoutine;
	typedef std::function<void(const std::shared_ptr<Socket>& sender, unsigned short commands, std::shared_ptr<unsigned char>& message, int message_size)>
																				MessageEventHandler;
	typedef std::function<void(const std::shared_ptr<Socket>& sender)>			AbortEventHandler;

public:
	Socket(boost::asio::io_context& context, int id, const std::string& server, int port, const std::string& key, int subtract);
	virtual ~Socket();

public:
	const int																	Id;
	MessageEventHandler															MessageEvent;
	AbortEventHandler															AbortEvent;

public:
	virtual bool																Available();
	bool																		TryOpen(int milliseconds);
	virtual void																Open(int milliseconds);
	virtual void																Close();
	inline void																	Send(unsigned short commands, const std::shared_ptr<unsigned char>& buffer, size_t len)
	{
		return this->Send(commands, buffer, 0, len);
	};
	virtual void																Send(unsigned short commands, const std::shared_ptr<unsigned char>& buffer, int offset, size_t len);
	virtual void																UnsafeTransmit(const std::shared_ptr<unsigned char>& packet, int packet_offset, size_t packet_size);
	virtual std::shared_ptr<unsigned char> 										ReadPacket(unsigned short& commands, int& size);
	virtual void																ReadPacketAsync();

protected:
	virtual void																ReceiveAsync(const std::shared_ptr<unsigned char>& buffer, int offset, size_t len, const ReceiveCompletionRoutine& callback);
	virtual void																SendAsync(const std::shared_ptr<unsigned char>& buffer, int offset, size_t len, const SendCompletionRoutine& callback);

protected:
	virtual void																OnAbort();
	virtual void																OnMessage(unsigned short commands, std::shared_ptr<unsigned char>& message, int message_size);

private:
	bool																		ReadPacketStream(std::shared_ptr<unsigned char>& buffer, int offset, size_t len);
	static void																	ReceiveFrameLoopCompletion(const std::shared_ptr<Socket>& sender, const boost::system::error_code& ec, std::size_t size);

private:
	boost::asio::io_context&													_context;
	std::string																	_server;
	int																			_port;
#ifdef __USE_UDP_PAYLOAD_TAP_PACKET
	int																			_fd;
	unsigned int																_address;
#else
	boost::asio::ip::tcp::socket												_socket;
	boost::asio::ip::tcp::resolver												_resolver;
	boost::asio::io_service::strand												_strand;
	bool																		_fhdr;
	std::shared_ptr<unsigned char>												_phdr;
	std::shared_ptr<unsigned char>												_messsage;
	int																			_fseek;
#endif
    std::string                                                                 _key;
    int                                                                         _subtract;
#if !defined(_USE_RC4_SIMPLE_ENCIPHER) || defined(__USE_UDP_PAYLOAD_TAP_PACKET)
	std::shared_ptr<Encryptor>													_encryptor;
#endif
};