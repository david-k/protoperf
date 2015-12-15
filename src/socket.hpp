#pragma once

#include "common.hpp"
#include "socket_logger.hpp"

#include <memory>


//==================================================================================================
// Interface for a blocking socket.
class Socket
{
public:
	virtual ~Socket() {};

	// Makes the socket listen for incoming connections.
	virtual void listen() = 0;

	// Blocks until a connection with a client has been established. `listen()` must be called
	// first.
	virtual std::unique_ptr<Socket> accept() = 0;

	virtual void connect() = 0;

	// Returns the number of bytes written or zero if the connection has been closed.
	virtual size_t write(char const *src, size_t size) = 0;

	// Returns the number of bytes read or zero if the connection has been closed.
	virtual size_t read(char *dest, size_t size) = 0;

	virtual void print_options() {}
	virtual void print_statistics() {}
};


//==================================================================================================
void read_all(Socket *sock, char *data, size_t size)
{
	size_t total_read = 0;
	while(total_read < size)
	{
		size_t read_res = sock->read(data + total_read, size - total_read);
		if(read_res == 0)
			throw std::runtime_error{"read_all(): connection closed"};

		total_read += read_res;
	}
}

void write_all(Socket *sock, char const *data, size_t size)
{
	size_t total_written = 0;
	while(total_written < size)
	{
		size_t write_res = sock->write(data + total_written, size - total_written);
		if(write_res == 0)
			throw std::runtime_error{"write_all(): connection closed"};

		total_written += write_res;
	}
}

size_t read_discard(Socket *sock, int64_t num_bytes)
{
	int64_t const buffer_size = 8 * 1024;
	char buf[buffer_size];
	int64_t total_bytes_read = 0;

	while(total_bytes_read < num_bytes)
	{
		int bytes_read = sock->read(buf, std::min(buffer_size, num_bytes - total_bytes_read));
		if(bytes_read == 0)
			break;

		total_bytes_read += bytes_read;
	}

	return total_bytes_read;
}


//==================================================================================================
struct MessageHeader
{
	using ID = unsigned char;
	static size_t const length = sizeof(ID) + sizeof(uint64_t);

	constexpr explicit MessageHeader(ID id = 0) :
		id{id},
		payload_length{0} {}

	MessageHeader(ID id, size_t payload_length) :
		id{id},
		payload_length{payload_length} {}

	ID id;
	uint64_t payload_length;
};


void discard_message(Socket *sock, MessageHeader::ID id)
{
	MessageHeader msg;

	read_all(sock, (char*)&msg.id, sizeof(msg.id));
	if(msg.id != id)
		throw std::runtime_error{"Unexpected message id"};

	// TODO Convert to host byte order.
	read_all(sock, (char*)&msg.payload_length, sizeof(msg.payload_length));

	read_discard(sock, msg.payload_length);
}

void write_message(Socket *sock, MessageHeader const &msg)
{
	write_all(sock, (char const*)&msg.id, sizeof(msg.id));

	// TODO Convert to network byte order.
	write_all(sock, (char const*)&msg.payload_length, sizeof(msg.payload_length));
}
