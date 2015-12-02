#include "common.hpp"

#include <iostream>
#include <memory>
#include <chrono>

#include <udt/udt.h>

#include <unistd.h>


//==================================================================================================
class Socket
{
public:
	virtual ~Socket() {};

	virtual void listen() = 0;
	virtual std::unique_ptr<Socket> accept() = 0;
	virtual void connect() = 0;
	virtual size_t write(char const *src, size_t size) = 0;
	virtual size_t read(char *dest, size_t size) = 0;
};


class TCPSocket : public Socket
{
public:
	explicit TCPSocket(Address const &addr) :
		m_addr{addr},
		m_socket{::socket(m_addr.family(), m_addr.type(), 0)}
	{
		if(m_socket == -1)
			throw std::runtime_error{"socket(): " + errno_string(errno)};
	}

	TCPSocket(Address const &addr, int socket) :
		m_addr{addr},
		m_socket{socket} {}

	virtual ~TCPSocket()
	{
		::close(m_socket);
	}

	virtual void listen()
	{
		if(::bind(m_socket, m_addr.native_address(), m_addr.native_size()) == -1)
			throw std::runtime_error{"bind(): " + errno_string(errno)};

		if(::listen(m_socket, 10) == -1)
			throw std::runtime_error{"listen(): " + errno_string(errno)};
	}

	virtual std::unique_ptr<Socket> accept()
	{
		while(true)
		{
			::sockaddr_storage client_addr;
			socklen_t addr_size;
			int client_sock = ::accept(m_socket, (::sockaddr*)&client_addr, &addr_size);

			if(client_sock == -1)
			{
				if(errno != EAGAIN && errno != EWOULDBLOCK && errno != ECONNABORTED)
					throw std::runtime_error{"server::accept(): accept()" + errno_string(errno)};
			}
			else
			{
				Address addr{m_addr.type(), "", (::sockaddr*)&client_addr, addr_size};
				return std::make_unique<TCPSocket>(addr, client_sock);
			}
		}
	}

	virtual void connect()
	{
        if(::connect(m_socket, m_addr.native_address(), m_addr.native_size()) == -1)
        {
            // If no connection could be established immediatly, connect() returns but the connection
            // process is continued asyncronously.
            if(errno != EINPROGRESS)
                throw std::runtime_error{"connect: connect failed: " + errno_string(errno)};
        }
	}

	virtual size_t write(char const *src, size_t size)
	{
		while(true)
		{
			auto send_res = ::send(m_socket, src, size, MSG_NOSIGNAL);
			if(send_res == -1)
			{
				if(errno == EPIPE || errno == ECONNRESET)
				{
					// Connection has been closed
					return 0;
				}
				else if(errno != EINTR)
					throw std::runtime_error{"write_non_blocking: send failed: " + errno_string(errno)};
			}
			else
				return send_res;
		}
	}

	virtual size_t read(char *dest, size_t size)
	{
		while(true)
		{
			auto recv_res = ::recv(m_socket, dest, size, 0);
			if(recv_res == -1)
			{
				if(errno != EINTR)
					throw std::runtime_error{"recv(): " + errno_string(errno)};
			}
			else
			{
				// If recv_res == 0 the connection has been closed
				return recv_res;
			}
		}
	}

private:
	Address m_addr;
	int m_socket;
};


//==================================================================================================
struct Invocation
{
	enum class Mode
	{
		client,
		server
	};

	enum class Protocol
	{
		tcp,
		udt
	};

	Mode mode;
	Protocol protocol;
	std::string port;

	// Client
	std::string host;
};

std::string to_string(Invocation::Protocol p)
{
	switch(p)
	{
		case Invocation::Protocol::tcp: return "TCP";
		case Invocation::Protocol::udt: return "UDT";
		default: return "<unknown>";
	};
}

Invocation parse_args(int argc, char *argv[])
{
	bool mode_specified = false;
	Invocation invoc;
	invoc.protocol = Invocation::Protocol::tcp;
	invoc.port = "9001";

	for(int i = 1; i < argc; ++i)
	{
		if(!std::strcmp(argv[i], "-s"))
		{
			invoc.mode = Invocation::Mode::server;
			mode_specified = true;
		}
		else if(!std::strcmp(argv[i], "-c"))
		{
			invoc.mode = Invocation::Mode::client;
			mode_specified = true;

			if(++i == argc)
				throw std::runtime_error{"You must specify a host the client can connect to"};

			invoc.host = argv[i];
		}
	}

	if(!mode_specified)
		throw std::runtime_error{"You must specify either -s or -c to run a server or client"};

	return invoc;
}


//==================================================================================================
std::unique_ptr<Socket> make_benchmark_socket(Invocation::Protocol protocol, Address const &addr)
{
	switch(protocol)
	{
		case Invocation::Protocol::tcp: return std::make_unique<TCPSocket>(addr);
		default:
			throw std::runtime_error{"Unsupported protocol: " + to_string(protocol)};
	};
}


void write_all(Socket *sock, char const *data, size_t size)
{
	while(size)
	{
		size_t write_res = sock->write(data, size);
		if(write_res == 0)
			throw std::runtime_error{"write_all(): connection closed"};

		size -= write_res;
	}
}


int main(int argc, char *argv[])
{
	auto invoc = parse_args(argc, argv);

	if(invoc.mode == Invocation::Mode::server)
	{
		auto addrs = local_addresses(invoc.port.c_str(), SOCK_STREAM, AF_INET);
		if(addrs.empty())
			throw std::runtime_error{"No addresses found"};

		std::cout << addrs[0] << std::endl;
		auto socket = make_benchmark_socket(invoc.protocol, addrs[0]);
		socket->listen();

		std::vector<char> buffer(10 * 1024 * 1024);
		while(true)
		{
			auto client = socket->accept();
			std::cout << "Client accepted. " << std::flush;

			size_t bytes_read = 0;
			size_t read_res = 0;

			auto start_time = std::chrono::high_resolution_clock::now();
			while((read_res = client->read(buffer.data(), buffer.size())))
				bytes_read += read_res;

			auto end_time = std::chrono::high_resolution_clock::now();
			std::chrono::duration<double> elapsed = end_time - start_time;

			double mbits = (bytes_read * 8) / 1000000.0;
			double mbps = mbits / elapsed.count();

			std::cout << "Bytes read: " << bytes_read
			          << " in " << elapsed.count() << " s"
			          << " (" << mbps << " Mbits/sec)" << std::endl;
		}
	}
	else
	{
		auto addrs = remote_addresses(invoc.host.c_str(), invoc.port.c_str(), SOCK_STREAM, AF_INET);
		if(addrs.empty())
			throw std::runtime_error{"No addresses found"};

		std::cout << addrs[0] << std::endl;
		auto socket = make_benchmark_socket(invoc.protocol, addrs[0]);

		socket->connect();

		size_t bytes_written = 0;
		std::vector<char> buffer(1000 * 1024 * 1024);

		for(int i = 0; i < 50; ++i)
		{
			write_all(socket.get(), buffer.data(), buffer.size());
			bytes_written += buffer.size();
		}


		std::cout << "Bytes written: " << bytes_written << std::endl;
	}
		
}
