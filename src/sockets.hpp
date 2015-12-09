#pragma once

#include "common.hpp"

#include <udt/udt.h>
#include <udt/ccc.h>

#include <memory>
#include <iostream>
#include <unistd.h>
#include <netinet/tcp.h>


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

	virtual void print_options() {}
	virtual void print_statistics() {}
};


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


//==================================================================================================
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
			socklen_t addr_size = sizeof(client_addr);
			int client_sock = ::accept(m_socket, (::sockaddr*)&client_addr, &addr_size);

			if(client_sock == -1)
			{
				if(errno != EAGAIN && errno != EWOULDBLOCK && errno != ECONNABORTED)
					throw std::runtime_error{"accept(): " + errno_string(errno)};
			}
			else
			{
				Address addr{m_addr.type(), "", (::sockaddr*)&client_addr, addr_size};
				return std::unique_ptr<TCPSocket>{new TCPSocket{addr, client_sock}};
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
				throw std::runtime_error{"connect(): " + errno_string(errno)};
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
					throw std::runtime_error{"send(): " + errno_string(errno)};
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

	virtual void print_statistics()
	{
		tcp_info info;
		socklen_t info_size = sizeof(info);
		if(getsockopt(m_socket, SOL_TCP, TCP_INFO, (void*)&info, &info_size) != 0)
			throw std::runtime_error{"getsockopt(): " + errno_string(errno)};

		std::cout << "RTT: " << info.tcpi_rtt / 1000.0 << " ms\n";
	}

private:
	Address m_addr;
	int m_socket;
};


//==================================================================================================
template<typename T>
void udt_setsockopt(UDTSOCKET sock, UDT::SOCKOPT opt_name, T val)
{
	if(UDT::setsockopt(sock, 0, opt_name, (void*)&val, sizeof(val)) == UDT::ERROR)
		throw std::runtime_error{std::string{"UDT::setsockopt(): "} + UDT::getlasterror_desc()};
}

template<typename T>
T udt_getsockopt(UDTSOCKET sock, UDT::SOCKOPT opt_name)
{
	T val;
	int len;
	if(UDT::getsockopt(sock, 0, opt_name, (void*)&val, &len) == UDT::ERROR)
		throw std::runtime_error{std::string{"UDT::getsockopt(): "} + UDT::getlasterror_desc()};

	return val;
}


class UDTSocket : public Socket
{
public:
	UDTSocket(Address const &addr) :
		m_addr{addr},
		m_socket{UDT::socket(addr.family(), addr.type(), 0)}
	{
		if(m_socket == UDT::INVALID_SOCK)
			throw std::runtime_error{std::string{"UDT::socket(): "} + UDT::getlasterror_desc()};
	}

	UDTSocket(Address const &addr, UDTSOCKET sock) :
		m_addr{addr},
		m_socket{sock} {}

	virtual ~UDTSocket()
	{
		UDT::close(m_socket);
	}

	UDTSOCKET native() { return m_socket; }

	virtual void listen()
	{
		if(UDT::bind(m_socket, m_addr.native_address(), m_addr.native_size()) == UDT::ERROR)
			throw std::runtime_error{std::string{"UDT::bind(): "} + UDT::getlasterror_desc()};

		if(UDT::listen(m_socket, 10) == UDT::ERROR)
			throw std::runtime_error{std::string{"UDT::listen(): "} + UDT::getlasterror_desc()};
	}

	virtual std::unique_ptr<Socket> accept()
	{
		::sockaddr_storage client_addr;
		int addr_size = sizeof(client_addr);
		UDTSOCKET client_sock = UDT::accept(m_socket, (::sockaddr*)&client_addr, &addr_size);

		if(client_sock == UDT::INVALID_SOCK)
			throw std::runtime_error{std::string{"UDT::accept(): "} + UDT::getlasterror_desc()};
		else
		{
			Address addr{m_addr.type(), "", (::sockaddr*)&client_addr, (size_t)addr_size};
			std::unique_ptr<UDTSocket> client{new UDTSocket{addr, client_sock}};

			return std::move(client);
		}
	}

	virtual void connect()
	{
        if(UDT::connect(m_socket, m_addr.native_address(), m_addr.native_size()) == UDT::ERROR)
			throw std::runtime_error{std::string{"UDT::connect(): "} + UDT::getlasterror_desc()};
	}

	virtual size_t write(char const *src, size_t size)
	{
		auto send_res = UDT::send(m_socket, src, size, MSG_NOSIGNAL);
		if(send_res == UDT::ERROR)
		{
			if(UDT::getlasterror_code() == CUDTException::ECONNLOST)
			{
				// Connection has been closed
				return 0;
			}
			else
				throw std::runtime_error{std::string{"UDT::send(): "} + UDT::getlasterror_desc()};
		}
		else
			return send_res;
	}

	virtual size_t read(char *dest, size_t size)
	{
		auto recv_res = UDT::recv(m_socket, dest, size, 0);
		if(recv_res == UDT::ERROR)
		{
			if(UDT::getlasterror_code() == CUDTException::ECONNLOST)
				return 0;
			else
				throw std::runtime_error{std::string{"UDT::recv(): "} + UDT::getlasterror_desc()};
		}
		else
			return recv_res;
	}

	virtual void print_options()
	{
		std::cout << "UDT send buffer: " << udt_getsockopt<int>(m_socket, UDT_SNDBUF) / 1024.0 / 1024.0 << " MB\n"
		          << "UDT recv buffer: " << udt_getsockopt<int>(m_socket, UDT_RCVBUF) / 1024.0 / 1024.0 << " MB\n"
		          << "UDP send buffer: " << udt_getsockopt<int>(m_socket, UDP_SNDBUF) / 1024.0 / 1024.0 << " MB\n"
		          << "UDP recv buffer: " << udt_getsockopt<int>(m_socket, UDP_RCVBUF) / 1024.0 / 1024.0 << " MB\n"
		          << "UDT packet size: " << udt_getsockopt<int>(m_socket, UDT_MSS) << " B"
		          << std::endl;
	}

	virtual void print_statistics()
	{
		UDT::TRACEINFO perf;
		if(UDT::perfmon(m_socket, &perf) == UDT::ERROR)
			throw std::runtime_error{std::string{"UDT::perfmon(): "} + UDT::getlasterror_desc()};

		std::cout << "RTT:            " << perf.msRTT << " ms\n"
		          << "Sending rate:   " << perf.mbpsSendRate << " Mbps\n"
		          << "Receiving rate: " << perf.mbpsRecvRate << " Mbps\n"
		          << "Bandwidth:      " << perf.mbpsBandwidth << " Mbps" << std::endl;
	}

private:
	Address m_addr;
	UDTSOCKET m_socket;
};
