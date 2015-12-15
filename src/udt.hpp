#pragma once

#include "socket.hpp"

#include <udt/udt.h>


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
		{
			socket_logger().add_bytes_written(send_res);
			return send_res;
		}
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
		{
			socket_logger().add_bytes_read(recv_res);
			return recv_res;
		}
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
		          << "Lost packets (snd):      " << perf.pktSndLossTotal << "\n"
		          << "Lost packets (rcv):      " << perf.pktRcvLossTotal << std::endl;
	}

	virtual SocketStats get_stats()
	{
		SocketStats stats{};
		return stats;
	}

private:
	Address m_addr;
	UDTSOCKET m_socket;
};
