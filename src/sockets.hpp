#pragma once

#include "common.hpp"

#include <udt/udt.h>

#include <memory>
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

private:
	Address m_addr;
	int m_socket;
};


//==================================================================================================
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
			return std::unique_ptr<UDTSocket>{new UDTSocket{addr, client_sock}};
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

private:
	Address m_addr;
	UDTSOCKET m_socket;
};
