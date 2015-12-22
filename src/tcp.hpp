#pragma once

#include "socket.hpp"

#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/socket.h>


//==================================================================================================
template<typename T>
T getsockopt(int sock, int level, int opt_name)
{
	T val = 0;
	socklen_t len = sizeof(T);
	if(getsockopt(sock, level, opt_name, (void*)&val, &len) == -1)
		throw std::runtime_error{"getsockopt(): " + errno_string(errno)};

	return val;
}

template<typename T>
T setsockopt(int sock, int level, int opt_name, T val)
{
	socklen_t len = sizeof(T);
	if(setsockopt(sock, level, opt_name, (void*)&val, len) == -1)
		throw std::runtime_error{"setsockopt(): " + errno_string(errno)};

	return val;
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

	int native() { return m_socket; }

	virtual void listen()
	{
		if(::bind(m_socket, m_addr.native_address(), m_addr.native_size()) == -1)
			throw std::runtime_error{"bind(): " + errno_string(errno)};

		if(::listen(m_socket, 10) == -1)
			throw std::runtime_error{"listen(): " + errno_string(errno)};
	}

	virtual std::unique_ptr<Socket> accept()
	{
		// Retry on EINTR and ECONNABORTED.
		while(true)
		{
			::sockaddr_storage client_addr;
			socklen_t addr_size = sizeof(client_addr);
			int client_sock = ::accept(m_socket, (::sockaddr*)&client_addr, &addr_size);

			if(client_sock == -1)
			{
				if(errno != EINTR && errno != ECONNABORTED)
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
		// Retry on EINTR.
		// It seems this only works on Linux, see http://www.madore.org/~david/computers/connect-intr.html
		// for more information.
		while(true)
		{
			if(::connect(m_socket, m_addr.native_address(), m_addr.native_size()) == -1)
			{
				if(errno != EINTR)
					throw std::runtime_error{"connect(): " + errno_string(errno)};
			}
			else
				break;
		}
	}

	virtual size_t write(char const *src, size_t size)
	{
		// Retry on EINTR.
		while(true)
		{
			// MSG_NOSIGNAL: Return EPIPE instead of sending a SIGPIPE signal if the connection has
			// been closed.
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
			{
				socket_logger().add_bytes_written(send_res);
				return send_res;
			}
		}
	}

	virtual size_t read(char *dest, size_t size)
	{
		// Retry on EINTR.
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
				socket_logger().add_bytes_read(recv_res);

				// If recv_res == 0 the connection has been closed.
				return recv_res;
			}
		}
	}

	// Should be called after calling listen() or connect() since some OS's don't show modified
	// values until then.
	virtual void print_options()
	{
		auto recv_buf = getsockopt<int32_t>(m_socket, SOL_SOCKET, SO_RCVBUF);
		auto send_buf = getsockopt<int32_t>(m_socket, SOL_SOCKET, SO_SNDBUF);
		auto max_seg_size = getsockopt<int32_t>(m_socket, IPPROTO_TCP, TCP_MAXSEG);

		std::cout << "Receive buffer: " << bytes_to_string(recv_buf) << '\n'
		          << "Send buffer:    " << bytes_to_string(send_buf) << '\n'
		          << "MSS:            " << bytes_to_string(max_seg_size)
		          << std::endl;
	}

	virtual void print_statistics()
	{
		tcp_info info;
		socklen_t info_size = sizeof(info);
		if(getsockopt(m_socket, SOL_TCP, TCP_INFO, (void*)&info, &info_size) != 0)
			throw std::runtime_error{"getsockopt(): " + errno_string(errno)};

		std::cout << "RTT: " << info.tcpi_rtt / 1000.0 << " ms\n"
		          << "Lost packets: " << info.tcpi_lost << '\n'
		          << "Retrans: " << info.tcpi_retrans << '\n'
		          << "Total retransmits: " << info.tcpi_total_retrans << std::endl;
	}

	virtual std::ostream& stats_csv(std::ostream &os)
	{
		tcp_info info;
		socklen_t info_size = sizeof(info);
		if(getsockopt(m_socket, SOL_TCP, TCP_INFO, (void*)&info, &info_size) != 0)
			throw std::runtime_error{"getsockopt(): " + errno_string(errno)};

		os << Milliseconds{info.tcpi_rtt / 1000.0}.count()
		   << ',' << info.tcpi_snd_cwnd
		   << ',' << info.tcpi_snd_mss
		   << ',' << info.tcpi_rcv_mss
		   << ',' << info.tcpi_reordering
		   << ',' << info.tcpi_snd_ssthresh
		   << ',' << info.tcpi_rcv_ssthresh
		;

		return os;
	}

private:
	Address m_addr;
	int m_socket;
};

