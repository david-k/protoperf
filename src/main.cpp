#include "common.hpp"
#include "sockets.hpp"

#include <iostream>
#include <memory>
#include <chrono>
#include <cassert>


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
	size_t bytes_to_send;

	// UDT
	bool use_ctcp; // TCP Congestion Control
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
	invoc.bytes_to_send = 1024 * 1024;
	invoc.use_ctcp = false;

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
		else if(!std::strcmp(argv[i], "-l"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify the number of Mbytes"};

			invoc.bytes_to_send = std::strtoull(argv[i], nullptr, 10) * 1024 * 1024;
		}
		else if(!std::strcmp(argv[i], "--udt"))
		{
			invoc.protocol = Invocation::Protocol::udt;
		}
		else if(!std::strcmp(argv[i], "--ctcp"))
		{
			invoc.use_ctcp = true;
		}
		else
			throw std::runtime_error{std::string{"Unknown flag: "} + argv[i]};
	}

	if(!mode_specified)
		throw std::runtime_error{"You must specify either -s or -c to run a server or client"};

	return invoc;
}


//==================================================================================================
std::unique_ptr<Socket> make_benchmark_socket(Invocation const &invoc, Address const &addr)
{
	switch(invoc.protocol)
	{
		case Invocation::Protocol::tcp: return std::unique_ptr<TCPSocket>{new TCPSocket{addr}};
		case Invocation::Protocol::udt: return std::unique_ptr<UDTSocket>{new UDTSocket{addr, invoc.use_ctcp}};
;
		default:
			throw std::runtime_error{"Unsupported protocol: " + to_string(invoc.protocol)};
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
		std::cout << "Protocol: " << to_string(invoc.protocol) << std::endl;
		auto socket = make_benchmark_socket(invoc, addrs[0]);
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

			std::cout << "Read " << (bytes_read / 1024.0 / 1024.0) << " Mbytes"
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
		std::cout << "Protocol: " << to_string(invoc.protocol) << std::endl;
		auto socket = make_benchmark_socket(invoc, addrs[0]);

		socket->connect();

		size_t const max_buffer_size = 100 * 1024 * 1024;
		size_t bytes_written = 0;
		std::vector<char> buffer(std::min(max_buffer_size, invoc.bytes_to_send));

		size_t iterations = invoc.bytes_to_send / max_buffer_size;
		for(size_t i = 0; i < iterations; ++i)
		{
			write_all(socket.get(), buffer.data(), buffer.size());
			bytes_written += buffer.size();
		}

		auto rest = invoc.bytes_to_send - bytes_written;
		assert(rest <= buffer.size());
		write_all(socket.get(), buffer.data(), rest);
		bytes_written += rest;

		std::cout << "Wrote " << (bytes_written / 1024.0 / 1024.0) << " Mbytes" << std::endl;
	}
		
}
