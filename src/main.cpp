#include "common.hpp"
#include "tcp.hpp"
#include "udt.hpp"

#include <iostream>
#include <memory>
#include <chrono>
#include <cassert>
#include <csignal>
#include <thread>
#include <atomic>

#include <fcntl.h>


//==================================================================================================
enum class Protocol
{
	tcp,
	udt
};

std::string to_string(Protocol p)
{
	switch(p)
	{
		case Protocol::tcp: return "TCP";
		case Protocol::udt: return "UDT";
		default: return "<unknown>";
	};
}

struct SocketOpts
{
	int snd_buf = -1;
	int rcv_buf = -1;
	int packet_size = -1;

	// UDP send/receive buffer sizes used by UDT.
	int udt_udp_snd_buf = -1;
	int udt_udp_rcv_buf = -1;
};


//==================================================================================================
struct Invocation
{
	enum class Mode
	{
		client,
		server,

		unknown
	};

	// Common options
	Mode mode;
	Protocol protocol = Protocol::tcp;
	std::string port = "9001";
	SocketOpts opts;
	size_t buffer_size = 8 * 1024;

	// Server options
	size_t server_bytes_to_send = 0;

	// Client options
	std::string host;
	int repeats = 1;
	std::string run_file;
	size_t client_bytes_to_send = 1024 * 1024;
};

size_t parse_byte_size(char const *str)
{
	auto length = strlen(str);
	if(!length)
		throw std::runtime_error{"parse_byte_size(): empty string"};

	auto unit = str[length - 1];
	int mul;
	switch(unit)
	{
		case 'B': mul = 1; break;
		case 'K': mul = 1024; break;
		case 'M': mul = 1024 * 1024; break;
		case 'G': mul = 1024 * 1024 * 1024; break;
		default:
			throw std::runtime_error{"Unknown unit suffix"};
	};

	return std::stoull(str, nullptr, 10) * mul;
}

Invocation parse_args(int argc, char *argv[], Invocation const &defaults = {})
{
	Invocation invoc = defaults;

	bool bytes_to_send_specified = false;
	size_t bytes_to_send = 0;
	for(int i = 1; i < argc; ++i)
	{
		if(!std::strcmp(argv[i], "-s"))
		{
			invoc.mode = Invocation::Mode::server;
		}
		else if(!std::strcmp(argv[i], "-c"))
		{
			invoc.mode = Invocation::Mode::client;

			if(++i == argc)
				throw std::runtime_error{"You must specify a host the client can connect to"};

			invoc.host = argv[i];
		}
		else if(!std::strcmp(argv[i], "-r"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify a number"};

			invoc.repeats = std::stoul(argv[i], nullptr, 10);
		}
		else if(!std::strcmp(argv[i], "-p"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify a port"};

			invoc.port = argv[i];
		}
		else if(!std::strcmp(argv[i], "-n"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify the number of bytes"};

			bytes_to_send = parse_byte_size(argv[i]);
			bytes_to_send_specified = true;
		}
		else if(!std::strcmp(argv[i], "-l"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify the number of bytes"};

			invoc.buffer_size = parse_byte_size(argv[i]);
		}
		else if(!std::strcmp(argv[i], "--udt"))
		{
			invoc.protocol = Protocol::udt;
		}
		else if(!std::strcmp(argv[i], "--packet-size"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify the number of bytes"};

			invoc.opts.packet_size = parse_byte_size(argv[i]);
		}
		else if(!std::strcmp(argv[i], "--snd-buf"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify the number of bytes"};

			invoc.opts.snd_buf = parse_byte_size(argv[i]);
		}
		else if(!std::strcmp(argv[i], "--rcv-buf"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify the number of bytes"};

			invoc.opts.rcv_buf = parse_byte_size(argv[i]);
		}
		else if(!std::strcmp(argv[i], "--udt-udp-snd-buf"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify the number of bytes"};

			invoc.opts.udt_udp_snd_buf = parse_byte_size(argv[i]);
		}
		else if(!std::strcmp(argv[i], "--udt-udp-rcv-buf"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify the number of bytes"};

			invoc.opts.udt_udp_rcv_buf = parse_byte_size(argv[i]);
		}
		else if(!std::strcmp(argv[i], "--run-file"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify a file"};

			invoc.run_file = argv[i];
		}
		else
			throw std::runtime_error{std::string{"Unknown flag: "} + argv[i]};
	}

	if(invoc.mode == Invocation::Mode::unknown)
		throw std::runtime_error{"You must specify either -s or -c to run a server or client"};

	if(bytes_to_send_specified)
	{
		switch(invoc.mode)
		{
			case Invocation::Mode::server: invoc.server_bytes_to_send = bytes_to_send; break;
			case Invocation::Mode::client: invoc.client_bytes_to_send = bytes_to_send; break;
			case Invocation::Mode::unknown: break;
		}
	}

	return invoc;
}

Invocation invocation_from_string(std::string const &arg_string, Invocation const &defaults)
{
	// Used to hold the string data.
	// TODO Get rid of it.
	std::vector<std::string> args_holder;

	std::vector<char*> args;

	std::string empty{"argv[0]"};
	args.push_back(&empty[0]);

	size_t pos = 0;
	while((pos = arg_string.find_first_not_of(" \t", pos)) != std::string::npos)
	{
		auto arg_end = arg_string.find_first_of(" \t", pos);
		auto count = arg_end == std::string::npos ? arg_string.length() - pos : arg_end - pos;
		auto arg = arg_string.substr(pos, count);
		pos += count;

		args_holder.push_back(arg);
		args.push_back(&args_holder.back()[0]);
	}

	return parse_args(args.size(), args.data(), defaults);
}


//==================================================================================================
std::unique_ptr<Socket> make_benchmark_socket(Protocol proto, SocketOpts const &opts, Address const &addr)
{
	switch(proto)
	{
		case Protocol::tcp:
		{
			std::unique_ptr<TCPSocket> sock{new TCPSocket{addr}};

			if(opts.snd_buf != -1)
				setsockopt(sock->native(), SOL_SOCKET, SO_SNDBUF, opts.snd_buf);
			if(opts.rcv_buf != -1)
				setsockopt(sock->native(), SOL_SOCKET, SO_RCVBUF, opts.rcv_buf);

			if(opts.packet_size != -1)
				setsockopt(sock->native(), IPPROTO_TCP, TCP_MAXSEG, opts.packet_size);

			return std::move(sock);
		}
		case Protocol::udt:
		{
		    std::unique_ptr<UDTSocket> sock{new UDTSocket{addr}};

			if(opts.snd_buf != -1)
				udt_setsockopt(sock->native(), UDT_SNDBUF, opts.snd_buf);
			if(opts.rcv_buf != -1)
				udt_setsockopt(sock->native(), UDT_RCVBUF, opts.rcv_buf);
			if(opts.udt_udp_snd_buf != -1)
				udt_setsockopt(sock->native(), UDP_SNDBUF, opts.udt_udp_snd_buf);
			if(opts.udt_udp_rcv_buf != -1)
				udt_setsockopt(sock->native(), UDP_RCVBUF, opts.udt_udp_rcv_buf);

			if(opts.packet_size != -1)
				udt_setsockopt(sock->native(), UDT_MSS, opts.packet_size);

			return std::move(sock);
		}

		default:
			throw std::runtime_error{"Unsupported protocol: " + to_string(proto)};
	};
}


//==================================================================================================
class RandomSource
{
public:
	RandomSource()
	{
		m_fd = ::open("/dev/urandom", O_RDONLY);
		if(m_fd == -1)
			throw std::runtime_error{"::open(/dev/urandom): " + errno_string(errno)};
	}

	void read(char *dest, size_t size)
	{
		if(::read(m_fd, dest, size) != (ssize_t)size)
			throw std::runtime_error{"reading from /dev/random failed."};
	}

	~RandomSource()
	{
		::close(m_fd);
	}

private:
	int m_fd;
};

inline RandomSource& random_source()
{
	static RandomSource rs;
	return rs;
}


class BenchmarkWriter
{
public:
	explicit BenchmarkWriter(size_t buffer_size) :
		m_buffer(buffer_size) 
	{
		random_source().read(m_buffer.data(), m_buffer.size());
	}

	size_t write(Socket *sock, size_t num_bytes)
	{
		size_t total_bytes_written = 0;

		while(total_bytes_written < num_bytes)
		{
			auto write_length = std::min(m_buffer.size(), num_bytes - total_bytes_written);
			int bytes_written = sock->write(m_buffer.data(), write_length);

			if(bytes_written == 0)
				break;

			total_bytes_written += bytes_written;
		}

		return total_bytes_written;
	}

private:
	std::vector<char> m_buffer;
};


//==================================================================================================
std::atomic<bool> collect_stats{true};
void stats_thread(Socket *sock, std::string const &filename)
{
	std::ofstream file{filename};
	auto start = time_now();
	while(collect_stats)
	{
		auto stats = sock->get_stats();
		auto time = time_now() - start;

		file << time.count() << ','
		     << stats.rtt.count() << ',' 
		     << stats.cwnd_size  << ','
		     << stats.rwnd_size
		     << std::endl;

		std::this_thread::sleep_for(Milliseconds{100});
	}
}


//==================================================================================================
unsigned char const MSG_REQUEST = '<';
unsigned char const MSG_RESPONSE = '>';
unsigned char const MSG_CONFIRMATION = '!';


struct ClientBenchmark
{
	Protocol protocol;
	std::string port;
	std::string host;

	int runs = 1;
	SocketOpts opts;
	size_t bytes_to_send;
	size_t buffer_size;
};

ClientBenchmark client_bench_from_invoc(Invocation const &invoc)
{
	ClientBenchmark bench;
	bench.host = invoc.host;
	bench.protocol = invoc.protocol;
	bench.port = invoc.port;
	bench.opts = invoc.opts;
	bench.runs = invoc.repeats;
	bench.bytes_to_send = invoc.client_bytes_to_send;
	bench.buffer_size = invoc.buffer_size;

	return bench;
}

void run_client_benchmark(ClientBenchmark const &bench)
{
	auto addrs = remote_addresses(bench.host.c_str(), bench.port.c_str(), SOCK_STREAM, AF_INET);
	if(addrs.empty())
		throw std::runtime_error{"No addresses found"};

	std::cout << addrs[0] << std::endl;
	std::cout << "Protocol: " << to_string(bench.protocol) << std::endl;

	BenchmarkWriter writer{bench.buffer_size};

	for(int i = 0; i < bench.runs; ++i)
	{
		auto socket = make_benchmark_socket(bench.protocol, bench.opts, addrs[0]);

		collect_stats = true;
		std::thread observer{stats_thread, socket.get(), "client_stats_" + std::to_string(i)};

		std::cout << "************************************************************\n";
		socket->connect();
		socket->print_options();
		std::cout << "Connected" << std::endl;

		socket_logger() = {};
		socket_logger().start("Total");

		// 1. Send data
		// 2. Wait for confirmation
		// 3. Receive data
		// 4. Send confirmation

		// Send random data.
		socket_logger().start("Sending ack");
		socket_logger().start("Sending");
		write_message(socket.get(), MessageHeader{MSG_REQUEST, bench.bytes_to_send});
		writer.write(socket.get(), bench.bytes_to_send);
		socket_logger().stop("Sending");

		discard_message(socket.get(), MSG_CONFIRMATION);
		socket_logger().stop("Sending ack");

		// Wait for confirmation.
		socket_logger().start("Receiving");
		discard_message(socket.get(), MSG_RESPONSE);
		socket_logger().stop("Receiving");

		write_message(socket.get(), MessageHeader{MSG_CONFIRMATION});

		socket_logger().stop("Total");

		socket->print_statistics();
		std::cout << '\n';
		socket_logger().print();
		std::cout << '\n';

		// Tell the server we are done.
		write_message(socket.get(), MessageHeader{MSG_CONFIRMATION});

		collect_stats = false;
		observer.join();
	}
}

std::vector<ClientBenchmark> load_run_file(std::string const &filepath, Invocation const &defaults)
{
	std::vector<ClientBenchmark> benchs;

	std::ifstream file{filepath};
	if(!file.good())
		throw std::runtime_error{"Opening file failed: " + filepath};

	std::string line;
	while(std::getline(file, line))
		benchs.push_back(client_bench_from_invoc(invocation_from_string(line, defaults)));

	return benchs;
}


//==================================================================================================
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
		auto socket = make_benchmark_socket(invoc.protocol, invoc.opts, addrs[0]);
		socket->listen();
		socket->print_options();

		BenchmarkWriter writer{invoc.buffer_size};
		int counter = 1;
		while(true)
		{
			auto client = socket->accept();
			collect_stats = true;
			std::thread observer{stats_thread, client.get(), "server_stats_" + std::to_string(counter++)};

			std::cout << "************************************************************\n";
			std::cout << "Accepted client" << std::endl;

			socket_logger() = {};
			socket_logger().start("Total");

			// 1. Receive data
			// 2. Send confirmation
			// 3. Send data
			// 4. Wait for confirmation

			// Read and discard all data.
			socket_logger().start("Receiving");
			discard_message(client.get(), MSG_REQUEST);
			socket_logger().stop("Receiving");

			write_message(client.get(), MessageHeader{MSG_CONFIRMATION});

			// Send confirmation.
			socket_logger().start("Sending ack");
			socket_logger().start("Sending");
			write_message(client.get(), MessageHeader{MSG_RESPONSE, invoc.server_bytes_to_send});
			writer.write(client.get(), invoc.server_bytes_to_send);
			socket_logger().stop("Sending");

			discard_message(client.get(), MSG_CONFIRMATION);
			socket_logger().stop("Sending ack");

			socket_logger().stop("Total");

			client->print_statistics();
			std::cout << '\n';

			socket_logger().print();
			std::cout << '\n';

			collect_stats = false;
			observer.join();
		}
	}
	else
	{
		std::vector<ClientBenchmark> benchs;
		if(invoc.run_file.empty())
			benchs.push_back(client_bench_from_invoc(invoc));
		else
		{
			auto defaults = invoc;
			defaults.run_file.clear(); // Don't use the run-file recursively.
			benchs = load_run_file(invoc.run_file, defaults);
		}

		for(auto const &bench: benchs)
			run_client_benchmark(bench);
	}
}
