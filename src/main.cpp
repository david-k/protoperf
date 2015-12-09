#include "common.hpp"
#include "sockets.hpp"

#include <iostream>
#include <memory>
#include <chrono>
#include <cassert>


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
	int udt_snd_buf = -1;
	int udt_rcv_buf = -1;
	int udp_snd_buf = -1;
	int udp_rcv_buf = -1;
	int udt_packet_size = -1;
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
	std::string port = "2000";
	SocketOpts opts;

	// Client options
	std::string host;
	size_t bytes_to_send = 1024 * 1024;
	int repeats = 1;
	std::string run_file;
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

Invocation parse_args(int argc, char *argv[], Invocation const defaults = {})
{
	Invocation invoc = defaults;

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
		else if(!std::strcmp(argv[i], "-n"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify the number of Mbytes"};

			invoc.bytes_to_send = parse_byte_size(argv[i]);
		}
		else if(!std::strcmp(argv[i], "-r"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify a number"};

			invoc.repeats = std::stoul(argv[i], nullptr, 10);
		}
		else if(!std::strcmp(argv[i], "--udt"))
		{
			invoc.protocol = Protocol::udt;
		}
		else if(!std::strcmp(argv[i], "--udt-packet-size"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify the number of Mbytes"};

			invoc.opts.udt_packet_size = parse_byte_size(argv[i]);
		}
		else if(!std::strcmp(argv[i], "--udt-snd-buf"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify the number of Mbytes"};

			invoc.opts.udt_snd_buf = parse_byte_size(argv[i]);
		}
		else if(!std::strcmp(argv[i], "--udt-rcv-buf"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify the number of Mbytes"};

			invoc.opts.udt_rcv_buf = parse_byte_size(argv[i]);
		}
		else if(!std::strcmp(argv[i], "--udp-snd-buf"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify the number of Mbytes"};

			invoc.opts.udp_snd_buf = parse_byte_size(argv[i]);
		}
		else if(!std::strcmp(argv[i], "--udp-rcv-buf"))
		{
			if(++i == argc)
				throw std::runtime_error{"You must specify the number of Mbytes"};

			invoc.opts.udp_rcv_buf = parse_byte_size(argv[i]);
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
		case Protocol::tcp: return std::unique_ptr<TCPSocket>{new TCPSocket{addr}};
		case Protocol::udt:
		{
		    std::unique_ptr<UDTSocket> sock{new UDTSocket{addr}};

			if(opts.udt_snd_buf != -1)
				udt_setsockopt(sock->native(), UDT_SNDBUF, opts.udt_snd_buf);
			if(opts.udt_rcv_buf != -1)
				udt_setsockopt(sock->native(), UDT_RCVBUF, opts.udt_rcv_buf);
			if(opts.udp_snd_buf != -1)
				udt_setsockopt(sock->native(), UDP_SNDBUF, opts.udp_snd_buf);
			if(opts.udp_rcv_buf != -1)
				udt_setsockopt(sock->native(), UDP_RCVBUF, opts.udp_rcv_buf);

			if(opts.udt_packet_size != -1)
				udt_setsockopt(sock->native(), UDT_MSS, opts.udt_packet_size);

			return std::move(sock);
		}

		default:
			throw std::runtime_error{"Unsupported protocol: " + to_string(proto)};
	};
}


//==================================================================================================
struct ClientBenchmark
{
	Protocol protocol;
	std::string port;
	std::string host;

	int runs = 1;
	size_t bytes_to_send;
	SocketOpts opts;
};

ClientBenchmark client_bench_from_invoc(Invocation const &invoc)
{
	ClientBenchmark bench;
	bench.host = invoc.host;
	bench.protocol = invoc.protocol;
	bench.port = invoc.port;
	bench.bytes_to_send = invoc.bytes_to_send;
	bench.opts = invoc.opts;
	bench.runs = invoc.repeats;

	return bench;
}

void run_client_benchmark(ClientBenchmark const &bench)
{
	auto addrs = remote_addresses(bench.host.c_str(), bench.port.c_str(), SOCK_STREAM, AF_INET);
	if(addrs.empty())
		throw std::runtime_error{"No addresses found"};

	std::cout << addrs[0] << std::endl;
	std::cout << "Protocol: " << to_string(bench.protocol) << std::endl;

	for(int i = 0; i < bench.runs; ++i)
	{
		auto socket = make_benchmark_socket(bench.protocol, bench.opts, addrs[0]);
		socket->print_options();
		socket->connect();

		size_t const max_buffer_size = 100 * 1024 * 1024;
		size_t bytes_written = 0;
		std::vector<char> buffer(std::min(max_buffer_size, bench.bytes_to_send));

		size_t iterations = bench.bytes_to_send / max_buffer_size;
		for(size_t i = 0; i < iterations; ++i)
		{
			write_all(socket.get(), buffer.data(), buffer.size());
			bytes_written += buffer.size();
		}

		auto rest = bench.bytes_to_send - bytes_written;
		assert(rest <= buffer.size());
		write_all(socket.get(), buffer.data(), rest);
		bytes_written += rest;

		std::cout << "Wrote " << (bytes_written / 1024.0 / 1024.0) << " Mbytes" << std::endl;
		socket->print_statistics();
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
		socket->print_options();
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
		std::vector<ClientBenchmark> benchs;
		if(invoc.run_file.empty())
			benchs.push_back(client_bench_from_invoc(invoc));
		else
		{
			auto defaults = invoc;
			defaults.run_file.clear();
			benchs = load_run_file(invoc.run_file, defaults);
		}

		for(auto const &bench: benchs)
			run_client_benchmark(bench);
	}
}
