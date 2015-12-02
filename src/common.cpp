#include "common.hpp"

//#include <sys/types.h>
//#include <sys/socket.h>
#include <netdb.h>


//==================================================================================================
std::string errno_string(int err)
{
	char buffer[128] = {0};
	auto str = strerror_r(err, buffer, 128);

	return str;
}


//==================================================================================================
char const* address_family_to_string(int fam)
{
	switch(fam)
	{
		case AF_UNSPEC: return "any_family";
		case AF_INET: return "inet";
		case AF_INET6: return "inet6";
		case AF_IPX: return "ipx";
		case AF_NETLINK: return "netlink";
		case AF_X25: return "x25";
		case AF_AX25: return "ax25";
		case AF_ATMPVC: return "atmpvc";
		case AF_APPLETALK: return "appletalk";
		case AF_PACKET: return "packet";
		case AF_UNIX: return "unix";
		default: throw std::runtime_error{"to_impl(): Invalid address family"};
	};
}

char const* sock_type_to_string(int type)
{
	switch(type)
	{
		case 0: return "any_type";
		case SOCK_STREAM: return "stream";
		case SOCK_DGRAM: return "datagram";
		case SOCK_SEQPACKET: return "sequence_packet";
		case SOCK_RAW: return "raw";
		case SOCK_RDM: return "reliable_datagram";
		default: throw std::runtime_error{"Invalid socket type"};
	};
}

std::ostream& operator << (std::ostream &os, Address const &addr)
{
	os << '(' << addr.canonical_name() << ", "
	   << address_family_to_string(addr.family()) << ", "
	   << sock_type_to_string(addr.type()) << ", ";

	if(addr.family() == AF_INET)
		os << addr.ipv4_address() << ", " << addr.ipv4_port();
	else
		os << "<not yet implemented>";

	return os << ')';
}


//==================================================================================================
namespace
{
	struct address_info
	{
		address_info() : info{nullptr} {}
		~address_info() { freeaddrinfo(info); }

		addrinfo *info;
	};

	std::vector<Address> build_address_list(addrinfo *first)
	{
		std::vector<Address> addresses;
		char const *canon_name = first->ai_canonname; // ai_canonname is only set in the first entry.
		while(first)
		{
			addresses.emplace_back(
				first->ai_socktype,
				canon_name ? canon_name : "",
				first->ai_addr,
				first->ai_addrlen
			);

			first = first->ai_next;
		}

		return addresses;
	}
}


std::vector<Address> remote_addresses(char const *host, char const *service, int sock_type, int fam)
{
	addrinfo hints;
	std::memset(&hints, 0, sizeof(hints));
	hints.ai_family = fam;
	hints.ai_socktype = sock_type;
	hints.ai_protocol = 0; // TODO: Protocols
	hints.ai_flags = AI_CANONNAME; // Return the canonical name of the server.

	address_info result;
	int res = getaddrinfo(host, service, &hints, &result.info);
	if(res != 0)
		throw std::runtime_error{std::string{"getaddrinfo() failed: "} + gai_strerror(res)};

	return build_address_list(result.info);
}


std::vector<Address> local_addresses(char const *service, int sock_type, int fam)
{
	addrinfo hints;
	std::memset(&hints, 0, sizeof(hints));
	hints.ai_family = fam;
	hints.ai_socktype = sock_type;
	hints.ai_protocol = 0; // TODO: Protocols
	hints.ai_flags = AI_PASSIVE; // Return wildcard addresses.

	address_info result;
	int res = getaddrinfo(nullptr, service, &hints, &result.info);
	if(res != 0)
		throw std::runtime_error{std::string{"getaddrinfo() failed: "} + gai_strerror(res)};

	return build_address_list(result.info);
}
