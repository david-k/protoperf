#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <iostream>

#include <arpa/inet.h>


//==================================================================================================
std::string errno_string(int err);


//==================================================================================================
class Address
{
public:
	Address(int type, std::string canonical_name, sockaddr const *addr, size_t size) :
		m_sock_type{type},
		m_canonical_name{std::move(canonical_name)},
		m_size{size}
	{
		std::memset(&m_address, 0, sizeof(m_address));
		std::memcpy(&m_address, addr, m_size);
	}

	// Common properties
	int family() const { return m_address.ss_family; }
	int type() const { return m_sock_type; }
	std::string const& canonical_name() const { return m_canonical_name; }

	// IPv4 stuff (call only if family() == address_family::ip_v4!)
	uint16_t ipv4_port() const { return ntohs(ipv4()->sin_port); }
	std::string ipv4_address() const
	{
		char addr[INET_ADDRSTRLEN];
		char const *str = inet_ntop(AF_INET, &ipv4()->sin_addr, addr, INET_ADDRSTRLEN);
		if(str == nullptr)
			throw std::runtime_error{"Error converting IPv4 address to string: " + errno_string(errno)};

		return str;
	}

	// Native stuff
	sockaddr const* native_address() const { return reinterpret_cast<sockaddr const*>(&m_address); }
	size_t native_size() const { return m_size; }

private:
	sockaddr_in const* ipv4() const { return reinterpret_cast<sockaddr_in const*>(&m_address); }
	sockaddr_in6 const* ipv6() const { return reinterpret_cast<sockaddr_in6 const*>(&m_address); }

private:
	int m_sock_type;
	std::string m_canonical_name;
	sockaddr_storage m_address;
	size_t m_size;
};


char const* address_family_to_string(int fam);
char const* sock_type_to_string(int type);
std::ostream& operator << (std::ostream &os, Address const &addr);


// Returns the list of internet addresses (IPv4 or IPv6) from the specified host that meet the
// given criteria.
// 'fam' must be any of address_family::ip_v4, address_family::ip_v6 or address_family::any.
// 'service' can be either a port number (like "80") or a service name which will be converted
// to a port number (e.g. "http"). See services(5).
// Use this function if you want to connect() to a host.
std::vector<Address> remote_addresses(char const *host, char const *service, int sock_type = 0,
                                      int fam = AF_UNSPEC);


// Returns the list of addresses from the local host that meet the given criteria. The returned
// addresses will be "wildcard addresses", meaning that if you bind() to them the IP address
// will automatically be set to the address of the local host.
// Use this function if you want to accept clients.
std::vector<Address> local_addresses(char const *service, int sock_type = 0, int fam = AF_UNSPEC);

