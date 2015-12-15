#pragma once

#include <string>
#include <chrono>
#include <unordered_map>
#include <vector>
#include <list>
#include <list>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>


//==================================================================================================
std::string bytes_to_string(size_t bytes)
{
	static char const *unit_str[] = {
		"B",
		"KB",
		"MB",
		"GB"
	};
	constexpr int max_unit_index = 3;

	double value = bytes;
	int unit = 0;
	while(value >= 1024.0 && unit <= max_unit_index)
		value /= 1024.0, ++unit;

	std::ostringstream os;
	os << value << unit_str[unit];
	return os.str();
}

std::string bps_to_string(size_t bps)
{
	static char const *unit_str[] = {
		" Bits/sec",
		" KBits/sec",
		" MBits/sec",
		" GBits/sec"
	};
	constexpr int max_unit_index = 3;

	double value = bps;
	int unit = 0;
	while(value >= 1000.0 && unit <= max_unit_index)
		value /= 1000.0, ++unit;

	std::ostringstream os;
	os << value << unit_str[unit];
	return os.str();
}


using TimePoint = std::chrono::high_resolution_clock::time_point;
using Seconds = std::chrono::duration<double>;
using Milliseconds = std::chrono::duration<double, std::milli>;

inline TimePoint time_now()
{
	return std::chrono::high_resolution_clock::now();
}


//==================================================================================================
class SocketLogger
{
public:

	struct Record
	{
		Record() = default;
		Record(std::string const &scope, TimePoint start) :
			scope{scope},
			start{start} {}

		std::string scope;
		size_t bytes_read = 0;
		size_t bytes_written = 0;
		TimePoint start;
		TimePoint end;
	};


	void start(std::string const &scope)
	{
		m_active_records[scope] = {scope, time_now()};
	}

	void stop(std::string const &scope)
	{
		auto rec = m_active_records.find(scope);
		if(rec == m_active_records.end())
			throw std::runtime_error{"Scope has not been started: " + scope};

		rec->second.end = time_now();
		m_closed_records.push_back(rec->second);

		m_active_records.erase(rec);
	}

	void add_bytes_written(size_t num_bytes)
	{
		for(auto &pair: m_active_records)
			pair.second.bytes_written += num_bytes;
	}

	void add_bytes_read(size_t num_bytes)
	{
		for(auto &pair: m_active_records)
			pair.second.bytes_read += num_bytes;
	}

	void print() const;

private:
	std::vector<Record> m_closed_records;
	std::unordered_map<std::string, Record> m_active_records;
};

void SocketLogger::print() const
{
	std::cout << "scope           read (bytes)  written (bytes)  read bandw.  write bandw.       time\n";
	std::cout << "-----------------------------------------------------------------------------------\n";

	for(auto const &rec: m_closed_records)
	{
		std::chrono::duration<double> elapsed_secs = rec.end - rec.start;
		double bps_read = (rec.bytes_read * 8) / elapsed_secs.count();
		double bps_written = (rec.bytes_written * 8) / elapsed_secs.count();

		std::cout
			<< std::left << std::setw(15) << rec.scope << " " << std::right
			<< std::setprecision(3)
			<< std::setw(12) << bytes_to_string(rec.bytes_read) << "  "
			<< std::setw(15) << bytes_to_string(rec.bytes_written) << "  "
			<< std::setw(11) << bps_to_string(bps_read) << "  "
			<< std::setw(11) << bps_to_string(bps_written) << "  "
			<< std::setw(10) << elapsed_secs.count() << "s\n";
	}

	std::cout << std::flush;
}


//==================================================================================================
inline SocketLogger& socket_logger()
{
	static SocketLogger sl;
	return sl;
}
