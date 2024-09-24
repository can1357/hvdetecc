#pragma once
#include <xstd/hashable.hpp>
#include <unordered_set>
#include <sdk/mi/api.hpp>
#include <sdk/nt/mmpfn_t.hpp>
#include <sdk/mi/pfn_cache_attribute_t.hpp>
#include <ntpp.hpp>
#include <mcrt/interface.hpp>
#include <ia32/memory.hpp>

namespace hwid
{
	// Describes a single disk.
	//
	struct disk_identifier
	{
		// PCI information.
		//
		uint32_t vendor = 0;
		uint32_t device = 0;
		uint32_t subsystem = 0;
		uint8_t  revision = 0;
		uint8_t  adr_func = 0;
		uint8_t  adr_bus = 0;
		uint8_t  adr_dev = 0;

		// Disk model number.
		//
		std::string model;

		// Disk serial number.
		//
		std::string serial;

		// Hashing and comparison.
		//
		xstd::hash_t hash() const { return xstd::make_hash( model, serial ); }
		bool operator==( const disk_identifier& o ) const { return model == o.model && serial == o.serial; }
		bool operator!=( const disk_identifier& o ) const { return model != o.model || serial != o.serial; }
	};

	// Page in the low 4GB range used for identification data.
	//
	inline auto identification_space = [ ] ()
	{
		for ( auto lim : { 2_gb, 3_gb, 4_gb, UINT64_MAX } )
			if ( void* res = mm::allocate_contiguous_memory( 0x1000, lim ) )
				return ( uint8_t* ) res;
		unreachable();
	}();


	// Describes a set of disks.
	//
	using disk_set = std::unordered_set<disk_identifier, xstd::hasher<>>;

	// Issues identify commands to every supported disk controller in the device and returns the resulting identifiers.
	//
	disk_set get_disks();
};