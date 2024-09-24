#include "bios.hpp"
#include <tuple>
#include <string_view>
#include <ia32/memory.hpp>
#include <ia32/iospace.hpp>
#include <ia32/smbios.hpp>
#include <xstd/text.hpp>
#include <sdk/wmip/api.hpp>

#include <ntpp.hpp>

namespace hwid
{
	// BIOS space ranges.
	//
	static constexpr size_t bios_space_base =   0xE0000;
	static constexpr size_t bios_space_length = 0x20000;

	// Entry point list.
	//
	static constexpr std::tuple<std::string_view, uint32_t, uint32_t> entry_points[] = {
		{ "_SM3_", 0xF0000, 0xFFFFF },
		{ "_SM_", 0xF0000, 0xFFFFF },
		//{ "_DMI_", 0xF0000, 0xFFFFF },
		//{ "_SYSID_", 0xE0000, 0xFFFFF },
		//{ "$PnP", 0xF0000, 0xFFFFF },
		//{ "RSD PTR ", 0xE0000, 0xFFFFF },
		//{ "$SNY", 0xE0000, 0xFFFFF },
		//{ "_32_", 0xE0000, 0xFFFFF },
		//{ "$PIR", 0xF0000, 0xFFFFF  },
		//{ "32OS", 0xE0000, 0xFFFFF },
		//{ "\252\125VPD", 0xF0000, 0xFFFFF },
		//{ "FJKEYINF", 0xF0000, 0xFFFFF },
		//{ "_MP_", 0xE0000, 0xFFFFF },
	};

	// VM string list.
	//
	struct vm_identifier_hash
	{
		size_t length;
		xstd::ahash_t hash;
		_CONSTEVAL vm_identifier_hash( const char* str ) : length( xstd::strlen( str ) ), hash( xstd::make_ahash( str ) ) {}
	};
	static constexpr vm_identifier_hash vm_ids[] = {
		"vmware",       // VMware
		"parallels", // Parallels
		"qemu",      // QEMU
		"vbox",      // VBox
		"bochs",     // Bochs
		"openstack", // OpenStack
		"seabios",   // SeaBios
		"innotek",   // Innotek
		"s3 corp",   // S3 Corp
		"red hat"    // KVM
		//"vs20",      // Ms Virtual Server
		//"virtual",   // Generic
		//"bxpc",      // Bochs2
		//"hyper",     // Hyper-V
		//"oracle",    // Oracle
	};

	// Gets the DCI/BIOS identifiers.
	//
	xstd::result<bios_identifiers> get_bios_identifiers()
	{
		bios_identifiers result = {};

		xstd::result<> last_smbios_status = {};
		auto parse_smbios = [ & ] ( uint64_t phys_adr, size_t len )
		{
			// Skip if already parsed.
			//
			if ( last_smbios_status.success() )
				return;

			// Map the range.
			//
			if ( len < sizeof( ia32::smbios::entry_header ) )
			{
				last_smbios_status = xstd::exception{ "Invalid SMBIOS range specified."_es };
				return;
			}
			auto range = ia32::mem::map_physical<char>( phys_adr, len );
			if ( !range )
			{
				last_smbios_status = xstd::exception{ "Failed to map SMBIOS memory."_es };
				return;
			}

			// Try parsing.
			//
			if ( auto res = ia32::smbios::parse( std::string_view{ range.get(), len } ); ( last_smbios_status = res.status ) )
			{
				if ( !res->entries.empty() )
				{
					for ( auto& [type, entry] : res->entries )
					{
						auto parse_asset_tag = [ &, e=&entry ] ( auto& dev )
						{
							if ( auto str = e->resolve( dev.asset_tag ); !str.empty() )
								result.asset_tags.emplace_back( str );
						};

						if ( type == ia32::smbios::memory_device_entry::type_id )
						{
							auto mem_dev = entry.as<ia32::smbios::memory_device_entry>();
							if ( mem_dev.size == 0 )
								continue;
							parse_asset_tag( mem_dev );

							auto& mem = result.memory_devices.emplace_back();
							mem.model = entry.resolve( mem_dev.part_number );
							mem.serial = entry.resolve( mem_dev.serial_number );
						}
						else if ( type == ia32::smbios::baseboard_entry::type_id )
						{
							auto baseboard = entry.as<ia32::smbios::baseboard_entry>();
							result.baseboard.model = entry.resolve( baseboard.product );
							result.baseboard.serial = entry.resolve( baseboard.serial_number );
							parse_asset_tag( baseboard );
						}
						else if ( type == ia32::smbios::sysinfo_entry::type_id )
						{
							auto sysinfo = entry.as<ia32::smbios::sysinfo_entry>();
							result.sys_guid = sysinfo.uuid.to_string();
							result.sys_serial = entry.resolve( sysinfo.serial_number );
						}
						else if ( type == ia32::smbios::system_enclosure_entry::type_id )
						{	
							auto enclosure = entry.as<ia32::smbios::system_enclosure_entry>();
							parse_asset_tag( enclosure );
						}
						else if ( type == ia32::smbios::processor_entry::type_id )
						{
							auto proc = entry.as<ia32::smbios::processor_entry>();
							parse_asset_tag( proc );
						}
					}
				}
				else
				{
					last_smbios_status = xstd::exception{ "SMBIOS table is empty."_es };
				}
			}
		};
		
		// Map the BIOS space.
		//
		auto bios_space = ia32::mem::map_physical<char[]>( bios_space_base, bios_space_length );
		if ( !bios_space )
			return xstd::exception{ "Failed to map BIOS space."_es };

		[ & ]() NO_INLINE {
			// Match strings.
			//
			for ( size_t n = 0; result.is_vm.empty() && n != bios_space_length; n++ )
			{
				auto beg = ( char* ) &bios_space[ n ];
				for ( const vm_identifier_hash& id : vm_ids )
				{
					if ( ( n + id.length ) > bios_space_length )
						continue;
					if ( xstd::make_ahash( std::string_view{ beg, beg + id.length } ) == id.hash )
					{
						result.is_vm.assign( beg, beg + id.length );
						break;
					}
				}
			}

			// Find all anchors.
			//
			for ( auto& [anchor, low, high] : entry_points )
			{
				for ( size_t n = low; n <= ( high - 0x10 ); n += 0x10 )
				{
					if ( !memcmp( &bios_space[ n - bios_space_base ], anchor.data(), anchor.size() ) )
					{
						// If SMBIOS anchor, parse the SMBIOS.
						//
						if ( anchor == ia32::smbios::anchor_v2 )
						{
							ia32::smbios::entry_point_v2* ep = ( any_ptr ) &bios_space[ n - bios_space_base ];
							if ( std::next( ep ) <= ( void* ) &bios_space[ bios_space_length ] && 
								  xstd::ptr_at( ep, ep->ep_length ) <= ( void* ) &bios_space[ bios_space_length ] )
							{
								if ( ia32::smbios::checksum( ep ) )
									parse_smbios( ep->address, ep->total_length );
							}
						}
						else if ( anchor == ia32::smbios::anchor_v3 )
						{
							ia32::smbios::entry_point_v3* ep = ( any_ptr ) &bios_space[ n - bios_space_base ];
							if ( std::next( ep ) <= ( void* ) &bios_space[ bios_space_length ] &&
								  xstd::ptr_at( ep, ep->ep_length ) <= ( void* ) &bios_space[ bios_space_length ] )
							{
								if ( ia32::smbios::checksum( ep ) )
									parse_smbios( ep->address, ep->total_length );
							}
						}
					}
				}
			}
		}();

		// Parse the WMIp saved SMBIOS range.
		//
		uint64_t smbios_physical_address = *( uint64_t* ) &wmip::sm_bios_table_physical_address;
		uint32_t smbios_length = *( uint32_t* ) &wmip::sm_bios_table_length;
		if ( smbios_physical_address != 0 )
		{
			if ( smbios_physical_address > 4_gb )
				result.is_tampered = true;
			parse_smbios( smbios_physical_address, smbios_length );
		}

		// Save the CMOS serial.
		//
		std::array<uint8_t, 6> cmos_serial = {};
		ia32::cmos_io_space.read_range( cmos_serial.data(), 0x41, cmos_serial.size() );
		result.cmos_serial = xstd::fmt::as_hex_string( cmos_serial );

		// Return the result.
		//
		if ( result.is_vm.empty() && !result.is_tampered && last_smbios_status.fail() )
			return last_smbios_status.status;
		else
			return result;
	}
};