#include <string_view>
#include <ia32.hpp>
#include <ia32/pci.hpp>
#include <xstd/text.hpp>
#include <xstd/guid.hpp>
#include <xstd/sha256.hpp>
#include <xstd/hashable.hpp>
#include <ntpp.hpp>
#include "hwid/bios.hpp"
#include "hwid/fs_footprint.hpp"
#include "hwid/disk_id.hpp"
#include "hwid/third_party.hpp"
#include <sdk/netio/api.hpp>
#include <sdk/win/key_basic_information_t.hpp>
#include <sdk/nt/functional_device_extension_t.hpp>
#include <bus/stor.hpp>

struct stor_scsi_address_t
{
	uint8_t path_id;    //{ +0x0000    +0x0000    +0x0000    } | .PathId
	uint8_t target_id;  //{ +0x0001    +0x0001    +0x0001    } | .TargetId
	uint8_t lun;        //{ +0x0002    +0x0002    +0x0002    } | .Lun
};

static constexpr auto dev2json = [ ] ( auto&& dev )
{
	return cbor::object_t {
		{ "model",   std::move( dev.model ) },
		{ "serial",  std::move( dev.serial ) }
	};
};
static constexpr auto reg2json = [ ] ( std::wstring_view key, std::wstring_view value ) -> cbor::instance
{
	if ( auto hkey = ntpp::open_key( key ) )
	{
		if ( auto val = ntpp::query_key_value( hkey->get(), value ) )
		{
			switch ( val->type )
			{
				case REG_QWORD:			   return ( uint64_t ) xstd::ref_at<uint64_t>( &val->data );
				case REG_DWORD:            return ( uint64_t ) xstd::ref_at<uint32_t>( &val->data );
				case REG_DWORD_BIG_ENDIAN: return ( uint64_t ) bswap( xstd::ref_at<uint32_t>( &val->data ) );
				case REG_SZ:
				case REG_MULTI_SZ:
				{
					wchar_t* data = xstd::ptr_at<wchar_t>( &val->data );
					wchar_t* data_end = data + ( val->data_length / 2 );

					if ( val->type == REG_SZ ) {
						return cbor::instance{ std::wstring{ data, std::find( data, data_end, 0 ) } };
					}
					else {
						std::vector<std::wstring> list;
						while ( data < data_end )
						{
							auto item_end = std::find( data, data_end, 0 );
							list.push_back( { data, item_end } );
							data = item_end + 1;
						}
						if ( list.back().empty() )
							list.pop_back();
						if ( list.size() == 1 )
							return cbor::instance{ std::move( list.front() ) };
						else if ( list.size() == 0 )
							return cbor::instance{ cbor::string_t{} };
						return cbor::instance( std::move( list ) );
					}
				}
				default:
				{
					return std::vector<uint8_t>{ &val->data[ 0 ], &val->data[ val->data_length ] };
				}
			}
		}
	}
	return cbor::null_t{};
};

template<typename E>
static void reg_enum( std::wstring_view ws, E&& enumerator ) {
	std::wstring tmp{ws};
	tmp += L"\\";
	size_t base_size = tmp.size();

	if ( auto root = ntpp::open_key( ws ) )
	{
		for ( size_t n = 0;; n++ )
		{
			auto bi = ntpp::query_subkey_info<win::key_basic_information_t>( root->get(), n, nt::key_information_class_t::key_basic_information );
			if ( !bi )
				break;
			tmp.resize( base_size );
			tmp.insert( tmp.end(), &bi->name[ 0 ], &bi->name[ bi->name_length / 2 ] );
			if ( auto child = ntpp::open_key( tmp ) ) {
				enumerator( child->get(), std::wstring_view{ tmp }, std::wstring_view{ &bi->name[ 0 ], &bi->name[ bi->name_length / 2 ] } );
			}
		}
	}
}

#pragma pack(push, 1)
namespace net
{
	struct ipv4_address
	{
		std::array<uint8_t, 4> values = { 0 };
		uint32_t& as_int() { return *( uint32_t* ) &values; }
		const uint32_t& as_int() const { return *( const uint32_t* ) &values; }
		auto tie() { return std::tie( as_int() ); }
		constexpr auto operator<=>( const ipv4_address& ) const = default;
		explicit operator bool() const { return as_int() != 0; }
	};
	struct mac_address_t
	{
		std::array<uint8_t, 6> values = { 0 };
		constexpr auto tie() { return std::tie( values ); }
		constexpr auto operator<=>( const mac_address_t& ) const = default;
		constexpr explicit operator bool() const { return values != mac_address_t{}.values; }
	};
};
#pragma pack(pop)

namespace netio
{
	#pragma pack(push, 1)
	struct net_luid_t
	{
		uint64_t rsvd : 24;
		uint64_t net_luid_index : 24;
		uint64_t if_type : 16;
	};
	struct sockaddr_in4_t
	{
		uint16_t          family;
		uint16_t          port;
		net::ipv4_address addr;
		uint8_t           zero[ 8 ];
	};
	struct sockaddr_in6_t
	{
		uint16_t family;
		uint16_t port;
		uint32_t flowinfo;
		uint64_t addr[ 2 ];
		uint32_t scope_id;
	};
	union sockaddr_inet_t
	{
		uint16_t       family;
		sockaddr_in4_t ip4;
		sockaddr_in6_t ip6;
	};
	static_assert( sizeof( sockaddr_inet_t ) == 0x1C );
	#pragma pack(pop)

	#pragma pack(push, 8)
	template<typename T>
	struct mib_table
	{
		uint32_t count;
		uint32_t __pad;
		T        table[ 1 ];

		T* begin() { return &table[ 0 ]; }
		const T* begin() const { return &table[ 0 ]; }
		T* end() { return &table[ count ]; }
		const T* end() const { return &table[ count ]; }
		size_t size() const { return count; }

		void operator delete( void* p ) { netio::free_mib_table( p ); }
	};
	enum class nl_neighbor_state_t {
		unreachable,
		incomplete,
		probe,
		delay,
		stale,
		reachable,
		permanent,
	};
	struct mib_ipnet_t {
		sockaddr_inet_t     address;
		uint32_t            interface_index;
		net_luid_t          interface_luid;
		union {
			uint8_t             physical_address[ 32 ];
			net::mac_address_t  mac_address;
		};
		uint32_t            physical_address_length;
		nl_neighbor_state_t state;
		uint8_t             is_rounter : 1;
		uint8_t             is_unreachable : 1;
		uint8_t             rsvd : 6;
		uint32_t            last_reachable_unreachable;

		static std::unique_ptr<mib_table<mib_ipnet_t>> query( uint32_t af = AF_UNSPEC )
		{
			mib_table<mib_ipnet_t>* tbl = nullptr;
			netio::get_ip_net_table2( af, ( any_ptr ) &tbl );
			return std::unique_ptr<mib_table<mib_ipnet_t>>{ tbl };
		}
	};
	static_assert( sizeof( mib_ipnet_t ) == 0x58 );
	#pragma pack(pop)
};

// Gets identifiers from the network interfaces.
//
extern "C" [[gnu::dllexport, virtualize]] transport::packet* hwidCollectNet()
{
	cbor::instance result = {};
	auto& data = result[ "data" ].object();
	auto& net = data[ "net" ].object();

	// Query all neighbors.
	//
	if ( auto ipnet = netio::mib_ipnet_t::query( AF_INET ) )
	{
		auto& neighbors = net[ "neighbours" ].array();
		int classcounter = 0;
		for ( auto& u : *ipnet )
		{
			// Skip:
			//  Multicast: 224.0.0.0 through 239.255.255.25.
			//
			if ( 224 <= u.address.ip4.addr.values[ 0 ] && u.address.ip4.addr.values[ 0 ] <= 239 )
				continue;
			// Skip null/full.
			//
			if ( !u.address.ip4.addr.as_int() || u.address.ip4.addr.as_int() == 0xFFFFFFFF || *( uint32_t* ) &u.physical_address[ 0 ] == 0xFFFFFFFF || *( uint32_t* ) &u.physical_address[ 0 ] == 0 )
				continue;

			// Skip invalid MAC.
			//
			if ( u.physical_address_length != 6 )
				continue;

			// Inc/dec if 10.0.0.0 block.
			//
			classcounter += u.address.ip4.addr.values[ 0 ] == 10 ? +1 : -1;

			// Write the entry.
			//
			cbor::object_t obj = {};
			obj[ "ip" ] = bswapd( u.address.ip4.addr.as_int() );
			obj[ "phys" ] = std::vector<uint8_t>{ u.mac_address.values.begin(), u.mac_address.values.end() };
			neighbors.emplace_back( std::move( obj ) );
		}
	}
	return transport::serialize( result );
}

// Get the identifiers from UEFI.
//
extern "C" [[gnu::dllexport, virtualize]] transport::packet* hwidCollectUefi()
{
	cbor::instance result = {};
	auto& data = result[ "data" ].object();
	auto& errors = result[ "errors" ].object();

	// If UEFI firmware:
	//
	if ( ex::get_firmware_type() == nt::firmware_type_t::uefi )
	{
		auto& uefi = data[ "uefi" ].object();
		if ( auto values = ntpp::query_system_environment_values() )
		{
			std::span<uint8_t> offline_unique_id = {};
			std::span<uint8_t> platform_key = {};
			std::span<uint8_t> unlock_id = {};
			std::span<uint8_t> language = {};

			for ( auto it = std::to_address( values ); it; it = it->next_entry_offset ? xstd::ptr_at( it, it->next_entry_offset ) : any_ptr{ 0ull } )
			{
				auto data = xstd::ptr_at( it, it->value_offset );
				std::span<uint8_t> range = { ( uint8_t* ) data, it->value_length };

				switch ( xstd::make_ahash( &it->name[ 0 ] ).as64() )
				{
					case L"PK"_ahash:                        platform_key = range;      break;
					case L"Lang"_ahash:                      language = range;          break;
					case L"UnlockIDCopy"_ahash:              unlock_id = range;         break;
					case L"OfflineUniqueIDRandomSeed"_ahash: offline_unique_id = range; break;
					default: break;
				}
			}
			if ( !language.empty() )
			{
				auto end = std::find( language.begin(), language.end(), '\x0' );
				uefi[ "language" ] = std::string{ language.begin(), end };
			}
			if ( !platform_key.empty() ) uefi[ "platformKeyHash" ] = xstd::make_hash<xstd::sha256>( platform_key ).to_string();
			if ( !unlock_id.empty() ) uefi[ "unlockIdHash" ] = xstd::make_hash<xstd::sha256>( unlock_id ).to_string();
			if ( !offline_unique_id.empty() ) uefi[ "offlineUniqueIdHash" ] = xstd::make_hash<xstd::sha256>( offline_unique_id ).to_string();
		}
		else
		{
			errors[ "uefiError" ] = values.status.to_string();
		}
	}

	return transport::serialize( result );
}

// Gets BIOS and CPU identifiers.
//
extern "C" [[gnu::dllexport, virtualize]] transport::packet* hwidCollectCpuBios()
{
	cbor::instance result = {};
	auto& data = result[ "data" ].object();
	auto& errors = result[ "errors" ].object();
	auto& flags = result[ "flags" ].array();

	// Get the CPU details.
	//
	data[ "cpuBrand" ] = ia32::get_brand();
	data[ "cpuHash" ] =  xstd::make_hash<xstd::fnv64>( ia32::static_cpuid<0x1, 0>[ 0 ], ia32::static_cpuid<0x0, 0>[ 0 ] ).as64();

	// Get the BIOS identifiers.
	//
	if ( auto bios_id = hwid::get_bios_identifiers() )
	{
		auto& bios = data[ "bios" ];
		if ( bios_id->is_tampered )
			flags.push_back( "spoofing.smbiosTampered" );
		if ( !bios_id->is_vm.empty() )
			flags.push_back( "vm.smbiosType1." + bios_id->is_vm );

		bios[ "cmosSerial" ] = bios_id->cmos_serial;
		bios[ "biosGuid" ] = bios_id->sys_guid;
		bios[ "biosSerial" ] = bios_id->sys_serial;
		bios[ "baseboardModel" ] = bios_id->baseboard.model;
		bios[ "baseboardSerial" ] = bios_id->baseboard.serial;


		auto& mem_list = bios[ "memoryDevices" ].array();
		for ( auto& mem : bios_id->memory_devices )
			mem_list.emplace_back( dev2json( std::move( mem ) ) );

		auto& tag_list = bios[ "assetTags" ].array();
		std::sort( bios_id->asset_tags.begin(), bios_id->asset_tags.end() );
		auto unique_end = std::unique( bios_id->asset_tags.begin(), bios_id->asset_tags.end() );
		for ( auto& tag : std::span{ bios_id->asset_tags.begin(), unique_end } )
			tag_list.emplace_back( std::move( tag ) );

		if ( !tag_list.empty() )
			flags.emplace_back( "corporate.smbiosAssetTag" );
	}
	else
	{
		errors[ "biosError" ] = bios_id.status;
	}

	return transport::serialize( result );
}

// Gets identifiers from the PCI devices.
//
extern "C" [[gnu::dllexport, virtualize]] transport::packet* hwidCollectPci()
{
	cbor::instance result = {};
	auto& data = result[ "data" ].object();
	auto& flags = result[ "flags" ].array();

	// Get all PCI devices.
	//
	auto& pci_devices = ia32::pci::get_device_list();
	if ( !pci_devices.empty() )
	{
		auto& pci_list = data[ "pci" ].array();
		bool is_vm = false;
		bool has_gpu = false;
		for ( auto& dev : pci_devices )
		{
			cbor::object_t obj = {};
			obj[ "vendor" ] = dev.config.vendor_id;
			obj[ "device" ] = dev.config.device_id;
			if ( dev.subsystem ) obj[ "subsystem" ] = dev.subsystem;
			obj[ "class" ] = dev.config.class_code;
			obj[ "subclass" ] = dev.config.sub_class_code;
			obj[ "pciFun" ] = ( uint8_t ) dev.address.function;
			obj[ "pciBus" ] = ( uint8_t ) dev.address.bus;
			obj[ "pciDev" ] = ( uint8_t ) dev.address.device;
			pci_list.emplace_back( std::move( obj ) );

			is_vm |= dev.config.vendor_id == 0x15ad;
			if ( dev.config.class_code == PCI_BASE_CLASS_DISPLAY )
			{
				has_gpu |=
					dev.config.vendor_id == 0x1002 ||
					dev.config.vendor_id == 0x1022 ||
					dev.config.vendor_id == 0x8086 ||
					dev.config.vendor_id == 0x10de;
			}
		}
		if ( is_vm )    flags.push_back( "vm.vmwarePci" );
		if ( !has_gpu ) flags.push_back( "vm.pciNoGpu" );
	}

	return transport::serialize( result );
}
