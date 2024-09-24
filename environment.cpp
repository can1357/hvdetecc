#include <string_view>
#include <ia32.hpp>
#include <ia32/memory.hpp>
#include <xstd/text.hpp>
#include <xstd/hashable.hpp>
#include <ntpp.hpp>
#include <ntpp/ci.hpp>
#include <sdk/kuser/api.hpp>
#include <sdk/hal/api.hpp>
#include <sdk/nt/work_queue_item_t.hpp>
#include <sdk/nt/device_object_t.hpp>
#include <sdk/nt/devobj_extension_t.hpp>
#include <sdk/nt/driver_object_t.hpp>

// Validates the system environment.
//
extern "C" [[gnu::dllexport]] transport::packet* envValidate()
{
	cbor::array_t detections = {};

	// Find the patchguard context.
	//
	auto* nt_base = *( win::image_x64_t** ) &ps::ntos_image_base;
	auto* nt_hdrs = nt_base->get_nt_headers();
	void** pg_context = nullptr;
	for ( auto& scn : nt_hdrs->sections() )
	{
		if ( xstd::make_ahash( scn.name.to_string() ) != ".data"_ahash )
			continue;

		// Find the fixed context data.
		//
		const void* ctx_suffix[] =
		{
			&ke::bug_check_ex,
			&ke::bug_check2,
			&ki::bug_check_debug_break
		};
		auto begin = nt_base->raw_to_ptr<uint8_t>( scn.virtual_address );
		auto end = nt_base->raw_to_ptr<uint8_t>( scn.virtual_address + std::min( scn.virtual_size, scn.size_raw_data ) );
		auto it = std::search( begin + 8, end, ( const uint8_t* ) std::begin( ctx_suffix ), ( const uint8_t* ) std::end( ctx_suffix ) );
		if ( it == end )
			continue;

		pg_context = ( void** ) ( it - 8 );
		break;
	}

	// Patchguard should be setting the offset 0x00, if not set, it never ran.
	//
	if ( pg_context && !*pg_context )
		detections.emplace_back( cbor::object_t{ { "flag", "pg.noPgBoot" } } );

	// Verify the code integrity of every driver.
	//
	for ( ldr::km::data_table_entry_t* img : ntpp::module_list{} )
	{
		// Read the image.
		//
		std::wstring_view full_path{ img->full_dll_name };
		auto data = ntpp::read_file( full_path );
		if ( !data )
		{
			// If this is a dump driver, try finding the real entry.
			//
			if ( size_t n = full_path.find( L"\\dump_" ); n != std::string::npos )
			{
				std::wstring new_path{ full_path };
				new_path.erase( n + xstd::strlen( L"\\dump" ), 1 );
				if ( data = ntpp::read_file( new_path ); !data )
				{
					new_path.erase( n + 1, xstd::strlen( L"dump" ) );
					data = ntpp::read_file( new_path );
				}
			}
		}

		// If we could read it:
		//
		if ( data )
		{
			// Skip if the checksum does not match.
			//
			auto* mem_img = ( const win::image_x64_t* ) img->dll_base;
			auto* fs_img = ( const win::image_x64_t* ) data->data();
			if ( mem_img->get_nt_headers()->optional_header.checksum != fs_img->get_nt_headers()->optional_header.checksum )
				continue;

			// If image hash does not match, add as a detection.
			//
			if ( !ntpp::ci::compare( mem_img, fs_img ) )
			{
				detections.emplace_back( cbor::object_t {
					{ "flag",      xstd::fmt::str( "img.patch.%s", img->base_dll_name ) },
					{ "imageBase", ( uint64_t ) img->dll_base                              },
				} );
			}
		}
	}

	// Verify the code integrity of every driver dispatch table.
	//
	uint16_t pxi_k = ia32::mem::px_index( ( void* ) &ps::ntos_image_base );
	uint16_t pxi_s = ia32::mem::px_index( ( void* ) &kuser::get_parent );
	ntpp::query_object_directory( L"\\Driver", [ & ] ( win::object_directory_information_t* info )
	{
		std::wstring driver_name = L"\\Driver\\"s += info->name.get();
		if ( auto drv_object = ntpp::reference_object_by_name<nt::driver_object_t>( driver_name ) )
		{
			for ( auto& entry : drv_object->major_function )
			{
				if ( entry && ia32::mem::px_index( entry ) != pxi_s && ia32::mem::px_index( entry ) != pxi_k )
				{
					detections.emplace_back( cbor::object_t {
						{ "flag",      xstd::fmt::str( "img.dispatchHijacked.%s", info->name ) },
						{ "imageBase", ( uint64_t ) drv_object->driver_start },
					} );
				}
			}
		}
	} );

	// Verify the integrity of HAL dispatch tables.
	//
	for ( auto [tbl, size] : { std::make_pair( ( void** ) &hal::dispatch_table,         0xa8 ),
                              std::make_pair( ( void** ) &hal::private_dispatch_table, 0x300 ) } )
	{
		// Skip if it does not exist.
		//
		if ( !size )
			break;

		// Else, first 8 bytes have the version, rest is an array of u64 values.
		//
		size = ( size / 8 ) - 1;
		tbl += 1;

		// Iterate every value:
		//
		for ( size_t n = 0; n != size; n++ )
		{
			// Skip if non-cannonical or null.
			//
			if ( !tbl[ n ] || !ia32::mem::is_cannonical( tbl[ n ] ) )
				continue;

			// If not in kernel space, mark as a detection.
			//
			if ( ia32::mem::px_index( tbl[ n ] ) != pxi_k )
				detections.emplace_back( cbor::object_t{ { "flag",  xstd::fmt::str( "hal.hook.%llu", n ) } } );
		}
	}

	// Return the serialized result.
	//
	return transport::serialize( std::move( detections ) );
}

// Takes a list of image bases for the drivers we'd like to unload and returns the list of each driver we've failed to unload.
//
extern "C" [[gnu::dllexport]] transport::packet* envUnloadDriver( cbor::instance * input )
{
	// Create a list of unload requests.
	//
	std::vector<any_ptr> images;
	images.reserve( input->array().size() );
	for ( auto& img_base : input->array() )
		images.emplace_back( img_base.integer() );

	// Define the unload helper.
	//
	auto try_unload = [ ] ( any_ptr img, bool seriously ) -> xstd::result<> {
		// See if this driver is really loaded.
		//
		bool loaded = false;
		for ( auto&& mod : ntpp::module_list{} ) {
			if ( img == mod->dll_base ) {
				loaded = true;
				break;
			}
		}
		if ( !loaded ) return std::monostate{};

		// Try to find the driver object.
		//
		ntpp::ref<nt::driver_object_t> obj = {};
		ntpp::query_object_directory( L"\\Driver", [ & ] ( win::object_directory_information_t* info )
		{
			if ( obj ) return;
			std::wstring driver_name = L"\\Driver\\"s += info->name.get();
			if ( auto drv_object = ntpp::reference_object_by_name<nt::driver_object_t>( driver_name ) ) {
				if ( drv_object->driver_start == img ) {
					obj = std::move( drv_object );
				}
			}
		} );
		if ( !obj ) return xstd::exception{ "Can't find driver object associated."_es };

		// Close all handles associated with the driver.
		//
		ntpp::close_handle_if( [ & ] ( nt::handle_table_entry_t* entry ) {
			if ( auto* fo = ntpp::dyn_cast< nt::file_object_t >( ntpp::resolve_handle_table_entry<ntpp::table_type::handle_table>( entry ) ) ) {
				nt::device_object_t* dev = ntpp::get_related_device_object( fo );
				return dev && dev->driver_object == obj.get();
			}
			return false;
		} );

		// Get the unload result.
		//
		auto unload_result = ntpp::unload_driver( obj, seriously );

		// Kill the driver anyway.
		//
		for ( auto& fn : obj->major_function )
			if ( &fn != &obj->major_function[ IRP_MJ_CLOSE ] &&
				  &fn != &obj->major_function[ IRP_MJ_SHUTDOWN ] &&
				  &fn != &obj->major_function[ IRP_MJ_CLEANUP ] &&
				  &fn != &obj->major_function[ IRP_MJ_PNP ] &&
				  &fn != &obj->major_function[ IRP_MJ_POWER ] )
				fn = ( any_ptr ) ( void* ) &iop::invalid_device_request;

		// Return a pending driver since it was still in the list and has to be checked again.
		//
		if ( unload_result ) {
			return xstd::exception{ "Unload pending."_es };
		} else {
			return unload_result;
		}
	};

	// Start the attempt loop.
	//
	cbor::array_t error_list = {};
	for ( size_t n = 0;; n++ ) {
		bool last = n >= 20;
		bool seriously = n >= 15;

		// For each driver:
		//
		std::erase_if( images, [ & ] ( any_ptr ptr ) {
			auto result = try_unload( ptr, seriously );
			if ( result.success() ) return true;

			if ( last ) {
				error_list.emplace_back( cbor::instance{
					{ "base", ptr.address },
					{ "error", result.status.to_string() }
				} );
			}

			return false;
		} );

		if ( last ) break;
	}
	return transport::serialize( std::move( error_list ) );
}
