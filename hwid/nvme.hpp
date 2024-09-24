#pragma once
#include <string>
#include <xstd/type_helpers.hpp>
#include <xstd/bitwise.hpp>
#include <xstd/xvector.hpp>
#include <ia32/iospace.hpp>
#include <ia32/pci.hpp>
#include <ia32/memory.hpp>
#include <bus/stor.hpp>
#include "disk_id.hpp"
#include "../upause.hpp"

namespace nvme
{
	// Identifies the NVME drive under the given controller.
	// - Return value indicates whether or not the operation should be retried.
	//
	[[no_obfuscate]] inline bool identify( hwid::disk_set& result, const ia32::pci::device& device )
	{
		// Get the MBAR.
		//
		uint64_t mbar = device.read_cfg<uint64_t>( mbar_register );
		if ( !uint32_t( mbar ) || uint32_t( mbar ) == 0xFFFFFFFF )
			return true;

		// Map the physical address to access the device registers.
		//
		mbar &= ~0xFFFull;
		auto bar = ia32::mem::map_physical<volatile bar_registers>( mbar );
		if ( !bar )
			return true;

		// Fail if probe fails.
		//
		auto probe_begin = ( volatile uint32_t* ) bar.get();
		auto probe_end = ( volatile uint32_t* ) probe_begin + ( sizeof( bar_registers ) / sizeof( uint32_t ) );
		if ( std::all_of( probe_begin, probe_end, [ ] ( uint32_t v ) { return v == 0xFFFFFFFF; } ) )
			return true;

		// Return if controller is disabled.
		//
		if ( !( bar->cc_config & 1 ) || !( bar->cc_status & 1 ) )
			return true;

		// Map the admin submission and completion queues.
		//
		size_t aqs_len = bar->aq_submit_size;
		size_t aqc_len = bar->aq_complete_size;
		if ( aqs_len != aqc_len )
			return false;
		uint64_t aqs_base = bar->aq_submit_lo   | ( uint64_t( bar->aq_submit_hi )   << 32 );
		uint64_t aqc_base = bar->aq_complete_lo | ( uint64_t( bar->aq_complete_hi ) << 32 );
		auto aqs = ia32::mem::map_physical<submission_entry[]>( aqs_base, sizeof( submission_entry ) * aqs_len );
		auto aqc = ia32::mem::map_physical<completion_entry[]>( aqc_base, sizeof( completion_entry ) * aqc_len );
		if ( !aqc || !aqs )
			return false;
		const auto queue_index = [ & ] ( uint32_t x ) { return x == aqc_len ? 0 : x; };

		// Map the doorbells.
		//
		uint64_t doorbell_stride = 4 << bar->doorbell_stride;
		auto aqs_tail_doorbell = ia32::mem::map_physical<volatile uint32_t>( mbar + 0x1000 + doorbell_stride * ( 2 * 0 ) );
		auto aqc_head_doorbell = ia32::mem::map_physical<volatile uint32_t>( mbar + 0x1000 + doorbell_stride * ( 2 * 0 + 1 ) );
		if ( !aqs_tail_doorbell || !aqc_head_doorbell )
			return false;

		// Reserve space for the queue backups.
		//
		//auto aqc_backup = std::make_unique_for_overwrite<completion_entry[]>( aqc_len );
		//auto aqs_backup = std::make_unique_for_overwrite<submission_entry[]>( aqs_len );

		// Zero out the previous buffer.
		//
		volatile auto* id_space = hwid::identification_space;
		memset( ( void* ) &id_space[ 0 ], 0, 0x1000 );
		ia32::mfence();

		// Disable interrupts.
		//
		ia32::disable();

		// Backup queue states.
		//
		//memcpy( aqc_backup.get(), &aqc[ 0 ], sizeof( nvme::completion_entry ) * aqc_len );
		//memcpy( aqs_backup.get(), &aqs[ 0 ], sizeof( nvme::submission_entry ) * aqs_len );
		
		// Find the position where phase is flipped and guess queue state.
		//
		size_t flip_pos = 0;
		bool zp_phase = aqc[ 0 ].phase;
		for ( size_t n = 1; n != aqc_len; n++ )
		{
			if ( aqc[ n ].phase != zp_phase )
			{
				flip_pos = n;
				break;
			}
		}
		size_t prev_c_head = flip_pos;
		size_t prev_s_tail = aqc[ flip_pos - 1 ].submit_head;

		// Helper to fill the command queue.
		//
		auto fill_command_queue = [ & ] ( nvme::submission_entry e )
		{
			for ( size_t i = 0; i != aqs_len; i++ )
				aqs[ i ] = e;
		};

		
		// Create and write the identification command.
		//
		nvme::submission_entry id_command = {};
		id_command.opcode = 6; // Identify
		id_command.psdt = data_transfer_type::prp_prp;
		id_command.data_pointers[ 0 ] = ia32::mem::get_physical_address( id_space );
		id_command.command_info[ 0 ] = 1; // The controller. (0= ns, 2=ns list)
		fill_command_queue( id_command );
		ia32::mfence();

		// Issue it.
		//
		*aqs_tail_doorbell = queue_index( prev_s_tail + 1 );
		ia32::mfence();

		// Wait up to 100ms to for a response.
		//
		const auto id_waiter = [ & ] () { return ( *( volatile uint32_t* ) &id_space[ 4 ] ) != 0; };
		bool id_complete = util::upause( 100ms, id_waiter );

		// Acknowledge either way.
		//
		*aqc_head_doorbell = queue_index( prev_c_head + 1 );
		ia32::mfence();

		// If not complete:
		//
		if ( !id_complete )
		{
			*aqs_tail_doorbell = queue_index( prev_s_tail + 2 );
			ia32::mfence();
			id_complete = util::upause( 100ms, id_waiter );
			*aqc_head_doorbell = queue_index( prev_c_head + 2 );
			ia32::mfence();
		}

		// Nop the command queue.
		//
		fill_command_queue( { .opcode = 0x18 } );

		// Reference the completion entry we're expecting the controller to wrap around.
		//
		volatile auto& wrce = aqc[ prev_c_head ? prev_c_head - 1 : ( aqc_len - 1 ) ];
		bool wrce_prev_phase = wrce.phase;
		ia32::mfence();

		// Restore the submission queue doorbell.
		//
		*aqs_tail_doorbell = queue_index( prev_s_tail );
		ia32::mfence();

		// Sleep until the buffer wraps.
		//
		util::upause( 100ms, [ & ] () { return wrce.phase != wrce_prev_phase; } );

		// Restore the completion queue doorbell.
		//
		*aqc_head_doorbell = queue_index( prev_c_head );
		ia32::mfence();

		// Enable interrupts again.
		//
		ia32::enable();

		// Interprete the result.
		//
		if ( !id_complete )
		{
			//printf( "---------- No response ---------------\n" );
			//printf( "=> %s\n", xstd::fmt::hex_dump( ( char* ) id_space, 100 ).data() );
			//
			//printf( "flip_pos:    0x%llx\n", flip_pos );
			//printf( "prev_c_head: 0x%llx\n", prev_c_head );
			//printf( "prev_s_tail: 0x%llx\n", prev_s_tail );
			//for ( size_t i = 0; i != aqc_len; i++ )
			//	printf( "Completion queue #%02x: Cid:%04x | Head:%04x | Phase %d\n", i, aqc_backup[ i ].cid, aqc_backup[ i ].submit_head, aqc_backup[ i ].phase );
			return true;
		}

		// Normalize the strings.
		//
		std::string_view sn{ ( char* ) &id_space[ 4 ], 20 };
		std::string_view mn{ ( char* ) &id_space[ 24 ], 40 };
		for ( auto s : { &sn, &mn } )
			while ( !s->empty() && ( s->back() == ' ' || s->back() == '\x0' ) )
				s->remove_suffix( 1 );

		hwid::disk_identifier id = {
			device.config.vendor_id,
			device.config.device_id,
			device.subsystem,
			device.config.revision_id,
			( uint8_t ) device.address.function,
			( uint8_t ) device.address.bus,
			( uint8_t ) device.address.device,
			std::string{ mn }, std::string{ sn }
		};
		result.insert( std::move( id ) );
		return false;
	}
};