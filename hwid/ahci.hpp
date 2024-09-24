#pragma once
#include <string>
#include <xstd/type_helpers.hpp>
#include <xstd/bitwise.hpp>
#include <ia32/iospace.hpp>
#include <ia32/pci.hpp>
#include <ia32/memory.hpp>
#include <bus/stor.hpp>
#include "disk_id.hpp"
#include "../upause.hpp"

namespace ahci
{
	struct identify_request
	{
		hba_command_table   table;
		ata::identification  identity;
	};

	// Identifies all devices under the given AHCI controller.
	// - Return value indicates whether or not the operation should be retried.
	//
	[[no_obfuscate]] inline bool identify( hwid::disk_set& result, const ia32::pci::device& device )
	{
		// Get the ABAR.
		//
		uint32_t abar = device.read_cfg<uint32_t>( abar_register );
		if ( !abar || abar == 0xFFFFFFFF )
			return true;

		// Map the physical address to access the HBA registers.
		//
		auto hba = ia32::mem::map_physical<volatile hba_registers>( abar & ~0xFFFu );
		if ( !hba )
			return true;

		// Fail if probe fails.
		//
		auto probe_begin = ( volatile uint32_t* ) hba.get();
		auto probe_end = ( volatile uint32_t* ) probe_begin + ( std::min( 0x400ull, sizeof( hba_registers ) ) / sizeof(uint32_t) );
		if ( std::all_of( probe_begin, probe_end, [ ] ( uint32_t v ) { return v == 0xFFFFFFFF; } ) )
			return true;

		// Fail if AHCI is not enabled or if the device is not configured to support 64-bit addressing.
		//
		if ( !( hba->caps.global_host_control >> 31 ) || !( hba->caps.host_capabilities >> 31 ) )
			return true;

		// Enumerate implemented ports:
		//
		bool fail = false;
		xstd::bit_enum( hba->caps.ports_implemented, [ & ] ( bitcnt_t bit )
		{
			// Skip if signature is invalid.
			//
			auto* port = &hba->ports[ bit ];
			if ( port->signature == 0xFFFFFFFF )
				return;
		
			// Read the command list.
			//
			uint64_t command_list = port->command_list_lo;
			command_list |= uint64_t( port->command_list_hi ) << 32;

			// Find an empty slot.
			//
			bitcnt_t slot = xstd::lsb( ~( port->sata_active | port->command_issue ) );
			if ( slot == -1 )
			{
				fail = true;
				return;
			}

			// Validate and map the command list.
			//
			if ( !command_list || !xstd::is_aligned( command_list, alignof( hba_command_list ) ) )
			{
				fail = true;
				return;
			}
			auto cmd_list = ia32::mem::map_physical<hba_command_list>( command_list );
			if ( !cmd_list )
			{
				fail = true;
				return;
			}

			// Reset the ID space.
			//
			auto* id = ( identify_request* ) hwid::identification_space;
			memset( id, 0, sizeof( identify_request ) );

			// Ready the first command slot.
			//
			auto* cmd = &cmd_list->commands[ 0 ];
			memset( cmd, 0, sizeof( hba_command_header ) );
			cmd->command_table_base = ia32::mem::get_physical_address( &id->table );
			cmd->fis_length = sizeof( fis_h2d ) / 4;
			cmd->write = false;
			cmd->len_prdt = 1;

			// Write the FIS.
			//
			auto* fis = ( fis_h2d* ) &id->table.fis;
			fis->type = fis_type::reg_h2d;
			fis->c = true;
			fis->command = ata::identification::opcode;

			// Write the PRDT describing the output.
			//
			auto prdt = &id->table.prdt[ 0 ];
			prdt->data_base = ia32::mem::get_physical_address( &id->identity );
			prdt->length = sizeof( ata::identification ) - 1;
			prdt->interrupt = false;
			ia32::sfence();

			// Issue the command and wait for 100ms.
			//
			const uint32_t slot_flag = 1u << slot;
			port->command_issue |= slot_flag;

			// Fail if it timed out.
			//
			if ( !util::upause( 100ms, [ & ] () { return ( port->command_issue & slot_flag ) == 0; } ) )
			{
				port->command_issue &= ~slot_flag;
				return;
			}

			// Save the identification.
			//
			hwid::disk_identifier entry = { 
				device.config.vendor_id,
				device.config.device_id,
				device.subsystem,
				device.config.revision_id,
				( uint8_t ) device.address.function,
				( uint8_t ) device.address.bus,
				( uint8_t ) device.address.device,
				id->identity.model_number.to_string(), 
				id->identity.serial_number.to_string() 
			};
			if ( !entry.model.empty() && !entry.serial.empty() )
				result.insert( std::move( entry ) );
		} );
		return fail;
	}
};
