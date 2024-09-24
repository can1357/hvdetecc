#include "disk_id.hpp"
#include <ia32/pci.hpp>
#include <xstd/random.hpp>
#include <xstd/bitwise.hpp>
#include <xstd/guid.hpp>
#include <ntpp.hpp>
#include <sdk/ke/api.hpp>
#include "ahci.hpp"
#include "nvme.hpp"

// Forces physical disks out of D3 sleep by issuing dummy I/O commands.
//
static void force_out_of_d3()
{
	// Get a list of all volumes.
	//
	uint32_t volume_mask = 0;
	for ( wchar_t i = 'A'; i <= 'Z'; i++ )
	{
		std::wstring path = L"\\??\\"s + i + L":\\";
		auto hnd = ntpp::create_file( {
			.path = path,
			.access = GENERIC_READ,
			.create_disposition = FILE_OPEN,
			.file_attributes = FILE_DIRECTORY_FILE,
		} );
		if ( hnd )
			volume_mask |= 1ull << ( i - 'A' );
	}

	// Repeat a non-cachable disk operation 4 times to force all devices out of D3 sleep.
	//
	for ( size_t n = 0; n != 4; n++ )
	{
		xstd::bit_enum( volume_mask, [ & ] ( bitcnt_t idx )
		{
			std::wstring path = L"\\??\\"s + wchar_t( 'A' + idx ) + L":\\" + xstd::guid{ idx }.to_wstring();
			auto f = ntpp::create_file( {
				.path = path,
				.access = GENERIC_WRITE,
				.create_disposition = FILE_CREATE,
				.file_attributes = FILE_ATTRIBUTE_NORMAL,
				.create_options = FILE_DELETE_ON_CLOSE,
			} );
			if ( f )
			{
				auto x = ia32::read_tsc();
				ntpp::write_file( f->get(), &x, 8 );
				ntpp::flush_file( f->get() );
				f->reset();
				ntpp::delete_file( path );
			}
		} );
	}
}

// Issues identify commands to every supported disk controller in the device and returns the resulting identifiers.
//
NO_INLINE hwid::disk_set hwid::get_disks()
{
	disk_set identifiers = {};

	// Query the PCI device list.
	//
	auto& pci_devices = ia32::pci::get_device_list();

	// Grab a list of NVME and AHCI devices.
	//
	auto nvme_devices = xstd::filter( pci_devices, [ ] ( auto& device )
	{
		return
			device.config.class_code == PCI_BASE_CLASS_STORAGE &&
			device.config.sub_class_code == PCI_SUB_CLASS_STORAGE_NVME;
	} );
	auto ahci_devices = xstd::filter( pci_devices, [ ] ( auto& device )
	{
		return
			device.config.class_code == PCI_BASE_CLASS_STORAGE &&
			device.config.sub_class_code == PCI_SUB_CLASS_STORAGE_SATA &&
			device.config.prog_if == 1;
	} );

	// If any of the devices are undoubtedly sleeping given their bus master / memory space status, force wakeup from D3.
	//
	bool in_sleep = false;
	for ( auto& device : nvme_devices )
		in_sleep |= ( device.config.command & 6 ) != 6;
	for ( auto& device : ahci_devices )
		in_sleep |= ( device.config.command & 6 ) != 6;
	if ( in_sleep )
		force_out_of_d3();

	// Attempt to grab identifiers up to four times.
	//
	bool retry = false;
	for ( size_t n = 0; n != 4; n++ )
	{
		// Identify NVMe drives.
		//
		for ( auto& device : nvme_devices )
		{
			ntpp::call_dpc( [ & ] ()
			{
				if ( nt::read_pcid() == 0 )
					retry |= nvme::identify( identifiers, device );
			} );
		}
	
		// Identify AHCI drives.
		//
		for ( auto& device : ahci_devices )
		{
			ntpp::call_dpc( [ & ] ()
			{
				if ( nt::read_pcid() == 0 )
					retry |= ahci::identify( identifiers, device );
			} );
		}
	
		// If we're done, break out.
		//
		if ( !retry )
			break;
	
		// Otherwise, force devices out of D3 sleep and retry.
		//
		force_out_of_d3();
	}
	return identifiers;
}