#pragma once
#include <string>
#include <vector>
#include <xstd/result.hpp>
#include <xstd/hashable.hpp>

namespace hwid
{
	struct bios_device
	{
		std::string model = {};
		std::string serial = {};
	};

	struct option_rom
	{
		uint32_t address;
		xstd::fnv64 hash;
	};

	struct dci_table
	{
		uint32_t address;
		std::string anchor;
	};

	struct bios_identifiers
	{
		// Detections.
		//
		std::string is_vm = {};
		bool is_tampered = false;
		
		// Identifiers.
		//
		std::string sys_guid = {};
		std::string sys_serial = {};
		bios_device baseboard = {};
		std::vector<bios_device> memory_devices = {};
		std::string cmos_serial = {};

		// Asset tags.
		//
		std::vector<std::string> asset_tags = {};
	};

	// Gets the DCI/BIOS identifiers.
	//
	xstd::result<bios_identifiers> get_bios_identifiers();
};