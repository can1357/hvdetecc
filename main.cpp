#include <mcrt/interface.hpp>
#include <sdk/obp/api.hpp>
#include <sdk/etw/api.hpp>
#include <sdk/perf/api.hpp>
#include <ia32/apic.hpp>

namespace crt {
	void rundown_heap();
};

// Runs the image down.
//
extern "C" [[gnu::dllexport]] void rundown()
{ 
	crt::rundown_image();
	crt::rundown_heap();
}

// Makes sure the image and the system is ready for the interfaces.
//
extern "C" bool entry_point() 
{
	ia32::apic::init();
	if ( sdk::exists( etw::threat_int_prov_reg_handle ) )
		*( uint64_t* ) &etw::threat_int_prov_reg_handle = 0;
	if ( sdk::exists( perf::global_group_mask ) )
		*( std::array<uint64_t, 2>* )& perf::global_group_mask = { 0, 0 };
	return true;
}