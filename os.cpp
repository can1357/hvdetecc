#include <ia32/memory.hpp>
#include <sdk/mi/api.hpp>
#include <sdk/mm/api.hpp>
#include <ntpp.hpp>

static any_ptr reserve_system_va( size_t length, mi::system_va_type_t type, bool use_ptes )
{
	size_t lpage_count = ( length + 0x1FFFFF ) >> ( 12 + 9 );
	uint64_t va = mi::obtain_system_va( lpage_count, type );
	if ( va )
	{
		mi::make_zeroed_page_tables(
			ia32::mem::get_pte( va ),
			ia32::mem::get_pte( va + ( lpage_count << ( 12 + 9 ) ) - 1 ),
			1 | ( use_ptes ? 0 : 2 ),
			type
		);
	}
	return va;
}
static void return_system_va( any_ptr ptr, size_t length, mi::system_va_type_t type )
{
	size_t lpage_count = ( length + 0x1FFFFF ) >> ( 12 + 9 );
	mi::return_system_va( ptr, ptr + ( lpage_count << ( 12 + 9 ) ), type, nullptr );
}


// Implement the IA32 interface.
//
[[gnu::constructor( 110 )]] void __init_mem() 
{
	ia32::mem::init( ia32::mem::px_index( *mm::pte_base ) );
}
FORCE_INLINE void ia32::mem::ipi_flush_tlb()
{
	ntpp::call_ipi( ia32::flush_tlb );
}
FORCE_INLINE void ia32::mem::ipi_flush_tlb( any_ptr ptr, size_t length )
{
	ntpp::call_ipi( [ & ] { ia32::invlpg( ptr, length ); } );
}
FORCE_INLINE any_ptr ia32::mem::map_physical_memory_range( uint64_t address, size_t length, bool cached )
{
	// Align parameters by large-page.
	//
	uint64_t offset = address & ( page_size( pde_level ) - 1 );
	address -= offset;
	length += offset;
	length = xstd::align_up( length, page_size( pde_level ) );

	// Reserve system VA.
	//
	auto va = reserve_system_va( length, mi::system_va_type_t::system_ptes, false );
	if ( !va ) return nullptr;

	// Map the pages.
	//
	for ( size_t it = 0; it < length; it += page_size( pde_level ) )
	{
		ia32::pt_entry_64 pte = { .flags = 0 };
		pte.present = true;
		pte.write = true;
		pte.user = false;
		pte.page_level_write_through = !cached;
		pte.page_level_cache_disable = !cached;
		pte.accessed = false;
		pte.dirty = false;
		pte.large_page = true;
		pte.global = true;
		pte.page_frame_number = ( address + it ) >> 12;
		pte.protection_key = 0;
		pte.execute_disable = false;
		*get_pte( va + it, pde_level ) = pte;
	}

	// Invalidate the TLB, return the pointer.
	//
	ipi_flush_tlb( va, length );
	return va + offset;
}
FORCE_INLINE void ia32::mem::unmap_physical_memory_range( any_ptr va, size_t length ) 
{
	// Align parameters by large-page.
	//
	uint64_t offset = va & ( page_size( pde_level ) - 1 );
	va -= offset;
	length += offset;
	length = xstd::align_up( length, page_size( pde_level ) );

	// Unmap the pages.
	//
	for ( size_t it = 0; it < length; it += page_size( pde_level ) )
		get_pte( va + it, pde_level )->flags = 0;
	return_system_va( va, length, mi::system_va_type_t::system_ptes );
}