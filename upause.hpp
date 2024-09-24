#pragma once
#include <xstd/intrinsics.hpp>
#include <ia32.hpp>
#include <mcrt/interface.hpp>

namespace util
{
	template<typename F, typename D>
	FORCE_INLINE inline bool upause( D duration, F&& func )
	{
		uint64_t tnow = ia32::read_tsc();
		const uint64_t end_time = tnow + crt::to_cycles( duration );
		while( true ) {
			ia32::pause_for( 0x8000, tnow );
			if ( func() ) 
				return true;
			tnow = ia32::read_tsc();
			if ( tnow > end_time )
				return false;
		}
		return false;
	}
	template<typename D>
	FORCE_INLINE inline bool upause( D duration )
	{
		return upause( duration, [ ] () { return false; } );
	}
};