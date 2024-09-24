#pragma once
#include <xstd/intrinsics.hpp>
#include <mcrt/interface.hpp>
#include <ia32.hpp>
#include <ia32/perfmon.hpp>
#include <ia32/memory.hpp>
#include <sdk/halp/api.hpp>
#include <sdk/mm/api.hpp>

// Benchmarking logic.
//
namespace benchmark
{
	// Timer information.
	// - Perf capability should be set externally.
	//
	inline int8_t has_mperf = 0;  // 0=no,1=yes,2=yes+rd_only
	inline int8_t has_aperf = 0;
	inline int8_t has_pperf = 0;
	inline int8_t has_irperf = 0;

	// Define all metrics:
	//
	template<ia32::pmu::event_id E>
	struct dynamic_pmc
	{
		inline static bool setup()
		{
			return ia32::pmu::dynamic_set_state(
				0,
				E,
				ia32::pmu::ctr_enable | ia32::pmu::ctr_supervisor,
				true
			);
		}
		FORCE_INLINE static uint64_t fetch( bool first )
		{
			auto v = ia32::read_pmc( 0 );
			ia32::serialize();
			return v;
		}
		inline static void rundown()
		{
			ia32::pmu::dynamic_disable( 0 );
		}
	};
	template<ia32::pmu::event_id E>
	struct fixed_pmc
	{
		inline static const uint32_t index = ia32::pmu::fixed_counter_v<true, E>;

		inline static bool setup()
		{
			auto lindex = ia32::pmu::fixed_set_state(
				E,
				ia32::pmu::ctr_enable | ia32::pmu::ctr_supervisor,
				true
			);
			return lindex != UINT32_MAX;
		}
		FORCE_INLINE static uint64_t fetch( bool first )
		{
			auto v = ia32::read_pmc( index, true );
			ia32::serialize();
			return v;
		}
		inline static void rundown()
		{
			ia32::pmu::fixed_set_state( E, 0 );
		}
	};
	struct tsc
	{
		inline static bool setup()
		{
			return true;
		}
		FORCE_INLINE static uint64_t fetch( bool first )
		{
			if ( first )
				return ia32::read_tsc();
			else
				return ia32::read_tscp().first;
		}
		inline static void rundown()
		{
		}
	};
	struct mperf
	{
		inline static uint64_t msr = 0;
		inline static bool setup()
		{
			switch ( has_mperf )
			{
				case 2:
					msr = IA32_MPERF | 0xC0000000;
					if ( ia32::read_msr( msr ) != 0 )
						return true;
					[[fallthrough]];
				case 1:
					msr = IA32_MPERF;
					if ( ia32::read_msr( msr ) != 0 )
						return true;
					[[fallthrough]];
				default:
					return false;
			}
		}
		FORCE_INLINE static uint64_t fetch( bool first )
		{
			auto v = ia32::read_msr( msr );
			ia32::serialize();
			return v;
		}
		inline static void rundown()
		{
		}
	};
	struct aperf
	{
		inline static uint64_t msr = 0;
		inline static bool setup()
		{
			switch( has_aperf )
			{
				case 2:
					msr = IA32_APERF | 0xC0000000;
					if ( ia32::read_msr( msr ) != 0 )
						return true;
					[[fallthrough]];
				case 1:
					msr = IA32_APERF;
					if ( ia32::read_msr( msr ) != 0 )
						return true;
					[[fallthrough]];
				default:
					return false;
			}
		}
		FORCE_INLINE static uint64_t fetch( bool first )
		{
			auto v = ia32::read_msr( msr );
			ia32::serialize();
			return v;
		}
		inline static void rundown()
		{
		}
	};
	struct pperf
	{
		inline static uint64_t msr = 0;
		inline static bool setup()
		{
			if ( !has_pperf ) return false;
			return ia32::read_msr( IA32_PPERF ) != 0;
		}
		FORCE_INLINE static uint64_t fetch( bool first )
		{
			auto v = ia32::read_msr( IA32_PPERF );
			ia32::serialize();
			return v;
		}
		inline static void rundown()
		{
		}
	};
	struct pkg_energy
	{
		inline static bool setup()
		{
			return ia32::read_msr( IA32_PKG_ENERGY_STATUS ) != 0;
		}
		FORCE_INLINE static uint64_t fetch( bool first )
		{
			auto v = ia32::read_msr( IA32_PKG_ENERGY_STATUS );
			ia32::serialize();
			return v;
		}
		inline static void rundown() {}
	};
	struct dram_energy
	{
		inline static bool setup()
		{
			return ia32::read_msr( IA32_MSR_DRAM_ENERGY_STATUS ) != 0;
		}
		FORCE_INLINE static uint64_t fetch( bool first )
		{
			auto v = ia32::read_msr( IA32_MSR_DRAM_ENERGY_STATUS );
			ia32::serialize();
			return v;
		}
		inline static void rundown(){}
	};
	struct tlb_persistance
	{
		using page_entry_t = std::tuple<volatile uint8_t*, ia32::pt_entry_64*, ia32::pt_entry_64>;
		static constexpr size_t count = 1 /*one zero page*/ + 64 /*probes*/;
		inline static auto pages = []() -> const std::array<page_entry_t, count>&
		{
			static std::array<page_entry_t, count> page_list = {};
			for ( size_t i = 0; i != count; i++ )
			{
				uint8_t* page = mm::allocate_independent_pages( 0x1000, -1ll );
				*page = i == 0 ? 0 : 1;
				auto pte = ia32::mem::get_pte( page );
				page_list[ i ] = { page, pte, *pte };
			}

			crt::atexit( []()
			{
				for ( auto& [page, pte, vpte] : page_list )
				{
					*pte = vpte;
					mm::free_independent_pages( page, 0x1000 );
				}
			} );

			return page_list;
		}();

		inline static bool setup() { return true; }
		FORCE_INLINE static uint64_t fetch( bool first )
		{
			if ( first )
			{
				auto& [zp, zpt, zptv] = pages[ 0 ];

				// For each page:
				//
				for ( size_t n = 1; n != count; n++ )
				{
					// Probe the pages with PFN pointing at 1.
					//
					auto& [tp, tpt, tptv] = pages[ n ];
					tpt->page_frame_number = tptv.page_frame_number;
					for ( size_t n = 0; n != 12; n++ )
						ia32::touch( tp, true );

					// Set the PFN to point at zero page, do not invalidate the TLB.
					//
					tpt->page_frame_number = zptv.page_frame_number;
				}

				// Serialize memory stores, serialize instruction stream.
				//
				ia32::sfence();
				ia32::serialize();
				return 0;
			}
			else
			{
				// Serialize instruction stream.
				//
				ia32::serialize();

				// Access each page starting from the LRU, sum the values read.
				//
				size_t counter = 0;
				for ( size_t n = 1; n != count; n++ )
					counter += *std::get<0>( pages[ n ] );

				// Serialize loads.
				//
				ia32::lfence();
				return counter;
			}
		}
		inline static void rundown(){}
	};
	struct mp_clock
	{
		inline static std::atomic<uint64_t> timestamp = 0;
		inline static uint8_t* jump_point = 0;

		[[gnu::naked, gnu::noinline, no_split]] static void timer()
		{
			__asm
			{
				lea rax, [rip+p]
				mov [jump_point], rax

				xor eax, eax
				lea rcx, [timestamp]
				x:
					inc rax
					mov [rcx], rax
				p:
				jmp x
			}
		}
		inline static bool setup()
		{
			return ia32::is_intel() && timestamp != 0;
		}
		FORCE_INLINE static uint64_t fetch( bool first )
		{
			return timestamp.load();
		}
		inline static void rundown(){}
	};
	struct hpet
	{
		struct hpet_clock
		{
			uint8_t pad1[ 0xF0 ];
			std::atomic<uint64_t> value;
		};
		inline static hpet_clock* const base = *( hpet_clock** ) &halp::hpet_base_address;
		inline static bool setup() { return base; }
		FORCE_INLINE static uint64_t fetch( bool first )
		{
			if ( first )
			{
				auto v1 = base->value.load();
				while ( base->value.compare_exchange_strong( v1, v1 ) )
					yield_cpu();
				return v1;
			}
			else
			{
				ia32::serialize();
				return base->value.load();
			}
		}
		inline static void rundown() {}
	};

	// Define the single metric helper.
	//
	static constexpr int test_count = 48;
	template<typename Metric>
	[[gnu::flatten, no_split, no_obfuscate]] inline static std::optional<uint32_t> run_single( void( *fn )() )
	{
		interrupt_counters ctrs = {};
		interrupt_guard _g{ &ctrs };
		if ( !Metric::setup() )
			return std::nullopt;
		Metric::fetch( true );
		if ( ctrs.has_exception() )
			return std::nullopt;

		// Flush CPU caches.
		//
		ia32::wbinvd();
		ia32::flush_tlb();

		std::array<uint32_t, test_count> results = {};
		for ( int n = -4; n != test_count; n++ )
		{
			// Stall the execution engine and let L1d/DSB//TLB fill.
			//
			for ( size_t n = 0; n != 16; n++ )
			{
				if ( !( ia32::read_tsc() % 0xDEADBEEF ) )
					fn();
				ia32::touch( fn );
				ia32::touch( ia32::get_sp() - 16 * 8 );
				ia32::mfence();
			}

			// Serialize execution, do the measurement, serialize again.
			//
			ia32::serialize();
			auto m1 = Metric::fetch( true );
			fn();
			auto m2 = Metric::fetch( false );
			ia32::serialize();

			// Write the result.
			//
			results[ std::max( n, 0 ) ] = uint32_t( m2 - m1 );
		}

		Metric::rundown();
		std::sort( results.begin(), results.end() );
		return xstd::percentile( results, 0.5 );
	}

	// Define the wrapper testing using every metric.
	//
	inline static cbor::object_t run( void( *fn )() )
	{
		cbor::object_t results = {};
		if ( auto v = run_single<fixed_pmc<ia32::pmu::event_id::clock_tsc>>( fn ) )
			results[ "pmcTsc" ] = cbor::fp_t( *v );
		if ( auto v = run_single<fixed_pmc<ia32::pmu::event_id::clock_core>>( fn ) )
			results[ "pmcCore" ] = cbor::fp_t( *v );
		if ( auto v = run_single<tsc>( fn ) )
			results[ "tsc" ] = cbor::fp_t( *v );
		if ( auto v = run_single<mp_clock>( fn ) )
			results[ "mpc" ] = cbor::fp_t( *v );
		if ( auto v = run_single<mperf>( fn ) )
			results[ "mperf" ] = cbor::fp_t( *v );
		if ( auto v = run_single<aperf>( fn ) )
			results[ "aperf" ] = cbor::fp_t( *v );
		if ( auto v = run_single<pperf>( fn ) )
			results[ "pperf" ] = cbor::fp_t( *v );
		if ( auto v = run_single<hpet>( fn ) )
			results[ "hpet" ] = cbor::fp_t( *v );
		if ( auto v = run_single<tlb_persistance>( fn ) )
			results[ "tlb" ] = cbor::fp_t( *v );
		if ( auto v = run_single<dram_energy>( fn ) )
			results[ "poDram" ] = cbor::fp_t( *v );
		if ( auto v = run_single<pkg_energy>( fn ) )
			results[ "poPkg" ] = cbor::fp_t( *v );
		return results;
	}

	// Lambda wrappers.
	//
	template<xstd::StatelessLambda F>
	inline static auto wrap_fixed_duration( F )
	{
		static const uint64_t cycles_1ms = crt::to_cycles( 1ms );

		return []() __attribute__((flatten, __no_obfuscate__, __no_split__, __enforce_alignment__(64)))
		{
			auto f = F{};
			auto t = ia32::read_tsc() + cycles_1ms;
			while ( ia32::read_tsc() <= t )
				f();
		};
	}
	template<xstd::StatelessLambda F>
	inline static constexpr auto wrap_no_obfuscation( F )
	{
		return []() __attribute__((flatten, __no_obfuscate__, __no_split__, __enforce_alignment__(64)))
		{
			F{}();
		};
	}
};
