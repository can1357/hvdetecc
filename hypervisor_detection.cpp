#include <ia32/perfmon.hpp>
#include <sdk/mm/api.hpp>
#include <sdk/ke/api.hpp>
#include <sdk/nt/kpcr_t.hpp>
#include <sdk/nt/kprcb_t.hpp>
#include <sdk/ex/api.hpp>
#include <sdk/halp/api.hpp>
#include <sdk/kd/api.hpp>
#include <xstd/statistics.hpp>
#include <ia32/memory.hpp>
#include <ntpp.hpp>
#include <vmx.hpp>
#include "benchmark.hpp"
#include "interrupt_guard.hpp"

// Northbridge tests.
//
namespace northbridge
{
	// Test for VMWare escape.
	//
	FORCE_INLINE static void test_vmw( cbor::object_t& result, cbor::object_t& detections )
	{
		// Flag if VMWare port works.
		//
		detections[ "vm.vmwareIo" ] = vmx::channel::open().is_valid();
	}

	// Test if the SMIs are delivered as expected.
	//
	FORCE_INLINE static void test_smi( cbor::object_t& result, cbor::object_t& detections )
	{
		if ( !ia32::is_intel() ) {
			return;
		}

		// Try setting up an SMI counter.
		//
		bool counter_setup = ia32::pmu::dynamic_set_state(
			0,
			ia32::pmu::event_id::smi_received,
			ia32::pmu::ctr_enable |
			ia32::pmu::ctr_supervisor,
			true
		);

		// If we've failed try using the MSR.
		//
		if ( !counter_setup )
		{
			interrupt_counters ctrs = {};
			{
				interrupt_guard _g{ &ctrs };
				ia32::read_msr( IA32_MSR_SMI_COUNT );
			}
			if ( ctrs.has_exception() )
				return;
		}

		auto read_counter = [ & ] ()
		{
			return counter_setup ? ia32::pmu::dynamic_query_value( 0 ) : ia32::read_msr( IA32_MSR_SMI_COUNT );
		};

		// Read the counter and cause a random number of SMIs.
		//
		size_t count = xstd::make_random( 1, 8 );
		size_t ecount = read_counter();
		while ( count )
		{
			ia32::write_io( 0xB2, 0 );
			--count; ++ecount;
		}
		size_t rcount = read_counter();

		// Reset the counter state if relevant.
		//
		if ( !counter_setup )
			ia32::pmu::dynamic_disable( 0 );

		// If SMI counter did not increment as expected, flag the machine.
		//
		detections[ "vm.smiSuppressed" ] = rcount < ecount;
		result[ "smiExpected" ] = ecount;
		result[ "smiReceived" ] = rcount;
	}
};

// Processor behaviour tests.
//
namespace processor
{
	// Collect basic information about the processor.
	//
	FORCE_INLINE static void collect_info( cbor::object_t& result, cbor::object_t& detections )
	{
		auto& basic_info = ia32::static_cpuid<0, 0, ia32::cpuid_eax_00>;

		std::array<char, 13> brand = { 0 };
		memcpy( &brand[ 0 ], &basic_info.ebx_value_genu, 4 );
		memcpy( &brand[ 4 ], &basic_info.edx_value_inei, 4 );
		memcpy( &brand[ 8 ], &basic_info.ecx_value_ntel, 4 );
		result[ "brand" ] = ( const char* ) brand.data();
		result[ "highestFunction" ] = basic_info.max_cpuid_input_value;

		auto& details = ia32::static_cpuid<1, 0, ia32::cpuid_eax_01>;
		result[ "family" ] = details.cpuid_version_information.family_id;
		result[ "model" ] = details.cpuid_version_information.model;
		result[ "type" ] = details.cpuid_version_information.processor_type;
		result[ "stepping" ] = details.cpuid_version_information.stepping_id;
		result[ "extendedFamily" ] = details.cpuid_version_information.extended_family_id;
		result[ "extendedModel" ] = details.cpuid_version_information.extended_model_id;
		result[ "isIntel" ] = ia32::is_intel();
		detections[ "vm.hvFlagSet" ] = details.cpuid_feature_information_ecx.hypervisor_present;

		static constexpr std::tuple<uint32_t, int8_t&> msr_list[] = {
			{ IA32_MPERF,  benchmark::has_mperf },
			{ IA32_APERF,  benchmark::has_aperf },
			{ IA32_PPERF,  benchmark::has_pperf },
			{ IA32_IRPERF, benchmark::has_irperf }
		};
		for ( auto&& [msr, out] : msr_list )
		{
			interrupt_counters ctrs = {};
			interrupt_guard g{ &ctrs };
			auto val = ia32::read_msr( msr );
			if ( ctrs.has_exception() )
			{
				out = 0;
			}
			else if ( !val )
			{
				g.end();
				detections[ "vm.nullClock" ] = true;
				out = 0;
			}
			else
			{
				ia32::read_msr( msr | 0xC0000000 );
				out = ctrs.has_exception() ? 1 : 2;
			}
		}
	}

	// Test if the guest interruptability is faultily implemented.
	//
	FORCE_INLINE static void test_int( cbor::object_t& result, cbor::object_t& detections )
	{
		// Test STR and SLDT.
		//
		{
			uint64_t b = 0;
			uint64_t a = -1;
			asm volatile( "strq %%rax" : "+a" ( a ) );
			b |= ( a >> 16 );
			asm volatile( "stc; sbbq %q0, %q0;" : "+r" ( a ) :: "flags" );
			asm volatile( "strl %%eax" : "+a" ( a ) );
			b |= ( a >> 16 );
			a = 0xeacceacceacceacc;
			asm volatile( "strw %%ax" : "+a" ( a ) );
			b |= ( ( a >> 16 ) - 0xeacceacceacc );
			detections[ "vm.strEmulFail" ] = b != 0;
		}
		{
			uint64_t b = 0;
			uint64_t a = -1;
			asm volatile( "sldtq %%rax" : "+a" ( a ) );
			b |= ( a >> 16 );
			asm volatile( "stc; sbbq %q0, %q0;" : "+r" ( a ) :: "flags" );
			asm volatile( "sldtl %%eax" : "+a" ( a ) );
			b |= ( a >> 16 );
			a = 0xeacceacceacceacc;
			asm volatile( "sldtw %%ax" : "+a" ( a ) );
			b |= ( ( a >> 16 ) - 0xeacceacceacc );
			detections[ "vm.sldtEmulFail" ] = b != 0;
		}

		// Cause a suppressed #DB and count the interrupts.
		//
		static uint16_t g = 0x18;
		interrupt_counters ctr = {};
		{
			ia32::write_dr0( &g );
			ia32::write_dr7( {
				.local_breakpoint_0 = 1,
				.length_0 = 0b01,
				.read_write_0 = 0b11,
			} );

			{
				interrupt_guard _g{ &ctr };
				__asm
				{
					mov    ss, word ptr[ g ]
					int    2
				}
			}

			ia32::write_dr7( { .flags = 0 } );
		}

		// See if we were delivered 2 #DB's as expected, else flag the machine.
		//
		size_t db_count = xstd::count( ctr, 1 );
		detections[ "vm.dbSuppressed" ] = db_count != 1;
		result[ "dbsDelivered" ] = db_count;
	}

	// Test if power management is implemented.
	//
	FORCE_INLINE static void test_po( cbor::object_t& result, cbor::object_t& detections )
	{
		if ( !ia32::is_intel() )
			return;

		// Flag if turbo boost writes do not stick or #GP.
		//
		if ( ia32::static_cpuid_s<6, 0, ia32::cpuid_eax_06>.eax.intel_turbo_boost_technology_available ) {
			interrupt_counters ctrs = {};
			uint64_t val = 0, val2 = 0;
			{
				interrupt_guard _g{ &ctrs };
				val = ia32::read_msr( IA32_MISC_ENABLE );
				ia32::write_msr( IA32_MISC_ENABLE, val ^ ( 1ull << 38 ) );
				val2 = ia32::read_msr( IA32_MISC_ENABLE );
				ia32::write_msr( IA32_MISC_ENABLE, val );
			}
			detections[ "vm.turboSuppressed" ] = ctrs.has_exception() || !xstd::bit_test( val ^ val2, 38 );
		}
	}

	// Test if performance monitoring is faultily implemented.
	//
	FORCE_INLINE static void test_pm( cbor::object_t& result, cbor::object_t& detections )
	{
		// Disable the PMC and write to its PMC counter.
		//
		if ( !ia32::pmu::dynamic_disable( 0 ) )
		{
			result[ "failedSettingPmcs" ] = true;
			return;
		}
		auto magic_val = xstd::make_random<uint64_t>( 1ull << 2, 1ull << 20 );
		if ( !ia32::pmu::dynamic_set_value( 0, magic_val ) )
		{
			result[ "failedWritingPmcs" ] = true;
			return;
		}

		// Flag if the written value was not sustained.
		//
		detections[ "vm.pmcMsrMismatch" ] = ia32::pmu::dynamic_query_value( 0 ) != magic_val;

		// Flag if readpmc faults.
		//
		interrupt_counters ctrs = {};
		auto& rdpmcRes = detections[ "vm.rdpmcMismatch" ].integer();
		{
			interrupt_guard _g{ &ctrs };
			rdpmcRes = ia32::read_pmc( 0 ) != magic_val;
		}
		detections[ "vm.rdpmcFaulted" ] = ctrs.has_exception();

		// Enable the PMC for a short while.
		//
		if ( !ia32::pmu::dynamic_set_state( 0, ia32::pmu::event_id::ins_retire, ia32::pmu::ctr_enable | ia32::pmu::ctr_supervisor, true ) )
		{
			result[ "failedSettingPmcs" ] = true;
			return;
		}
		ia32::pmu::dynamic_disable( 0 );

		// Flag if the written value was not incremented.
		//
		detections[ "vm.pmcDead" ] = ia32::pmu::dynamic_query_value( 0 ) <= magic_val;

		// If Intel processor check if PEBS works.
		//
		if ( ia32::is_intel() )
		{
			interrupt_counters ctrs = {};
			uint64_t pebs_valid = 0;
			{
				interrupt_guard _g{ &ctrs };
				ia32::write_msr( IA32_PEBS_ENABLE, IA32_PEBS_ENABLE_ENABLE_PEBS_FLAG );
				pebs_valid = ia32::read_msr( IA32_PEBS_ENABLE );
				ia32::write_msr( IA32_PEBS_ENABLE, 0 );
			}

			if ( ctrs.has_exception() )
				result[ "failedEnablingPebs" ] = true;
			else
				detections[ "vm.pebsSuppressed" ] = ( pebs_valid & IA32_PEBS_ENABLE_ENABLE_PEBS_FLAG ) == 0;
		}
	}

	// Tests if control registers are faultily implemented.
	//
	FORCE_INLINE static void test_cr( cbor::object_t&, cbor::object_t& detections )
	{
		auto xcr0 =   ia32::read_xcr( 0 );
		auto randhi = ( ia32::read_tsc() << 32 ) | ( 1ull << 32 );

		// Try reading XGETBV with high trashed.
		//
		interrupt_counters ctrs = {};
		if ( ia32::static_cpuid_s<0xD, 1, ia32::cpuid_eax_0d_ecx_01>.eax.supports_xgetbv_with_ecx_1 ) {
			// Try reading ECX=1.
			//
			interrupt_guard g{ &ctrs };
			ia32::read_xcr( 1 | randhi );
		} else {
			// Try reading ECX=0.
			//
			interrupt_guard g{ &ctrs };
			ia32::read_xcr( 0 | randhi );
		}
		detections[ "vm.xgetbvEmulFail" ] = ctrs.has_exception();
		ctrs.clear();

		// Flag if XSETBV with invalid ECX does not fault.
		//
		{
			interrupt_guard g{ &ctrs };
			ia32::write_xcr( 3, 0 );
		}
		detections[ "vm.xsetbvLeafEmulFail" ] = !ctrs.has_exception();
		ctrs.clear();

		// Flag if XSETBV with valid ECX faults.
		//
		{
			interrupt_guard g{ &ctrs };
			ia32::write_xcr( randhi, xcr0 );
		}
		detections[ "vm.xsetbvLeafEmulFail2" ] = ctrs.has_exception();
		ctrs.clear();

		// Flag if XSETBV with invalid value does not fault.
		//
		{
			interrupt_guard g{ &ctrs };
			ia32::write_xcr( randhi, xcr0 | ( 1ull << 21 ) /*the XAAD bit*/ );
		}
		detections[ "vm.xsetbvValueEmulFail" ] = !ctrs.has_exception();
		ctrs.clear();

		// Flag if SMSW does not match CR0.
		//
		detections[ "vm.smswEmulFail" ] = uint32_t( ia32::smsw().flags ^ ia32::read_cr0().flags ) != 0;
	}

	// Test if processor identifiers are faultily implemented or indicate the presence of an hypervisor.
	//
	FORCE_INLINE static void test_id( cbor::object_t& result, cbor::object_t& detections )
	{
		// If CPUID 0xD.0 and 0xD.1 are equivalent, ECX is value is ignored by the hypervisor.
		//
		auto max_cpuid = ia32::static_cpuid<0, 0, ia32::cpuid_eax_00>.max_cpuid_input_value;
		if ( max_cpuid >= 0xD )
			detections[ "vm.cpuidEcxSuppressed" ] = ia32::static_cpuid<0xD, 0x00> == ia32::static_cpuid<0xD, 0x01>;
	}

	// Test if debug extensions are faultily implemented or are being used on us.
	//
	FORCE_INLINE static void test_dbg( cbor::object_t& result, cbor::object_t& detections )
	{
		// Flag if write is discarded.
		//
		if ( !ia32::static_cpuid_s<0x7, 0, ia32::cpuid_eax_07>.edx.arch_lbr )
		{
			interrupt_counters ctrs = {};
			uint64_t state;
			{
				interrupt_guard _g{ &ctrs };
				ia32::write_msr( IA32_DEBUGCTL, IA32_DEBUGCTL_LBR_FLAG );
				state = ia32::read_msr( IA32_DEBUGCTL );
				ia32::write_msr( IA32_DEBUGCTL, 0 );
			}
			detections[ "vm.lbrSuppressed" ] = ( state & IA32_DEBUGCTL_LBR_FLAG ) == 0;
		}

		// If Intel, enable BTS ring masking.
		//
		if ( ia32::is_intel() )
		{
			interrupt_counters ctrs = {};
			uint64_t state;
			{
				interrupt_guard _g{ &ctrs };
				ia32::write_msr( IA32_DEBUGCTL, IA32_DEBUGCTL_BTS_OFF_OS_FLAG );
				state = ia32::read_msr( IA32_DEBUGCTL );
			}
			detections[ "vm.btsOsFault" ] = ctrs.has_exception();
			detections[ "vm.btsOsSuppressed" ] = ( state & IA32_DEBUGCTL_BTS_OFF_OS_FLAG ) == 0;
		}

		// Enable BTF.
		//
		ia32::write_msr( IA32_DEBUGCTL, IA32_DEBUGCTL_BTF_FLAG );
		interrupt_counters ctrs = {};
		{
			interrupt_guard _g{ &ctrs };
			__asm
			{
				pushfq
				push    [rsp]
				bts     dword ptr [rsp], RFLAGS_TRAP_FLAG_BIT
				popfq
				pause
				popfq
			}
			ia32::write_msr( IA32_DEBUGCTL, 0 );
		}

		// Flag if setting the trap flag generated a #DB instead of doing nothing since we had no branches.
		//
		detections[ "vm.btfSuppressed" ] = ctrs.has_exception();

		// If Intel Broadwell and later, change the controls for Intel PT.
		//
		if ( ia32::is_intel() )
		{
			auto& version = ia32::static_cpuid<1, 0, ia32::cpuid_eax_01>.cpuid_version_information;
			uint32_t family = version.family_id;
			uint32_t model = version.model;
			switch ( family )
			{
				case 0x6:
				case 0xF:
					model += uint32_t( version.extended_model_id ) << 4;
				default:
					break;
			}
			if ( family > 6 || ( family == 6 && model >= 70 ) ) {
				interrupt_counters ctrs = {};
				bool supressed = false;
				{
					interrupt_guard _g{ &ctrs };
					auto rtit_prev = ia32::read_msr<ia32::rtit_ctl_register>( IA32_RTIT_CTL );

					ia32::rtit_ctl_register rtit_new = { .flags = 0 };
					rtit_new.topa = true;
					rtit_new.trace_enabled = true;
					rtit_new.branch_enabled = true;
					ia32::write_msr( IA32_RTIT_CTL, rtit_new );

					auto rtit_active = ia32::read_msr<ia32::rtit_ctl_register>( IA32_RTIT_CTL );
					ia32::write_msr( IA32_RTIT_CTL, rtit_prev );

					supressed = !rtit_active.trace_enabled;
				}
				detections[ "vm.ptSuppressed" ] = supressed;
			}
		}

		// Flag based on silicon debugging interface.
		//
		//if ( ia32::is_intel() ) {
		//	// If we can read the value:
		//	//
		//	interrupt_counters ctrs = {};
		//	interrupt_guard g{ &ctrs };
		//	auto debug = ia32::read_msr<ia32::debug_interface_register>( IA32_DEBUG_INTERFACE );
		//	g.end();
		//	if ( !ctrs.has_exception() ) {
		//		// Save debug occured value.
		//		//
		//		detections[ "dbg.siliconDebugOccurred" ] = ( bool ) debug.debug_occurred;
		//
		//		// If it is not locked, try disabling.
		//		//
		//		if ( !debug.lock ) {
		//			debug.enable = false;
		//			debug.lock = true;
		//			{
		//				interrupt_guard g{ &ctrs };
		//				ia32::write_msr( IA32_DEBUG_INTERFACE, debug );
		//			}
		//			debug.flags = ia32::read_msr( IA32_DEBUG_INTERFACE );
		//		}
		//
		//		// Save if debug interface is locked as enabled.
		//		//
		//		detections[ "dbg.siliconLockedEnable" ] = ( bool ) debug.enable;
		//	}
		//}
	}

	// Test if MSRs are faultily implemented.
	//
	FORCE_INLINE static void test_msr( cbor::object_t&, cbor::object_t& detections )
	{
		// MSR reads do not #GP as expected.
		//
		if ( ia32::is_intel() )
			detections[ "vm.msrDefaultInvalid" ] = benchmark::has_mperf == 2 && benchmark::has_irperf;

		// Check for hypervisor MSRs.
		//
		interrupt_counters ctrs = {};
		{
			interrupt_guard _g{ &ctrs };
			ia32::read_msr( 0x4b564d01 );
			ia32::read_msr( 0x40000000 );
		}
		detections[ "vm.hvMsrs" ] = ctrs.count_exceptions() != 2;

		// Check for emulation failure w.r.t RCX/ECX distinguishment.
		// - Also functions as a check for the AMD SVM errata where 0x10 is not affected by TSC offsetting.
		//
		size_t fail_count = 0;
		for ( size_t n = 0; n != 16; n++ ) {
			ctrs.clear();
			interrupt_guard g{ &ctrs };
			uint64_t tsc1, tsc2;
			__NoObfuscate(
				ia32::serialize();
				tsc1 = ia32::read_tsc();
				ia32::serialize();
				tsc2 = ia32::read_msr( 0x10 );
				ia32::serialize();
			);
			g.end();
			// Delta shouldn't be more than 1500 cycles.
			fail_count += ( ctrs.has_exception() || ( uint64_t( tsc2 - tsc1 ) > 1500 ) ) ? 1 : 0;
		}
		detections[ "vm.tscMsrEmulFail" ] = fail_count > 8;
	}

	// Test if NX is handled properly.
	//
	[[no_split]] static void test_nx( volatile uint8_t* page, cbor::object_t&, cbor::object_t& detections )
	{
		static std::pair<ia32::pt_entry_64*, bool> revert_list[ 4096 ];
		static size_t revert_list_i = 0;
		static constexpr auto set_nx = [] ( any_ptr p, int n, bool xd, bool rec ) {
			auto add = [ & ] ( ia32::pt_entry_64* e ) {
				if ( e->execute_disable == xd ) return;

				if ( xd ) {
					if ( xstd::atomic_bit_set( e->flags, PT_ENTRY_64_EXECUTE_DISABLE_BIT ) ) return;
				} else {
					if ( !xstd::atomic_bit_reset( e->flags, PT_ENTRY_64_EXECUTE_DISABLE_BIT ) ) return;
				}
				revert_list[ revert_list_i++ ] = { e, xd };
			};

			while ( n > 0 ) {
				__hint_unroll()
				for ( int8_t d = ia32::mem::pxe_level; d >= ia32::mem::pte_level; d-- ) {
					auto e = ia32::mem::get_pte( p, d );

					// If present:
					if ( e->present ) {
						// If not PTE and not large page, move to next level.
						if ( d != ia32::mem::pte_level && !e->large_page ) {
							if ( rec ) add( e );
							continue;
						}

						// Add the entry.
						add( e );
						ia32::invlpg( p );
					}

					// Onto the next one.
					p += ia32::mem::page_size( d );
					n -= ia32::mem::page_size( d );
					break;
				}
			}
		};

		interrupt_counters ctrs = {};
		{
			interrupt_guard _g{ &ctrs };

			// Make sure the test page is no-execute.
			//
			set_nx( page, 0x1000, true, false );

			// Make sure the code page we're executing / IDT / GDT / TSS / Page tables associated are not set NX.
			//
			set_nx( impl::idt.data(), 0x1000, false, true );
			for ( size_t n = 0; n != 0x100; n++ )
				set_nx( impl::idt[ n ].get_handler(), 0x1000, false, true );
			auto [gdt, lim] = ia32::get_gdt();
			set_nx( gdt, ( lim + 1 ) * sizeof( ia32::gdt_entry ), false, true );
			auto* tss = ( ( ia32::tss_entry* ) &gdt[ ia32::get_tr().index ] );
			set_nx( tss->get_offset(), tss->get_limit() + 1, false, true );
			set_nx( ia32::get_ip(), 0x2000, false, true );
			set_nx( ia32::get_sp() - 0x500, 0x2000, false, true );

			// Disable NX in EFER.
			//
			auto efer = ia32::read_msr<ia32::efer_register>( IA32_EFER );
			efer.execute_disable_bit_enable = false;
			ia32::write_msr( IA32_EFER, efer );

			// Disable XD in misc enable.
			//
			ia32::misc_enable_register misc;
			if ( ia32::is_intel() ) {
				misc = ia32::read_msr<ia32::misc_enable_register>( IA32_MISC_ENABLE );
				misc.xd_bit_disable = true;
				ia32::write_msr( IA32_MISC_ENABLE, misc );
			}

			// Touch the NX'd page and CPUID.
			//
			*page = 0;
			ia32::query_cpuid( 0 );
			ia32::write_cr3( ia32::read_cr3() );
			*page = 0;
			ia32::query_cpuid( 0 );
			*page = 0;

			// Revert the changes we've made.
			//
			if ( ia32::is_intel() ) {
				misc.xd_bit_disable = false;
				ia32::write_msr( IA32_MISC_ENABLE, misc );
			}
			efer.execute_disable_bit_enable = true;
			ia32::write_msr( IA32_EFER, efer );

			for ( size_t i = 0; i != revert_list_i; i++ ) {
				auto [e, xd] = revert_list[ i ];
				if ( xd ) {
					xstd::atomic_bit_reset( e->flags, PT_ENTRY_64_EXECUTE_DISABLE_BIT );
				} else {
					xstd::atomic_bit_set( e->flags, PT_ENTRY_64_EXECUTE_DISABLE_BIT );
				}
			}
			revert_list_i = 0;
		}

		// Save the detection.
		//
		detections[ "vm.eferNxDiscard" ] = !ctrs.has_exception();
	}

	// Tests the clock integrity.
	//
	FORCE_INLINE static void test_clk( cbor::object_t& result, cbor::object_t& detections )
	{
		// Detect missing clock sources.
		//
		detections[ "vm.hiddenClocks" ] = !benchmark::has_aperf || !benchmark::has_mperf;

		// Check if write to TSC works as it should.
		//
		if ( ia32::is_intel() && ia32::static_cpuid_s<7, 0, ia32::cpuid_eax_07>.ebx.ia32_tsc_adjust_msr ) {
			ia32::disable();
			volatile uint64_t amsr = IA32_TSC_ADJUST;
			uint64_t t0, t1;
			uint32_t rng = xstd::make_random<uint32_t>() | 0xdead00;
			uint64_t ta = ia32::read_msr( amsr );
			__NoObfuscate(
				t0 = ia32::read_tsc();
				ia32::serialize();

				ia32::write_msr( amsr, ta + rng );
				ia32::serialize();

				t1 = ia32::read_tscp().first;
				ia32::serialize();
			);
			ia32::write_msr( amsr, ta );
			ia32::enable();
			t1 -= rng;
			detections[ "vm.tscWarped" ] = t1 < t0 || t1 > ( t0 + 3000 );
		}
	}


	// Runs the processor benchmarks collecting metrics.
	//
	NO_INLINE static void run_bench( cbor::object_t& result, cbor::object_t& detections )
	{
		static auto defxcr0 = ia32::read_xcr( 0 );
		static uint64_t tmp_a = 0xdead;
		static volatile int64_t tmp_b;

		constexpr auto fn_nop = [ ] () FORCE_INLINE {};
		constexpr auto fn_alu = []() FORCE_INLINE { tmp_b = tmp_a / int64_t( xstd::lce_64( tmp_a ) | 1 ); asm volatile( "" :: "m" ( tmp_b ) ); };
		constexpr auto fn_cpuid = [ ] () FORCE_INLINE { ia32::query_cpuid( 0 ); };
		constexpr auto fn_xsetbv = [ ] () FORCE_INLINE { ia32::write_xcr( 0, defxcr0 ); };
		constexpr auto fn_smi = [ ] () FORCE_INLINE { ia32::write_io( 0xB2, 0 ); };

		result[ "nop" ] = benchmark::run( benchmark::wrap_no_obfuscation( fn_nop ) );
		result[ "alu" ] = benchmark::run( benchmark::wrap_no_obfuscation( fn_alu ) );
		result[ "cpuid" ] = benchmark::run( benchmark::wrap_no_obfuscation( fn_cpuid ) );
		result[ "smi" ] = benchmark::run( benchmark::wrap_no_obfuscation( fn_smi ) );
		result[ "xsetbv" ] = benchmark::run( benchmark::wrap_no_obfuscation( fn_xsetbv ) );
		result[ "nopLong" ] = benchmark::run( benchmark::wrap_fixed_duration( fn_nop ) );
		result[ "aluLong" ] = benchmark::run( benchmark::wrap_fixed_duration( fn_alu ) );
		result[ "cpuidLong" ] = benchmark::run( benchmark::wrap_fixed_duration( fn_cpuid ) );
		result[ "smiLong" ] = benchmark::run( benchmark::wrap_fixed_duration( fn_smi ) );
		result[ "xsetbvLong" ] = benchmark::run( benchmark::wrap_fixed_duration( fn_xsetbv ) );
	}
};

extern "C" [[gnu::dllexport]] transport::packet* dbgDetect()
{
	auto* process = ke::get_eprocess();
	cbor::instance result = {};
	auto& detections = result[ "detections" ].object();

	[ & ] () __attribute__((__virtualize__, noinline)) {
		// If process has debug port set, flag.
		//
		if ( process->debug_port ) {
			detections[ "dbg.usermode" ] = true;
		}

		// Fuck up KD.
		//
		*( int32_t* ) &kd::disable_count = 0x7aaaaaaa;
		*( uint8_t* ) &kd::pitch_debugger = true;
		*( uint8_t* ) &kd::block_enable = true;
	}();

	return transport::serialize( result );
}

// Must be called at IRQL = 2.
//
static std::atomic<bool> clock_latch = false;
extern "C" [[gnu::dllexport]] transport::packet* hvDetectBasic()
{
	cbor::instance result = {};
	auto& detections = result[ "detections" ].object();
	auto& data = result[ "data" ].object();
	auto& nb_data = data[ "northbridge" ].object();
	auto& bench_data = data[ "benchmarks" ].object();
	auto& cpu_data = data[ "processor" ].object();

	// Flag if VMXE is enabled.
	//
	detections[ "vm.vmxe" ] = (bool) ia32::read_cr4().vmx_enable;

	// Test the northbridge.
	//
	ntpp::call_dpc( [ & ]() __attribute__( ( __virtualize__ ) ) {
		if ( nt::read_pcid() == 0 ) {
			northbridge::test_smi( nb_data, detections );
			northbridge::test_vmw( nb_data, detections );
		}
	} );

	// Run basic processor tests.
	//
	ntpp::call_dpc( [ & ]() __attribute__( ( __virtualize__ ) ) {
		if ( nt::read_pcid() == 0 ) {
			processor::collect_info( cpu_data, detections );
			processor::test_int( cpu_data, detections );
			processor::test_po( cpu_data, detections );
			processor::test_pm( cpu_data, detections );
			processor::test_dbg( cpu_data, detections );
			processor::test_id( cpu_data, detections );
			processor::test_clk( cpu_data, detections );
		}
	} );

	ntpp::call_dpc( [ & ]() __attribute__( ( __virtualize__ ) ) {
		// Disable all PMCs.
		//
		ia32::pmu::fixed_disable( ia32::pmu::event_id::ins_retire );
		ia32::pmu::fixed_disable( ia32::pmu::event_id::clock_core );
		ia32::pmu::fixed_disable( ia32::pmu::event_id::clock_tsc );
		for ( size_t n = 0; n != 8; n++ )
			ia32::pmu::dynamic_disable( n );

		// If first processor, run the benchmarks.
		//
		if ( nt::read_pcid() == 0 ) {
			while ( !xstd::make_volatile( benchmark::mp_clock::jump_point ) )
				yield_cpu();
			processor::run_bench( bench_data, detections );
			*benchmark::mp_clock::jump_point = 0xC3;
			ia32::clflush( benchmark::mp_clock::jump_point );
		}
		// Otherwise use as a clock source until we're done if second.
		//
		else if ( !clock_latch.exchange( true ) ) {
			ia32::set_irql( IPI_LEVEL - 1 );
			benchmark::mp_clock::timer();
			*benchmark::mp_clock::jump_point = 0xEB;
			ia32::set_irql( DISPATCH_LEVEL );
		}
	} );

	return transport::serialize( result );
}
extern "C" [[gnu::dllexport]] transport::packet* hvDetectAdvanced()
{
	cbor::instance result = {};
	auto& detections = result[ "detections" ].object();
	auto& data = result[ "data" ].object();
	auto& cpu_data = data[ "processor" ].object();

	volatile uint8_t* page = mm::allocate_independent_pages( 0x1000, -1ll );
	ntpp::call_ipi( [ & ]() __attribute__((__virtualize__)) {
		if ( nt::read_pcid() == 0 ) {
			// Run advanced processor tests with the risk of crashing the hypervisor if we did not log any detections yet.
			//
			processor::test_cr( cpu_data, detections );
			processor::test_msr( cpu_data, detections );
			processor::test_nx( page, cpu_data, detections );
		}
	});
	mm::free_independent_pages( page, 0x1000 );

	return transport::serialize( result );
}
