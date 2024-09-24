#pragma once
#include <ia32.hpp>
#include <array>
#include <optional>
#include <ia32/hde64.hpp>

// Basic interrupt handling logic.
//
struct interrupt_counters
{
	uint8_t* iterator;
	uint8_t store[ 128 ];

	// Interrupt recording enabled.
	//
	interrupt_counters()
	{
		iterator = &store[ 0 ];
	}

	// No counter recording.
	//
	interrupt_counters( std::nullopt_t )
	{
		iterator = nullptr;
	}

	// Make iterable.
	//
	auto* begin() const { return &store[ 0 ]; }
	auto* end() const { return iterator; }
	size_t size() const { return iterator ? end() - begin() : 0; }
	void clear() { iterator = &store[ 0 ]; }

	// Simple check for exceptions.
	//
	size_t count_exceptions() const
	{
		size_t n = 0;
		for ( auto it = begin(); it != end(); ++it )
			n += *it != 2 && *it <= 0x1E;
		return n;
	}
	bool has_exception() const
	{
		for ( auto it = begin(); it != end(); ++it )
			if ( *it != 2 && *it <= 0x1E )
				return true;
		return false;
	}
};

namespace impl
{
	static interrupt_counters nill_counter = { std::nullopt };

	// Skips a single instruction.
	//
	[[gnu::no_caller_saved_registers]] inline void __cdecl skip_instruction( const void** ip )
	{
		if ( !memcmp( *ip, "\x0F\x01\xD1", 3 ) || !memcmp( *ip, "\x0F\x01\xD0", 3 ) )
			*ip = xstd::ptr_at( *ip, 3 );
		else
		{
			auto hde = hde64::disasm( *ip );
			if ( hde.flags & F_ERROR_OPCODE )
				*ip = xstd::ptr_at( *ip, 15 );
			else
				*ip = xstd::ptr_at( *ip, hde.len );
		}
	}

	// The common interrupt service routine.
	//
	template<uint8_t vector>
	[[gnu::naked, no_split]] inline void counter_isr()
	{
		static constexpr bool has_exception =
			vector == 8 ||  // #DF
			vector == 10 || // #TS
			vector == 11 || // #NP
			vector == 12 || // #SS
			vector == 13 || // #GP
			vector == 14 || // #PF
			vector == 17 || // #AC
			vector == 21 || // #CP
			vector == 30;   // #SX
		
		// Nop padding for deferred #DB.
		//
		__asm { nop };

		// Pop exception code if relevant.
		//
		if constexpr ( has_exception )
			__asm { add rsp, 8 };

		// Handle the interrupt counter.
		//
		__asm 
		{
			push        rax
			push        rbx
		};
		asm volatile( "mov %0, %%bl" :: "i" ( vector ) );
		__asm
		{
			mov         rax,             gs:[0]
			test        rax,             rax
			jz          skip_counter

			mov         [rax],           bl
			inc         qword ptr gs:[0]

		skip_counter:
			pop         rbx
			pop         rax
		}

		// Skip to the failure handler if exception, else continue.
		//
		if constexpr ( vector != 1 /*cba, assume trap*/ && 
					   vector != 2 /*NMI*/ &&
					   vector != 3 /*trap*/ && 
					   vector != 4 /*trap*/ && 
					   vector <= 0x1E /*not exception otherwise*/ )
		{
			__asm 
			{ 
				push    rcx
				lea     rcx,             [rsp+8]
				call    skip_instruction
				pop     rcx
			}
		}
	
		__asm { iretq }
	}

	// The IDT mapping to counter_isr<N>'s.
	//
	inline const auto idt = xstd::make_constant_series<0x100>( [  ] ( auto id )
	{
		ia32::idt_entry entry = {};
		memset( &entry, 0, sizeof( entry ) );
		entry.selector = 0x10;
		entry.ist_index = 0;
		entry.type = 0xE;
		entry.priv = 3;
		entry.present = 1;
		entry.set_handler( &counter_isr<(id > 0x1E && id != 0xFE ? 0xCC : id)> );
		return entry;
	});
};

// RAII exception catching.
//
struct interrupt_guard
{
	uint64_t previous_gsbase = 0;
	ia32::segment_descriptor_register_64 prev_idtr;
	ia32::rflags flags = { .flags = 0 };
	
	// Starts guarding the scope from any interrupts.
	//
	interrupt_guard( interrupt_counters* counters = &impl::nill_counter ) { reset( counters ); }
	void reset( interrupt_counters* counters )
	{
		if ( !previous_gsbase )
		{
			// Disable the interrupts and swap the GS base & IDT.
			//
			flags = ia32::read_flags();
			ia32::disable();
			previous_gsbase = ia32::read_gsbase();
			ia32::read_idtr( &prev_idtr );
			ia32::set_idt( impl::idt.data(), impl::idt.size() );;
			ia32::write_gsbase( counters );
		}
	}

	// No copy allowed.
	//
	interrupt_guard( const interrupt_guard& ) = delete;

	// Exits the guarded scope on destruction.
	//
	void end()
	{
		if ( auto pgs = std::exchange( previous_gsbase, 0 ) )
		{
			// Restore IDTR/GSBASE/RFLAGS.
			//
			ia32::write_gsbase( pgs );
			ia32::write_idtr( &prev_idtr );
			ia32::write_flags( flags );
		}
	}
	~interrupt_guard() { end(); }
};

