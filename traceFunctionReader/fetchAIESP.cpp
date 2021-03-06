/**
 * Generate a list which shows <Address> <Instruction> <ESP value if present>
 * Input: <trace>
 *
 */

#include <cassert>
#include <exception>
#include <iostream>
#include <iomanip>
#include "trace.container.hpp"
#include <math.h>
#include <limits.h>

extern "C" {
#include "xed-interface.h"
}

using namespace SerializedTrace;

// for disassembly
#define LINE_SIZE 1024
char line[LINE_SIZE] = {0};
uint64_t ctr = 0;
static xed_error_enum_t xed_error;
static xed_decoded_inst_t xedd;

void print(frame &f) {
	std::cout << f.DebugString() << std::endl;
}

void print_assembly(std::string mystring, ::google::protobuf::uint64 address)
{
	xed_decoded_inst_zero(&xedd);
	#ifdef HHPIN64
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
	#else
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);
	#endif

	xed_error = xed_decode(&xedd, XED_STATIC_CAST(const xed_uint8_t*, mystring.c_str()), mystring.length());
	xed_decoded_inst_dump_att_format(&xedd, line, LINE_SIZE - 1, address);

	if(xed_error != 0)
		std::cout << "XED decode error: " << xed_error_enum_t2str(xed_error) << std::endl;

	std::cout << line;

	return;
}

uint64_t letoUint64(std::string lestring){

	int length = lestring.length();
	uint64_t amt = 0;
	for(int i = 0; i < length; i++){
		amt += (lestring.at(i) & 0xff) * (uint32_t)pow(256,i);
		//std::cout << ((uint) lestring.at(i) & 0xff) << "*" <<pow(256,i)<<"="<< ((uint) lestring.at(i) & 0xff) * pow(256,i) <<" ";
	}
	return amt;

}


uint64_t fetchESPvalue(const operand_value_list& elelist) {
	for (int i = 0; i < elelist.elem_size(); i++) {
		const ::operand_info& cur_element = elelist.elem(i);

		const ::operand_info_specific& cur_specific = cur_element.operand_info_specific();
		if (cur_specific.has_mem_operand()) continue;

		if (cur_specific.reg_operand().name().compare(0, 5, "R_ESP") != 0) continue;

		return letoUint64(cur_element.value());

	}
	return 0;
}

//uint64_t fetchFirstWrittenMemoryLocation(const operand_value_list& elelist) {
//	uint64_t ret = ULONG_MAX;
//	for (int i = 0; i < elelist.elem_size(); i++) {
//		const ::operand_info& cur_element = elelist.elem(i);
//		const ::operand_info_specific& cur_specific = cur_element.operand_info_specific();
//		if (!cur_specific.has_mem_operand()) // Skip if its a non memory location
//			continue;
//		if (!cur_element.operand_usage().written()) continue; // Skip if the location is not written to.
//
//		uint64_t curr = cur_specific.mem_operand().address();
//		if (ret > curr) ret = curr;
//	}
//
//	return ret;
//}

void print_std_frame(frame &cur_frame) {
	const ::std_frame& cur_std_frame = cur_frame.std_frame();

	std::cout << "0x" << std::hex << cur_std_frame.address() << std::dec <<" ";

	uint64_t esp = fetchESPvalue(cur_std_frame.operand_pre_list());

	print_assembly(cur_std_frame.rawbytes(), cur_std_frame.address());
	if (esp == 0){
		std::cout<<std::endl;
		return;
	}

	std::cout << " " << std::hex << esp << std::dec << std::endl;

}

void print_all(const char *f) {
	TraceContainerReader t(f);

	while (!t.end_of_trace()) {
		ctr++;
		std::auto_ptr<frame> cur_frame = t.get_frame();

		if (cur_frame->has_std_frame()) print_std_frame(*cur_frame);
	}

	assert(ctr == t.get_num_frames());
}

int main(int argc, char **argv) {
	if (argc != 2) {
		if (argv[0]) {
			std::cout << "Usage: " << argv[0] << " <trace>" << std::endl;
		}
		exit(1);
	}

	xed_tables_init();

	print_all(argv[1]);
}
