/**
 * Generate a list which shows <Address> <Instruction> <InstructionNo> <EIP>
 * Input: <trace>
 *
 */

#include <cassert>
#include <exception>
#include <iostream>
//#include <iomanip>
#include "trace.container.hpp"
#include <math.h>
//#include <limits.h>

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

uint64_t fetchEIPvalue(const operand_value_list& elelist) {
	for (int i = 0; i < elelist.elem_size(); i++) {
		const ::operand_info& cur_element = elelist.elem(i);

		const ::operand_info_specific& cur_specific = cur_element.operand_info_specific();
		if (cur_specific.has_mem_operand()) continue;

		if (cur_specific.reg_operand().name().compare(0, 5, "R_EIP") != 0) continue;

		return letoUint64(cur_element.value());

	}
	return 0;
}

void print_std_frame(frame &cur_frame) {
	const ::std_frame& cur_std_frame = cur_frame.std_frame();

	std::cout << "0x" << std::hex << cur_std_frame.address() << std::dec ;

	std::cout << " ";
	print_assembly(cur_std_frame.rawbytes(), cur_std_frame.address());

	std::cout << " CTR:" << ctr -1;



	uint64_t eip = 0;

	if (((int) cur_std_frame.rawbytes().at(0) & 0xff) != 0xc3) {
		eip = fetchEIPvalue(cur_std_frame.operand_pre_list());

		if (eip == 0) {// non call
			std::cout << std::endl;
			return;
		}

		eip += cur_std_frame.rawbytes().length();
	} else {
		eip = fetchEIPvalue(cur_std_frame.operand_post_list()); // ret
	}

	std::cout << " EIP:0x" << std::hex << eip << std::dec << std::endl;
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
			std::cout << "Generate a list which shows <Address> <Instruction> <InstructionNo> <EIP>" << std::endl;
			std::cout << "Usage: " << argv[0] << " <trace>" << std::endl;
		}
		exit(1);
	}

	xed_tables_init();

	print_all(argv[1]);
}
