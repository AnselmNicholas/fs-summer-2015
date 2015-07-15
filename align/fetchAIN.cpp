/**
 * Generate a list which shows <Address> <Instruction> <InstructionNo>
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

void my_to_string(std::string mystring) {
int length = mystring.length();
for (int i = 0; i < length; i++)
std::cout << " " << std::setw(2) << std::setfill('0') << std::hex << ((int) mystring.at(i) & 0xff) << std::dec;
return;
}

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

void print_element(const ::operand_info& cur_element) {
const ::operand_info_specific& cur_specific = cur_element.operand_info_specific();
if (cur_specific.has_reg_operand())
std::cout << cur_specific.reg_operand().name();
else if (cur_specific.has_mem_operand()) std::cout << std::hex << cur_specific.mem_operand().address() << std::dec;

std::cout << "\tbitlen: " << cur_element.bit_length();

std::cout << "\tT[";
if (cur_element.taint_info().has_no_taint())
std::cout << 0;
else if (cur_element.taint_info().has_taint_id())
std::cout << cur_element.taint_info().taint_id();
else
std::cout << -1;
std::cout << "]\tvalue:";
my_to_string(cur_element.value());
std::cout << std::endl;
}

void print_list(const ::operand_value_list & cur_list) {
for (int i = 0; i < cur_list.elem_size(); i++) {
	std::cout << "   [" << i << "] ";
	print_element(cur_list.elem(i));
}

std::cout << std::endl;
}

void print_memory_values(frame &cur_frame)
{
	const ::std_frame& cur_std_frame = cur_frame.std_frame();

	if(cur_std_frame.has_operand_post_list())
	{
		//std::cout << "  post_list:" << std::endl;
		print_list(cur_std_frame.operand_post_list());
	}
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


//uint64_t fetchESPvalue(const operand_value_list& elelist) {
//	for (int i = 0; i < elelist.elem_size(); i++) {
//		const ::operand_info& cur_element = elelist.elem(i);
//
//		const ::operand_info_specific& cur_specific = cur_element.operand_info_specific();
//		if (cur_specific.has_mem_operand()) continue;
//
//		if (cur_specific.reg_operand().name().compare(0, 5, "R_ESP") != 0) continue;
//
//		return letoUint64(cur_element.value());
//
//	}
//	return 0;
//}

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

uint64_t fetchFirstWrittenMemoryLocation(const operand_value_list& elelist) {
	uint64_t ret = ULONG_MAX;
	for (int i = 0; i < elelist.elem_size(); i++) {
		const ::operand_info& cur_element = elelist.elem(i);
		const ::operand_info_specific& cur_specific = cur_element.operand_info_specific();
		if (!cur_specific.has_mem_operand()) // Skip if its a non memory location
			continue;
		if (!cur_element.operand_usage().written()) continue; // Skip if the location is not written to.

		uint64_t curr = cur_specific.mem_operand().address();
		if (ret > curr) ret = curr;
	}

	return ret;

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









//
//	//todo: check if <frameNo> is a call instruction with opcode E8.
//	bool paramChecker[paramCnt];
//	memset(paramChecker, 0, paramCnt);
//
//	uint32_t numParamRemain = paramCnt;
//	uint32_t maxEspOffset = paramCnt * 4;
//	while (numParamRemain > 0 && ctr > 0) {
//		ctr--;
//
//		t.seek(ctr);
//		cur_frame = t.get_frame();
//		//print_std_frame(*cur_frame);
//
//		const ::std_frame& cur_std_frame = cur_frame->std_frame();
//
//		uint64_t cesp = fetchESPvalue(cur_std_frame.operand_pre_list());
//
//		if (cesp == 0) continue;
//		if (cesp - esp > maxEspOffset) {
//			std::cout << "Stopping as " << ctr << " as frame's esp offset from call is greater than 4*paramCnt" << std::endl;
//			break; //Stop earlier and not at frame 1 if incorrect paramCnt is inputted.
//			//continue; //Switch back to continue if it causes error.
//		}
//
//		uint64_t memLoc = fetchFirstWrittenMemoryLocation(cur_std_frame.operand_pre_list());
//		uint64_t diff = memLoc - esp;
//
//		uint64_t paramIdx = diff / 4;
//
//		if (paramIdx >= paramCnt) continue;
//		if (paramChecker[paramIdx]) continue;
//
//		paramChecker[paramIdx] = true;
//		numParamRemain--;
//
//		std::cout << "First memory location " << std::hex << memLoc << std::dec << " Frame No " << ctr << std::endl;
//		std::cout << "Parameter: " << paramIdx + 1 << ", Offset from ESP: " << diff << std::endl;
//		//print_std_frame(*cur_frame);
//		print_memory_values(*cur_frame);
//
//	}
//
//	if (numParamRemain > 0) std::cout << "Error: Could only find " << paramCnt - numParamRemain << " out of " << paramCnt << " parameters." << std::endl;

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
			std::cout << "Generate a list which shows <Address> <Instruction> <InstructionNo>" << std::endl;
			std::cout << "Usage: " << argv[0] << " <trace>" << std::endl;
		}
		exit(1);
	}

	xed_tables_init();

//	char *end;
//	uint64_t frameNo = strtoul(argv[2], &end, 10);
//	uint32_t paramCnt = strtoul(argv[3], &end, 10);

	//std::cout << frameNo << " " << paramCnt << std::endl;
	print_all(argv[1]);
}
