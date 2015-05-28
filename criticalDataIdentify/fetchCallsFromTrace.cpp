/**
 * Fetches Call instruction in the form
 * <Instruction Address> call <Destination Address> ctr <Frame Count>
 *
 */

#include <cassert>
#include <exception>
#include <iostream>
#include <iomanip>
#include "trace.container.hpp"
#include <math.h>

using namespace SerializedTrace;

uint64_t ctr = 0;

void print_std_frame(frame &cur_frame) 
{
	const ::std_frame& cur_std_frame = cur_frame.std_frame();

	//Checks for call instruction with opcode 0xE8
	if (((int)cur_std_frame.rawbytes().at(0) & 0xff) != 0xe8) return;

	//Fetch destination offset
	std::string offset = cur_std_frame.rawbytes().substr(1,std::string::npos);

	//Convert to int
	int length = offset.length();
	int32_t amt = 0;
	for(int i = 0; i < length; i++){
		amt += (offset.at(i) & 0xff) * (int32_t)pow(256,i);
		//std::cout << ((int) offset.at(i) & 0xff) << "*" <<pow(256,i)<<"="<< ((int) offset.at(i) & 0xff) * pow(256,i) <<" ";
	}


#ifdef HHPIN32
	std::cout << "0x" << std::setw(8) << std::setfill('0') 
#else
	std::cout << "0x" 
#endif
              << std::hex << cur_std_frame.address() << " call ";

#ifdef HHPIN32
	std::cout << "0x" << std::setw(8) << std::setfill('0')
#else
	std::cout << "0x"
#endif
			<< std::hex  << cur_std_frame.address()+cur_std_frame.rawbytes().length()+amt;

	std::cout << " ctr "<< std::dec << ctr - 1 ;
	std::cout << std::endl;

}

void print_all(const char *f) 
{
	TraceContainerReader t(f);

	while (!t.end_of_trace()) 
	{
		ctr++;
		std::auto_ptr<frame> cur_frame = t.get_frame();

		if(cur_frame->has_std_frame())
			print_std_frame(*cur_frame);
	}

	assert(ctr == t.get_num_frames());
}

int main(int argc, char **argv) 
{
	if (argc != 2) {
		if (argv[0]) {
			std::cout << "Usage: " << argv[0] << " <trace>" << std::endl;
		}
		exit(1);
	}

	print_all(argv[1]);
}

