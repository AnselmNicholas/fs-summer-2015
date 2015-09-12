/**
 * Fetch slice candidate in parent
 * Input: <trace> <trace> <frame no of fork> <memorylocationofvariable>
 * Output: <insnno> <index>
 */

//#include <cassert>
//#include <exception>
#include <iostream>
//#include <iomanip>
#include "trace.container.hpp"
//#include <math.h>
//#include <limits.h>

using namespace SerializedTrace;

#define ALIGN_SIZE 1000
uint64_t ctr = 0;
uint64_t cur_frame_counter;

bool hasResult(frame &cur_frame, uint64_t target) {

	if (!cur_frame.has_std_frame()) return false;

	const ::std_frame& cur_std_frame = cur_frame.std_frame();
	if (!cur_std_frame.has_operand_post_list()) return false;

	const operand_value_list& operand_list = cur_std_frame.operand_post_list();
	for (int i = 0; i < operand_list.elem_size(); i++) {
		const ::operand_info& cur_element = operand_list.elem(i);
		const ::operand_info_specific& cur_specific = cur_element.operand_info_specific();
		if (!cur_specific.has_mem_operand())
			continue;

		uint64_t curr = cur_specific.mem_operand().address();

		if (curr == target) {

			std::cout << cur_frame_counter << " " << i << std::endl;
			return true;
		}

	}
	return false;
}

void process(const char *f, uint64_t frameNo, uint64_t target) {
	TraceContainerReader t(f);

	cur_frame_counter = frameNo;

	uint64_t pad_num = cur_frame_counter % ALIGN_SIZE;
	uint64_t ctr = cur_frame_counter;

	if (pad_num) {
		ctr = cur_frame_counter - pad_num;
		t.seek(ctr);
		std::auto_ptr < std::vector<frame> > pad_frames = t.get_frames(pad_num + 1);

		for (uint64_t i = pad_num, j = 0; j < pad_num + 1; i--, j++, cur_frame_counter--)
			if (hasResult(pad_frames->at(i), target)) return;
	}

	if (!ctr) {
		std::cout << "err err" << std::endl;
		return;
	}

	uint64_t multiple = ctr / ALIGN_SIZE;
	ctr -= ALIGN_SIZE;

	for (uint64_t k = 0; k < multiple; ctr -= ALIGN_SIZE, k++) {
		t.seek(ctr);
		//std::cout << std::dec << cur_frame_counter << std::endl;
		std::auto_ptr < std::vector<frame> > pad_frames = t.get_frames(ALIGN_SIZE);
		for (uint64_t i = ALIGN_SIZE - 1, j = 0; j < ALIGN_SIZE; i--, j++, cur_frame_counter--)
			if (hasResult(pad_frames->at(i), target)) return;
	}

	std::cout << "err err" << std::endl;
}

int main(int argc, char **argv) {
	if (argc != 4) {
		if (argv[0]) {
			std::cout << "Usage: " << argv[0] << " <trace> <frame no of fork> <memorylocationofvariable>\nOutput: <insnno> <index>" << std::endl;
		}
		exit(1);
	}

	char *end;
	uint64_t frameNo = strtoul(argv[2], &end, 10);
	uint64_t target = strtoul(argv[3], &end, 16);

	process(argv[1], frameNo, target);
}

