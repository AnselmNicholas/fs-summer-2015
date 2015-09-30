/**
 * Prepare trace for input to the SMT solver
 * Input: <trace> <slice_insn> <output trace name>
 *
 */

#include <cassert>
#include <exception>
#include <iostream>
#include <iomanip>
#include "trace.container.hpp"
#include <math.h>
#include <limits.h>
#include <fstream>
#include <vector>

extern "C" {
#include "xed-interface.h"
}

using namespace SerializedTrace;

// for disassembly
#define LINE_SIZE 1024
char line[LINE_SIZE] = {0};
uint64_t ctr = 0;

std::vector<uint64_t> slice_insn;

bool isTainted(frame &cur_frame) {
	const ::std_frame& cur_std_frame = cur_frame.std_frame();

	if (cur_std_frame.has_operand_pre_list()) {
		for (int i = 0; i < cur_std_frame.operand_pre_list().elem_size(); i++) {
			if (!cur_std_frame.operand_pre_list().elem(i).taint_info().has_no_taint() && (cur_std_frame.operand_pre_list().elem(i).operand_usage().read() || cur_std_frame.operand_pre_list().elem(i).operand_usage().base())) return true;
		}
	}
	if (cur_std_frame.has_operand_post_list()) {
		for (int i = 0; i < cur_std_frame.operand_post_list().elem_size(); i++) {
			if (!cur_std_frame.operand_post_list().elem(i).taint_info().has_no_taint() && (cur_std_frame.operand_pre_list().elem(i).operand_usage().read() || cur_std_frame.operand_pre_list().elem(i).operand_usage().base())) return true;
		}
	}
	return false;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		if (argv[0]) {
			std::cout << "Usage: " << argv[0] << " <trace> <slice_insn> <output trace name>" << std::endl;
		}
		exit(1);
	}

	std::ifstream infile(argv[2]);
	std::string line;
	char *end;
	while (std::getline(infile, line))
	{
		if (line == "") continue;
		uint64_t insn_no = strtoul(line.c_str(), &end, 10);
		slice_insn.push_back(insn_no);
		//std::cout << insn_no << std::endl;

	}
	std::sort(slice_insn.begin(), slice_insn.end());

	std::cout << "Adding the following insn from slice";
	for (std::vector<uint64_t>::iterator it=slice_insn.begin(); it!=slice_insn.end(); ++it)
		std::cout << ' ' << *it;
	std::cout << '\n';

	char *outputName = "test.bpt";
	if (argc == 4)
		outputName = argv[3];

	TraceContainerReader tr(argv[1]);
	TraceContainerWriter tw(outputName, tr.get_arch(), tr.get_machine(), tr.get_frames_per_toc_entry(), false);

	uint64_t current_slice_insn_idx = 0;
	while (!tr.end_of_trace())
	{
		ctr++;
		std::auto_ptr<frame> cur_frame = tr.get_frame();
		if (isTainted(*cur_frame)){
			tw.add(*cur_frame);
			continue;
		}

		if (current_slice_insn_idx < slice_insn.size()){
			if (ctr-1 == slice_insn[current_slice_insn_idx]){
				tw.add(*cur_frame);

				std::cout << "Added " << ctr - 1 << " at " << tw.get_num_frames()-1 << std::endl;


				current_slice_insn_idx++;
				continue;
			}
		}

	}
	assert(ctr == tr.get_num_frames());
	//assert(tw.get_num_frames() == tr.get_num_frames());
	tw.finish();
	std::cout << "New trace has " << tw.get_num_frames() << "/" << ctr <<" frames."<< std::endl;
}

