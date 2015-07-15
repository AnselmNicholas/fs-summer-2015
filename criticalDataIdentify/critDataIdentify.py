from tempfile import mkstemp
import os
import logging
import argparse
import re
import shlex

'''
Use gdb to find address of function.
Input:
    functions = list of function name
    binary = path to binary file
    source = path to source file for stripped binary
Output:
    named dictionary of {function address:function name}
'''
def fetchAddressFromGDB(functions, binary, source=""):
    logger = logging.getLogger(__name__)
    
    logger.info("Fetching addresse for %i function %s from binary [%s] with source [%s]", len(functions), functions, binary, source)
    
    handler, name = mkstemp()
    logger.info("Created temp file %s as input for gdb command", name)
    ret = {}
    
    
    try:
        logger.info("Writing gdb command file")
        with open(name, "w") as f:
            f.write("set width 0\nset height 0\nset verbose off\n")
            f.write("python\r\ndef ignore_error(arg):\r\n\ttry:\r\n\t\tgdb.execute (arg)\r\n\texcept:\r\n\t\tgdb.execute(\"print \\\"\" + \"ERROR: \" + arg + \"\\\"\")\r\n")
            
            '''
            writing the following python code to file to handle gdb quitting on scripting error. Taken from 
            http://stackoverflow.com/questions/17923865/gdb-stops-in-a-command-file-if-there-is-an-error-how-to-continue-despite-the-er
            
            python
            def ignore_error(arg):
              try:
                gdb.execute (arg)
              except:
                gdb.execute("print \"" + "ERROR: " + arg + "\"")
            '''
            
            
            for function in functions:
                logger.debug("Adding address check for function %s", function)
                f.write("ignore_error(\"p " + function + "\")\n")
        logger.info("Finish writing gdb command file")
        
        
        with open(name, "r") as f:
            logger.debug("Content of log file is:\n%s", f.read())
        
        cmd = "gdb --batch --command=" + name + " " + binary
        logger.info("Executing: [%s]", cmd)
        with os.popen(cmd) as result:
            rst = result.read()        
            logger.debug("Result:\n%s", rst)
            
            rst = rst.splitlines()
            
            assert len(rst) == len(functions), "Result count from GDB is not euqal to no of input functions"
            
            for idx, function in enumerate(functions):
                logger.debug("Getting address of [%i] %s from %s", idx, function, rst[idx])
                if "ERROR: p " + function in rst[idx]:
                    # ret.append({None:function})
                    logger.info("Address of function %s is unknown", function)
                else:
                    address = rst[idx].rsplit(" ", 2)[1]
                    # ret.append({address:function})
                    ret[address] = function
                    logger.info("Address of function %s is %s", function, address)
        
    except Exception, e:
        logging.error("Fetching address from GDB", exc_info=True)

    finally:
        logger.info("Removing GDB command file [%s]", name)
        os.unlink(name)
    
    return ret

'''
Use objdump to find address of function.
Input:
    functions = list of function name
    binary = path to binary file
    source = path to source file for stripped binary
Output:
    named dictionary of {function address:function name}
'''
def fetchAddressFromObjdump(functions, binary, source=""):
    logger = logging.getLogger(__name__)
    
    logger.info("Fetching addresse for %i function %s from binary [%s] with source [%s]", len(functions), functions, binary, source)
    
    # objdump -t ~/Desktop/bof1/bof1 | grep "g     F"
    # objdump -j.plt -d ~/Desktop/bof1/bof1
    ret = {}
    parseResult = {}
    
    cmd = "objdump -j.plt -d " + binary
    logger.info("Executing: [%s]", cmd)
    with os.popen(cmd) as result:
        rst = result.read()        
        logger.debug("Result:\n%s", rst)
        
        rst = rst.splitlines()
        
        for result in rst:
            
            if not "@plt>" in result:
                logger.debug("Skipping %s", result)
                continue
            
            addr, funct = result.split()
            funct, _ = funct.split("@")
            funct = funct[1:]
            addr = addr.lstrip("0")
            logger.debug("Split [%s] [%s]", addr, funct)
            
            parseResult[funct] = addr
    
    cmd = 'objdump -t ' + binary + ' | grep "g     F"'
    logger.info("Executing: [%s]", cmd)
    with os.popen(cmd) as result:
        rst = result.read()        
        logger.debug("Result:\n%s", rst)
        
        rst = rst.splitlines()
        for result in rst:
            addr, _, _, _, _, funct = re.split("\W+", result, 5)
            addr = addr.lstrip("0")
            logger.debug("Split [%s] [%s]", addr, funct)
            
            parseResult[funct] = addr
    
     
    for idx, function in enumerate(functions):
        logger.debug("Getting address of [%i] %s", idx, function)
        
        if not function in parseResult.keys():
            # ret.append({None:function})
            logger.info("Address of function %s is unknown", function)
        else:
            address = "0x" + parseResult[function]
            # ret.append({address:function})
            ret[address] = function
            logger.info("Address of function %s is %s", function, address)
      
    return ret 

'''
Fetch frame number for frames which calls inputed destination addresses
Input:
    dstAddresses = list of destination address
    trace_file = path to trace file
Output:
    named dictionary of {destination address:[frame nos]}
'''
def getInstructionAddress(dstAddresses, trace_file):
    logger = logging.getLogger(__name__)
    
    ret = {};
    
    cmd = "bin/fetchCallFromTrace " + trace_file
    logger.info("Executing: [%s]", cmd)
    with os.popen(cmd) as result:
        rst = result.read()        
        logger.debug("Result:\n%s", rst)
        
        rst = rst.splitlines()
        
        for result in rst:
            instrAddr, _, dstAddr, _, ctr = result.split()
            logger.debug("Checking instruction %s with destination %s frameno %s", instrAddr, dstAddr, ctr)
        
            if dstAddr in dstAddresses:
                logger.info("%s is called at %s with frame no %s", dstAddr, instrAddr, ctr)
                # ret.append({dstAddr:ctr})
                try:
                    ret[dstAddr].append(ctr)
                except KeyError:
                    ret[dstAddr] = [ctr]

    return ret;

'''
Fetch parameter values for function call
Input:
    trace_file = path to trace file
    frame = frame no of function call
    paramCnt = number of parameter for input function
Ouput:
    list of frameno, first memory address pair -> [[123,ff123],[456,ff456]]
'''
def fetchParam(trace_file, frame, paramCnt):
    logger = logging.getLogger(__name__)
    
    cmd = "bin/fetchParam {0} {1} {2}".format(trace_file, frame, paramCnt)
    logger.info("Executing: [%s]", cmd)
    with os.popen(cmd) as result:
        rst = result.read()
        
    logger.debug("Result:\n%s", rst)
    
    rst = rst.splitlines()
    ret = []
    for result in rst:
        
        if not result.startswith("First memory location"):
            logger.debug("Skipping %s", result)
            continue
        
        result = result.split()
        
        ret.append([result[6], result[3]])
            
    return ret

def test():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    functions = {"impossible":0, "test":1, "setuid":1, "main":0, "exit":0, "open":2, "read":3, "close":1, "perror":0}
    trace_file = "~/Desktop/bof1/5802-readme.bpt"
    binary_file = "~/Desktop/bof1/bof1"
    
#     dstAddresses = fetchAddressFromGDB(functions.keys(), binary_file)
#     logger.info("Output for fetchAddress: %s", dstAddresses)
    
    
    dstAddresses = fetchAddressFromObjdump(functions.keys(), binary_file)
    logger.info("Output for fetchAddress: %s", dstAddresses)
    
    addrFrameMap = getInstructionAddress(dstAddresses.keys(), trace_file)
    logger.info("Output for getInstructionAddress: %s", addrFrameMap)
     
    frameParamCntMap = [[addrFrameMap[address], functions[dstAddresses[address]]] for address in addrFrameMap.keys()]
         
    for frame, paramCnt in frameParamCntMap:
        firstMemoryFrameNo = fetchParam(trace_file, frame, paramCnt)
        logger.info("Output for fetchParam: %s", firstMemoryFrameNo)
'''
Output:
     Dict of Dict of list keyed to function name followed by function call frame followed by a list of frameno, first memory address pair for critical data
    
     Example 
     {
    'open': {
         '91227': [['91226','ffb821e4'],['91225','ffb821e8']]
         '91240': [['91239','ffb821e4'],['91228','ffb821e8']]
         }    
     }
     
'''        
def run(functions_file, trace_file, binary_file, use_gdb=False):
    logger = logging.getLogger(__name__)
    
    logger.info("Reading input file %s", functions_file)
    
    functions = {}
    with open(functions_file, "r") as functF:
        logger.debug("Opened function file")
        
        function_file_content = functF.read()
        logger.debug("Content is \n%s", function_file_content)
        
        lexer = shlex.shlex(function_file_content, posix=True)
        
        functionName = lexer.get_token()
        paramCnt = lexer.get_token()
        
        while(functionName is not None and paramCnt is not None):
            logger.info("Added %s:%s", functionName, paramCnt)
            functions[functionName] = paramCnt
            functionName = lexer.get_token()
            paramCnt = lexer.get_token()
                
    if (use_gdb):
        dstAddresses = fetchAddressFromGDB(functions.keys(), binary_file)
    else:
        dstAddresses = fetchAddressFromObjdump(functions.keys(), binary_file)
        
    logger.info("Output for fetchAddress: %s", dstAddresses)
    
    addrFrameMap = getInstructionAddress(dstAddresses.keys(), trace_file)
    logger.info("Output for getInstructionAddress: %s", addrFrameMap)
    
    # frameParamCntMap = [[frame, functions[dstAddresses[address]]] for address in addrFrameMap.keys() for frame in addrFrameMap[address]]
        
    # for frame, paramCnt in frameParamCntMap: 
    #    fetchParam(trace_file, frame, paramCnt)
    
    ret = {}
    for address in addrFrameMap.keys():
        for frame in addrFrameMap[address]:
            logger.info("Function: {0}, Frame: {1}".format(dstAddresses[address], frame))
            firstMemoryFrameNo = fetchParam(trace_file, frame, functions[dstAddresses[address]])
            ret.setdefault(dstAddresses[address], {})[frame] = firstMemoryFrameNo
            logger.info("Output for fetchParam: %s", firstMemoryFrameNo)
            
    logger.info("returning: {0}".format(ret))
    return ret
    
def main():
    parser = argparse.ArgumentParser(description="Identify critical data from trace file")
    parser.add_argument("functions", help="File containing a list of functions and their argument count. Stored in the format <function name> <paramcnt> \\n")
    parser.add_argument("trace", help="Path to trace file (*.bpt).")
    parser.add_argument("binary", help="Path to binary file.")
    parser.add_argument('--gdb', dest='use_gdb', action='store_true', help="Use gdb instead of objdump")
    parser.add_argument('-v', '--verbose', action='count', default=0)
    
    args = parser.parse_args()
    if not os.path.exists(args.functions):
        parser.error("functions file do not exist");
    if not os.path.exists(args.trace):
        parser.error("trace file do not exist");
    if not os.path.exists(args.binary):
        parser.error("binary file do not exist");

    if args.verbose == 1: logging.basicConfig(level=logging.INFO)
    if args.verbose > 1: logging.basicConfig(level=logging.DEBUG)
    
    run(args.functions, args.trace, args.binary, args.use_gdb)
    
if __name__ == "__main__":
    main()
