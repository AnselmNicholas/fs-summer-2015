from tempfile import mkstemp
import os
import logging

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
Fetch frame number for frames which calls inputed destination addresses
Input:
    dstAddresses = list of destination address
    trace_file = path to trace file
Output:
    named dictionary of {destination address, frame no}
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
                ret[dstAddr] = ctr

    return ret;

'''
Fetch parameter values for function call
Input:
    trace_file = path to trace file
    frame = frame no of function call
    paramCnt = number of parameter for input function
'''
def fetchParam(trace_file, frame, paramCnt):
    logger = logging.getLogger(__name__)
    
    cmd = "bin/fetchParam {} {} {}".format(trace_file, frame, paramCnt)
    logger.info("Executing: [%s]", cmd)
    with os.popen(cmd) as result:
        rst = result.read()
        
    print rst


def test():
    logger = logging.getLogger(__name__)
    
    functions = {"impossible":0, "test":1, "setuid":1, "main":0, "exit":0, "open":2, "read":3, "close":1, "perror":0}
    trace_file = "~/Desktop/bof1/5802-readme.bpt"
    binary_file = "~/Desktop/bof1/bof1"
    
    dstAddresses = fetchAddressFromGDB(functions.keys(), binary_file)
    logger.info("Output for fetchAddress: %s",dstAddresses)
    
    addrFrameMap = getInstructionAddress(dstAddresses.keys(), trace_file)
    logger.info("Output for getInstructionAddress: %s",addrFrameMap)
    
    frameParamCntMap = [[addrFrameMap[address], functions[dstAddresses[address]]] for address in addrFrameMap.keys()]
        
    for frame, paramCnt in frameParamCntMap:
        fetchParam(trace_file, frame, paramCnt)
        

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test()
