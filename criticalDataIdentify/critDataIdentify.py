from tempfile import mkstemp
import os
import logging

logging.basicConfig(level=logging.INFO)    

# logger.setLevel(logging.DEBUG)

def fetchAddressFromGDB(functions, binary, source=""):
    logger = logging.getLogger(__name__)
    
    logger.info("Fetching addresse for %i function %s from binary [%s] with source [%s]", len(functions), functions, binary, source)
    
    handler, name = mkstemp()
    logger.info("Created temp file %s as input for gdb command", name)
    ret = []
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
                    ret.append(None)
                    logger.info("Address of function %s is unknown", function)
                else:
                    address = rst[idx].rsplit(" ", 2)[1]
                    ret.append(address)
                    logger.info("Address of function %s is %s", function, address)
        
    except Exception, e:
        logging.error("Fetching address from GDB", exc_info=True)

    finally:
        logger.info("Removing GDB command file [%s]", name)
        os.unlink(name)
    
    return ret

def getInstructionAddress(dstAddresses, trace_file):
    logger = logging.getLogger(__name__)
    
    cmd = "bin/fetchCallFromTrace-64 " + trace_file
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
#         assert len(rst) == len(functions), "Result count from GDB is not euqal to no of input functions"
#         
#         for idx, function in enumerate(functions):
#             logger.debug("Getting address of [%i] %s from %s", idx, function, rst[idx])
#             if "ERROR: p " + function in rst[idx]:
#                 ret.append(None)
#                 logger.info("Address of function %s is unknown", function)
#             else:
#                 address = rst[idx].rsplit(" ", 2)[1]
#                 ret.append(address)
#                 logger.info("Address of function %s is %s", function, address)
    
dstAddresses = fetchAddressFromGDB(["impossible", "test", "setuid", "main", "exit","open","read","close","perror"], "~/Desktop/bof1/bof1")

getInstructionAddress(dstAddresses, "~/Desktop/bof1/5802-readme.bpt")

        
