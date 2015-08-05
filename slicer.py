import logging
import subprocess

slice_cache = {}
print "Init slice cache"

def get(trace, insn, index=0):
    """Fetch slice result from cache perform a slice
    """
    logger = logging.getLogger(__name__)

    logger.debug("Fetching slice result of {insn}:{index} from {trace}".format(trace=trace, insn=insn, index=index))
    slicedDFG = slice_cache.get((trace, insn, index), None)
    
    if slicedDFG is None:
        slicedDFG = slice(trace, insn, index)
        slice_cache[(trace, insn, index)] = slicedDFG

    return slicedDFG

def slice(trace, insn, index=0, arch=32):
    """Perform the slice and return the result as a string.

    Executes the following command
        binslicer-{arch} {trace} {insn}:0
    """
    logger = logging.getLogger(__name__)

    logger.info("Slicing %s at %s", trace, insn)

    cmd = "binslicer-{arch} {trace} {insn}:{index}".format(arch=arch, trace=trace, insn=insn, index=index)
    logger.debug("Executing command: " + cmd)

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)

    stdout = p.stdout
    stderr = p.stderr
    with stdout as result:
        with stderr as err:
            errTxt = err.read()
            if errTxt:
                logger.error("Error in command:\n" + errTxt)
                raise Exception("Error executing command: " + cmd)

        rst = result.read()
        logger.debugv("Result:\n%s", rst)

    return rst
