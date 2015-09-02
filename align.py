import difflib
import misc
import logging
from tempfile import mkstemp
import os
import enhanceLogging
from misc import execute

def getFunctionNameCmd2(targetAddress, procFile, debug=False):
    """Print command to execute in console to fetch function name.

    Input:
        targetAddress - address in the form of a hexadecimal string appended with 0x
        procFile - output of gentrace
    """
    try:
        targetAddress = int(targetAddress[2:], 16)
    except ValueError:
        return "Dynamic jump detected {0}".format(targetAddress)

    for line in open(procFile):
        if not line.startswith("This is modload():"): continue
        l2 = line.split()
        src, dst = l2[-2:]
        src = int(src, 16)
        dst = int(dst, 16)

        if src <= targetAddress and targetAddress <= dst:
            if debug: print line
            offset = '%x' % (targetAddress - src)  # hex(targetAddress - src)[2:-1]
            location = l2[3]

            if not location == "0":
                # print "objdump -d {} | grep 'call   {}' -m 1 #0x{:x}".format(location, offset, targetAddress)
                return "{0} {1} 0x{2:x}".format(location, offset, targetAddress)
            else:
                return "#Anon region for 0x{0:x}".format(targetAddress)

    return "#Not Found 0x{0:x}".format(targetAddress)



def process(infile, mlfile):
#     infile = sys.argv[1]
#     mlfile = sys.argv[2]
    calloffset = []
    eips = []
    insns = [-1]
    combined = []
    with open(infile) as f:
        f = misc.Lookahead(f)

        for line in f:
            # print line
            line = line.strip()
            l = line.split()
            if l[1] == "calll":

                if l[2].startswith("0x") and not l[2][-1] == ")":
                    target = l[2]
                    # print " ".join(l[:3]),
                else:
                    target = f.lookahead().split()[0]
                    # print " ".join(l[:3]), target,

                calloffset.append(" ".join(getFunctionNameCmd2(target, mlfile).split()[:-1]))
                insns.append(int(l[-2][4:]))
                eips.append(l[-1][4:])
                combined.append("{} {} {}".format(l[-2], " ".join(getFunctionNameCmd2(target, mlfile).split()[:-1]), l[-1]))
            if l[1] == "retl":
                calloffset.append("retl")
                insns.append(int(l[-2][4:]))
                eips.append(l[-1][4:])
                combined.append("{} {} {}".format(l[-2], "retl", l[-1]))

    return insns, calloffset, eips, combined


def findInstructionIndex(insnList, insn):
    min = 1
    max = len(insnList)
    while True:
        mid = (max + min) / 2
        # print min, max, mid, insnList[mid]
        if insn == insnList[mid]:  # insn is a call
            return mid
        if min == mid:  # insn is between 2 call
            return mid

        if insn > insnList[mid]:
            min = mid
        else:
            max = mid

def findCallIndex(callretList, eipList, idx):
    logger = logging.getLogger(__name__)
    logger.info("Fetching call index for {0}".format(idx))

    idx -= 1  # zero align index

    if callretList[idx] is not "retl": return idx + 1  # one align index

    count = 1
    index = idx
    stack = [eipList[idx]]
    logger.debug("{0} {1}".format(callretList[index], eipList[index]))
    while count >= 0:
        index -= 1
        logger.debug("{0} {1}".format(callretList[index], eipList[index]))
        # print "a{}a".format(callretList[index])
        if callretList[index] is "retl":
            stack.append(eipList[index])
            count += 1
            # print "count++"
        else:
            try:
                while not stack.pop() == eipList[index]:
                    count -= 1
                count -= 1
            except IndexError:  # nothing else to pop. This means that no return for that call has been discovered.
                break
            # print "count--"

    if count:
        raise Exception("Call count is not 0 but {0}.".format(count))
    return index + 1  # one align index

def getAoffset(offsetBtoA, idx):
    min = 0
    max = len(offsetBtoA)
    while True:
        mid = (max + min) / 2
        # print min, max, mid, insnList[mid]
        if idx == offsetBtoA[mid][0]:  # idx is at the edge
            return offsetBtoA[mid - 1][1]
        if min == mid:  # idx is between 2 element
            return offsetBtoA[mid][1]

        if idx > offsetBtoA[mid][0]:
            min = mid
        else:
            max = mid

invalidOffset = "NA"
def align(r1, r2):
    logger = logging.getLogger(__name__)
    diff = difflib.context_diff(r1, r2, n=0, lineterm="")
    diff = misc.Lookahead(diff)
    for i in range(3):diff.next()
    amap = None
    diffMode1 = None
    diffMode2 = None
    offsetBtoA = [[-1, 0]]

    for a in diff:
        logger.debug(a)
        a = a[4:-5]
        a = a.split(",")

        if len(a) > 1:
            logger.debug("Skipping {} - {} + 1 = {}".format(a[1], a[0], int(a[1]) - int(a[0]) + 1))

            if amap is None:
                diffMode1 = diff.lookahead()[0]
                logger.debug("Setting diffMode 1 to {}".format(diffMode1))
            else:
                diffMode2 = diff.lookahead()[0]
                logger.debug("Setting diffMode 2 to {}".format(diffMode2))

            for i in range(int(a[1]) - int(a[0]) + 1):logger.debugv(diff.next())
        else:
            skippable = ["! ", "+ ", "- "]
            if diff.lookahead() is not None:
                if  diff.lookahead()[:2] in skippable:

                    if amap is None:
                        diffMode1 = diff.lookahead()[0]
                        logger.debug("Setting diffMode 1 to {}".format(diffMode1))
                    else:
                        diffMode2 = diff.lookahead()[0]
                        logger.debug("Setting diffMode 2 to {}".format(diffMode2))

                    logger.debug("Skipping single")
                    logger.debugv(diff.next())


        if amap is None:
            amap = a
        else:
            logger.debug("{} {} {} {}".format(amap, a, diffMode1, diffMode2))


            if diffMode1 == "!" and diffMode2 == "!":
                difference1 = int(amap[-1]) - int(amap[0]) + 1
                difference2 = int(a[-1]) - int(a[0]) + 1
                difference = difference2 - difference1

                newoffset = offsetBtoA[-1][1] - difference

                # print difference1, difference2, difference, offsetBtoA[-1][1], newoffset

                preva = int(a[0]) - 1

                logger.debug("offsetBtoA insert [ {} , {} ]".format(preva, invalidOffset))
                offsetBtoA.append([preva, invalidOffset])

                logger.debug("offsetBtoA insert [ {} , {} ]".format(a[-1], newoffset))
                offsetBtoA.append([int(a[-1]), newoffset ])


            elif diffMode1 == None and diffMode2 == "+":  # New line in 2
                difference = int(a[-1]) - int(a[0]) + 1
                newoffset = offsetBtoA[-1][1] - difference

                preva = int(a[0]) - 1

                logger.debug("offsetBtoA insert [ {} , {} ]".format(preva, invalidOffset))
                offsetBtoA.append([preva, invalidOffset])

                logger.debug("offsetBtoA insert [ {} , {} ]".format(a[-1], newoffset))
                offsetBtoA.append([int(a[-1]), newoffset ])

            elif diffMode1 == "-" and diffMode2 == None:  # Line missing from 1
                difference = int(amap[-1]) - int(amap[0]) + 1
                newoffset = offsetBtoA[-1][1] + difference

                logger.debug("offsetBtoA insert [ {} , {} ]".format(a[-1], newoffset))
                offsetBtoA.append([int(a[-1]), newoffset ])

            else:
                raise Exception("Unknown diffMode combination {} {}".format(diffMode1, diffMode2))

            amap = None
            diffMode1 = None
            diffMode2 = None
            if diff.lookahead() is not None:
                logger.debug("Skipping divider")
                logger.debug(diff.next())

    return offsetBtoA



def runAlign(infile1, mlfile1, infile2, mlfile2, targetinsn, writediffresult=False):
    """
    Align an instruction in trace 2 to the corresponding function in trace 1

    Input
        infile1 - path to ain of trace 1
        mlfile1 - path to modload of trace 1
        infile2 - path to ain of trace 2
        mlfile2 - path to modload of trace 2
        targetinsn - int - insn of an instruction in the function to be aligned

    Output
        instructionNo
        functionNo
    """
    logger = logging.getLogger(__name__)
#     infile1 = "test1/scalign-wuftpd-skiplib-5.ain"
#     mlfile1 = "test1/align-wuftpd-skiplib-5.modload"
#     infile2 = "test1/scalign-err-wuftpd-skiplib-4.ain"
#     mlfile2 = "test1/align-err-wuftpd-skiplib-4.modload"
#     writediffresult = False
#
#     targetinsn = 1123206


    insn1, r1, eips1, c1 = process(infile1, mlfile1)
    insn2, r2, eips2, c2 = process(infile2, mlfile2)

    if writediffresult:
        logger.info("Writing diff result to file.")
        with open("o1-align", "w") as f:
            for line in c1:
                f.write(line + "\n")

        with open("o2-align", "w") as f:
            for line in c2:
                f.write(line + "\n")

        d = difflib.HtmlDiff()
        with open("diffout.html", "w") as f:
            f.write(d.make_file(r1, r2, "Benign", "Error"))

#     def combineJunk(x):
#         return x[:4] in ["RET:", "CTR:"]
#
#
#     d = difflib.SequenceMatcher(combineJunk,c1,c2)
#     with open("diffout1.html", "w") as f:
#         f.write(d.make_file(c1, c2, "Benign", "Error"))

    offsetBtoA = align(r1, r2)

    for l in offsetBtoA:
        logger.debug(l)

    idx = findInstructionIndex(insn2, targetinsn)
    logger.info("Nearest call/ret to insn {0} is {1}.".format(targetinsn, idx))
    idx = findCallIndex(r2, eips2, idx)
    logger.info("Function no for insn in error trace is {0}.".format(idx))

    ofst = getAoffset(offsetBtoA, idx)
    logger.info("Offset for mapping error to benign is {0}".format(ofst))
    if ofst == invalidOffset:
        logger.warn("Unable to determine align offset")
        #raise Exception("Unable to determine align offset")
        return ofst, ofst

    functionNo = idx + ofst
    instructionNo = insn1[functionNo]

    logger.info("Input insn was mapped to insn {} funct {}".format(instructionNo, functionNo))
    return instructionNo, functionNo

def genAIN(trace, bindir=os.path.dirname(os.path.realpath(__file__)) + "/bin/", cache=False):
    """
    Generate ain of trace

    Input:
        trace - path to trace file
        bindir - path to the directory containing bin

    Output:
        path to ain file
    """
    logger = logging.getLogger(__name__)

    handler, name = mkstemp()
    logger.info("Temp ain file created at " + name)

    cmd = "{0}fetchAIN {1}".format(bindir, trace)

    rst = execute(cmd, cache)

    with open(name, "w") as f:
            f.write(rst)

    logger.info("ain generated")
    return name

def run(traceBenign, modloadBenign, traceError, modloadError, errorInsn, generateAin=True , writediffresult=False):
    if generateAin:
        nameAINBenign = genAIN(traceBenign)
        nameAINError = genAIN(traceError)
    else:
        nameAINBenign = traceBenign
        nameAINError = traceError
    insn, functn = runAlign(nameAINBenign, modloadBenign, nameAINError, modloadError, errorInsn, writediffresult)


    if generateAin:
        os.unlink(nameAINBenign)
        os.unlink(nameAINError)

    return insn, functn

def main():
    def check_errorInsn(value):
        ivalue = int(value)
        if ivalue < 0:
            raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
        return ivalue

    import argparse
    parser = argparse.ArgumentParser(description="Align benign with error trace and return benign insn given error insn")
    parser.add_argument("traceBenign", help="Path to trace file (*.bpt).")
    parser.add_argument("modloadBenign", help="Output of gentrace.")

    parser.add_argument("traceError", help="Path to trace file (*.bpt).")
    parser.add_argument("modloadError", help="Output of gentrace.")

    parser.add_argument("errorInsn", type=check_errorInsn, help="Instruction no of the memory error")
    parser.add_argument('--write-diff-result', dest='writediffresult', action='store_true', help="Output the result of parsing ain and diff to file for debugging.")
    parser.add_argument('--ain-input', dest='generateAin', action='store_false', help="Use input ain file instead of generating from input *.bpt.")
    parser.add_argument('-v', '--verbose', action='count', default=0)

    args = parser.parse_args()
    if not os.path.exists(args.traceBenign):
        parser.error("trace file do not exist");
    if not os.path.exists(args.modloadBenign):
        parser.error("modload file do not exist");
    if not os.path.exists(args.traceError):
        parser.error("trace file do not exist");
    if not os.path.exists(args.modloadError):
        parser.error("modload file do not exist");

    if args.verbose == 1: logging.basicConfig(level=logging.INFO)
    if args.verbose > 1: logging.basicConfig(level=logging.DEBUG)

    insn, functn = run(args.traceBenign, args.modloadBenign, args.traceError, args.modloadError, args.errorInsn, args.generateAin, args.writediffresult)
    print insn, functn

if __name__ == "__main__":
    main()


