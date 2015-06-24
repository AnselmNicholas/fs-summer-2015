import re
import numpy as np

class Lookahead:
    """Lookahead iterator for efficient parsing

    http://stackoverflow.com/a/1517965/1364256
    """
    def __init__(self, itera):
        self.iter = iter(itera)
        self.buffer = []

    def __iter__(self):
        return self

    def next(self):
        if self.buffer:
            return self.buffer.pop(0)
        else:
            return self.iter.next()

    def lookahead(self, n=0):
        """Return an item n entries ahead in the iteration."""
        while n >= len(self.buffer):
            try:
                self.buffer.append(self.iter.next())
            except StopIteration:
                return None
        return self.buffer[n]


import sys
sys.setrecursionlimit(10000000)
inpt = []




testInput = [("scwuftpd-skiplib.aiesp", "proc-map-wu-ftpd.txt"),
             ("3150-out-noskip.aiesp", "bof1-maps", 90897, 91589),  # 0x804856b, 0x8048588
             ("3577-bof2-noskip.aiesp", "bof2-maps"),
             ("3564-bof2-skip.aiesp", "bof2-maps"),
             ("5802-readme.aiesp", "")  # [91219:91912]
             ]
testChoice = 0
testInput = testInput[testChoice]




# # Init List

functionStack = []
totalCallCnt = totalRetCnt = 0
currentFunctionList = []  # Current function
currentInstrCount = 0

call_cnt = {}

inputFile = testInput[0]



lmin = lmax = -1

if len(testInput) > 2:
    lmin = testInput[2] - 1
    if len(testInput) > 3:
        lmax = testInput[3] - 1

with open(inputFile) as f:
    inpt = Lookahead(f)

    for idx, line in enumerate(inpt):

        if lmin > 0:
            if idx < lmin: continue
        if lmax > 0:
            if idx > lmax: break


        line_input = re.split("\W+", line.strip(), 2)
        address = line_input[0]
        operand = line_input[1]
        remainder = line_input[2] if len(line_input) > 2 else None

        try:
            if operand == "calll":
                target, espValue = remainder.split()

                if not target.startswith("0x") or target[-1] == (")"):  # handle indirect totalCallCnt
                    target = inpt.lookahead().split()[0]

                # print "totalCallCnt {}".format(espValue)
                currentFunctionList.append(line)
                currentInstrCount += 1
                functionStack.append([espValue, currentFunctionList, currentInstrCount, target])
                currentFunctionList = []
                currentInstrCount = 0



                cc = call_cnt.get(target, [0, []])
                cc[0] += 1
                call_cnt[target] = cc

                # print "{:<10} {} {} {}".format(address, header, operand, espValue)
                # display.write("<li>{:<10} {} {} {}<ul>".format(address, header, operand, espValue))
                # header += ":"

                totalCallCnt += 1
            elif operand == "retl":

                remainder = remainder.split()
                if len(remainder) == 1:
                    espValue = '%x' % (int(remainder[0], 16) + 4)  # hex(int(remainder[0], 16) + 4)[2:-1]
                else:
                    espValue = '%x' % (int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)  # hex(int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)[2:-1]

                if functionStack[-1][0] == espValue:

                    currentFunctionList.append(line)
                    currentInstrCount += 1
                    rst = functionStack.pop()
                    t = rst[1]
                    t.append(currentFunctionList)
                    currentFunctionList = t
                    currentInstrCount += rst[2]

                    call_cnt[rst[3]][1].append(currentInstrCount)

                    # print "{:<10} {} {} {}".format(address, header, operand, espValue)
                    # display.write("<li class='lastChild'>{:<10} {} {} {}</li></ul></li>".format(address, header, operand, espValue))
                    # header = header[:-1]

                else:
                    currentFunctionList.append(line)
                    currentInstrCount += 1
                    # print "{:<10} {} {} {} \t\t\t\t Err".format(address, header, operand, espValue)
                    # display.write("<li>{:<10} {} {} {} \t\t\t\t Err</li>".format(address, header, operand, espValue))



                # print "totalRetCnt {}".format(espValue)

                totalRetCnt += 1
                # functionStack.pop()
            else:

                currentFunctionList.append(line)
                currentInstrCount += 1
                # print "{:<10} {} {} {}".format(address, header, operand, remainder)

                # display.write("<li>{:<10} {} {} {}</li>".format(address, header, operand, remainder))
                pass

        except IndexError, e:
            print idx, e, line
            # break


    while len(functionStack):


        rst = functionStack.pop()
        t = rst[1]
        t.append(currentFunctionList)
        currentFunctionList = t
        currentInstrCount += rst[2]

        call_cnt[rst[3]][1].append(currentInstrCount)


# Processing
totalCallCnt = totalRetCnt = 0

def butlast(xs):
    xs = iter(xs)
    prev = xs.next()
    for x in xs:
        yield prev
        prev = x


def processList(xs, header="", debug=False):
    global totalCallCnt
    global totalRetCnt
    for x in butlast(xs):
        if type(x) == list:
            processList(x, header + ":")
        else:
            line_input = re.split("\W+", x, 2)
            address = line_input[0]
            operand = line_input[1]
            remainder = line_input[2] if len(line_input) > 2 else None

            if operand == "calll":

                espValue = remainder.split()[-1]
                # print "totalCallCnt {}".format(espValue)

                if debug: print "{:<10} {} {} {}".format(address, header, operand, espValue)
                display.write("<li>{:<10} {} {} {}<ul>".format(address, header, operand, espValue))
                # header += ":"

                totalCallCnt += 1
            elif operand == "retl":

                remainder = remainder.split()
                if len(remainder) == 1:
                    espValue = '%x' % (int(remainder[0], 16) + 4)  # hex(int(remainder[0], 16) + 4)[2:-1]

                else:
                    espValue = '%x' % (int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)  # hex(int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)[2:-1]





                if debug: print "{:<10} {} {} {} \t\t\t\t Err".format(address, header, operand, espValue)
                display.write("<li>{:<10} {} {} {} \t\t\t\t Err</li>".format(address, header, operand, espValue))



                # print "totalRetCnt {}".format(espValue)

                totalRetCnt += 1

            else:


                if debug: print "{:<10} {} {} {}".format(address, header, operand, remainder)

                display.write("<li>{:<10} {} {} {}</li>".format(address, header, operand, remainder))


    if type(xs[-1]) == list:
        processList(xs[-1], header + ":")
    else:

        line_input = re.split("\W+", xs[-1], 2)
        address = line_input[0]
        operand = line_input[1]
        remainder = line_input[2] if len(line_input) > 2 else None

        if operand == "calll":

#             espValue = remainder.split()[-1]
#             # print "totalCallCnt {}".format(espValue)
#
#             print "{:<10} {} {} {}".format(address, header, operand, espValue)
#             display.write("<li>{:<10} {} {} {}<ul>".format(address, header, operand, espValue))
#
#             totalCallCnt += 1

            raise Exception("Call instr at the end of a list")
        elif operand == "retl":

            remainder = remainder.split()
            if len(remainder) == 1:
                espValue = '%x' % (int(remainder[0], 16) + 4)  # hex(int(remainder[0], 16) + 4)[2:-1]

            else:
                espValue = '%x' % (int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)  # hex(int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)[2:-1]


            if debug: print "{:<10} {} {} {}".format(address, header, operand, espValue)
            display.write("<li class='lastChild'>{:<10} {} {} {}</li>".format(address, header, operand, espValue))


            # print "totalRetCnt {}".format(espValue)

            totalRetCnt += 1
            # functionStack.pop()
        else:
            if debug: print "{:<10} {} {} {}".format(address, header, operand, remainder)

            display.write("<li>{:<10} {} {} {}</li>".format(address, header, operand, remainder))


    display.write("</ul></li>")




# Run


display = open("output.html", "w")
display.write('<script type="text/javascript" src="htmlextra/CollapsibleLists.js">'
              + '</script><script type="text/javascript" src="htmlextra/runOnLoad.js">'
              + '</script><link rel="stylesheet" type="text/css" href="htmlextra/style2.css" />')
display.write('<ul class="collapsibleList"><li>Instructions<ul>')
processList(currentFunctionList)

display.write("</ul>")
display.write('<script>CollapsibleLists.apply();</script>')



print "\n\n"
print "totalCallCnt {} totalRetCnt {} left {}".format(totalCallCnt, totalRetCnt, len(functionStack))

sortCallCnt = []
for key in call_cnt.keys():
    sortCallCnt.append([key, call_cnt[key]])

sortCallCnt.sort(key=lambda x : x[1], reverse=True)

for ele in sortCallCnt[:]:
    # print ele
    print "{} is called {} times. Average instr count is {}. Median is {}. Total instr exec by funct is {}".format(ele[0], ele[1][0], np.mean(ele[1][1]), np.median(ele[1][1]), sum(ele[1][1]))


def getFunctionNameCmd(targetAddress, procFile, debug=False):
    """Print command to execute in console to fetch function name.

    Input:
    targetAddress - address in the form of a hexadecimal string appended with 0x
    procFile - output of /proc/pid/maps
    """
    try:
        targetAddress = int(targetAddress[2:], 16)
    except ValueError:
        print "Dynamic jump detected {}".format(targetAddress)
        return

    for line in open(procFile):
        l2 = line.split()
        src, dst = l2[0].split("-")
        src = int(src, 16)
        dst = int(dst, 16)


        if src <= targetAddress and targetAddress <= dst:
            if debug: print line
            offset = '%x' % (targetAddress - src)  # hex(targetAddress - src)[2:-1]
            location = line.split()[-1]

            print "objdump -d {} | grep {}".format(location, offset)
            return
    print "Not Found {}".format(targetAddress)



print "\n\nRun this on the server to get the list of function names.\n\n"


for ele in sortCallCnt[:]:
    getFunctionNameCmd(ele[0], testInput[1])

