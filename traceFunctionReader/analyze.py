import re


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

    def lookahead(self, n=1):
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
             ("5802-readme.aiesp", "bof1-maps"),
             ("3577-bof2-noskip.aiesp", "bof2-maps"),
             ("3564-bof2-skip.aiesp", "bof2-maps")
             ]
testChoice = 0





inputFile = testInput[testChoice][0]

for line in open(inputFile):
    inpt.append(line.strip())

# # Init List

stack = []
call = ret = 0
cur = []  # Current function

call_cnt = {}

inpt = Lookahead(inpt)
for idx, line in enumerate(inpt):  # [91219:91912]
    line_input = re.split("\W+", line, 2)
    address = line_input[0]
    operand = line_input[1]
    remainder = line_input[2] if len(line_input) > 2 else None



    try:
        if operand == "calll":
            target, espValue = remainder.split()
            # print "call {}".format(espValue)
            cur.append(line)
            stack.append([espValue, cur])
            cur = []

            if not target.startswith("0x") or target[-1] == (")"):  # handle indirect call
                target = inpt.lookahead().split()[0]

            call_cnt[target] = call_cnt.get(target, 0) + 1



            # print "{:<10} {} {} {}".format(address, header, operand, espValue)
            # display.write("<li>{:<10} {} {} {}<ul>".format(address, header, operand, espValue))
            # header += ":"

            call += 1
        elif operand == "retl":

            remainder = remainder.split()
            if len(remainder) == 1:
                espValue = hex(int(remainder[0], 16) + 4)[2:-1]

            else:
                espValue = hex(int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)[2:-1]




            if stack[-1][0] == espValue:

                cur.append(line)
                t = stack.pop()[1]
                t.append(cur)
                cur = t

                # print "{:<10} {} {} {}".format(address, header, operand, espValue)
                # display.write("<li class='lastChild'>{:<10} {} {} {}</li></ul></li>".format(address, header, operand, espValue))
                # header = header[:-1]


            else:
                cur.append(line)
                # print "{:<10} {} {} {} \t\t\t\t Err".format(address, header, operand, espValue)
                # display.write("<li>{:<10} {} {} {} \t\t\t\t Err</li>".format(address, header, operand, espValue))



            # print "ret {}".format(espValue)

            ret += 1
            # stack.pop()
        else:

            cur.append(line)
            # print "{:<10} {} {} {}".format(address, header, operand, remainder)

            # display.write("<li>{:<10} {} {} {}</li>".format(address, header, operand, remainder))
            pass
    except Exception, e:
        print idx, e, line
        # break


while len(stack):
    t = stack.pop()[1]
    t.append(cur)
    cur = t






# Processing
call = ret = 0

def butlast(xs):
    xs = iter(xs)
    prev = xs.next()
    for x in xs:
        yield prev
        prev = x


def processList(xs, header="", debug=False):
    global call
    global ret
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
                # print "call {}".format(espValue)

                if debug: print "{:<10} {} {} {}".format(address, header, operand, espValue)
                display.write("<li>{:<10} {} {} {}<ul>".format(address, header, operand, espValue))
                # header += ":"

                call += 1
            elif operand == "retl":

                remainder = remainder.split()
                if len(remainder) == 1:
                    espValue = hex(int(remainder[0], 16) + 4)[2:-1]

                else:
                    espValue = hex(int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)[2:-1]





                if debug: print "{:<10} {} {} {} \t\t\t\t Err".format(address, header, operand, espValue)
                display.write("<li>{:<10} {} {} {} \t\t\t\t Err</li>".format(address, header, operand, espValue))



                # print "ret {}".format(espValue)

                ret += 1

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
#             # print "call {}".format(espValue)
#
#             print "{:<10} {} {} {}".format(address, header, operand, espValue)
#             display.write("<li>{:<10} {} {} {}<ul>".format(address, header, operand, espValue))
#
#             call += 1

            raise Exception("Call instr at the end of a list")
        elif operand == "retl":

            remainder = remainder.split()
            if len(remainder) == 1:
                espValue = hex(int(remainder[0], 16) + 4)[2:-1]

            else:
                espValue = hex(int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)[2:-1]


            if debug: print "{:<10} {} {} {}".format(address, header, operand, espValue)
            display.write("<li class='lastChild'>{:<10} {} {} {}</li>".format(address, header, operand, espValue))


            # print "ret {}".format(espValue)

            ret += 1
            # stack.pop()
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
processList(cur)

display.write("</ul>")
display.write('<script>CollapsibleLists.apply();</script>')



print "\n\n"
print "call {} ret {} left {}".format(call, ret, len(stack))

sortCallCnt = []
for key in call_cnt.keys():
    sortCallCnt.append([key, call_cnt[key]])

sortCallCnt.sort(key=lambda x : x[1], reverse=True)

for ele in sortCallCnt[:50]:
    print "{} is called {} times.".format(*ele)


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
            offset = hex(targetAddress - src)[2:-1]
            location = line.split()[-1]

            print "objdump -d {} | grep {}".format(location, offset)
            return
    print "Not Found {}".format(targetAddress)




for ele in sortCallCnt[:]:
    getFunctionNameCmd(ele[0], testInput[testChoice][1])

