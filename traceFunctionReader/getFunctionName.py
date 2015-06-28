import os
for line in open("input"):
    line = line.strip()
    if line[:1] == "#" or not len(line):
        print line.strip()
        continue


    try:

        # try 1
        found = False
        location, offset, target = line.split()

        cmd = "objdump -d {0} | grep 'call   {1}' -m 1".format(location, offset)
        with os.popen(cmd) as result:
            rst = result.read().strip()

            if rst == "":
                # print location, offset, target
                pass
            else:
                print rst.split()[-1]
                # print "f"
                found = True
                pass

        if found: continue

        # try 2
        cmd = "objdump -d {0} | grep 'call   {1}' -m 1".format(location, target[2:])
        with os.popen(cmd) as result:
            rst = result.read().strip()

            if rst == "":
                # print location, offset, target
                pass
            else:
                print rst.split()[-1]
                # print "f"
                found = True

        if found: continue

        # try 3
        cmd = "objdump -d {0} | grep ^{1:0>8} -m 1".format(location, offset)
        with os.popen(cmd) as result:
            rst = result.read().strip()

            if rst == "":
                # print location, offset, target
                pass
            else:
                print rst.split()[-1]
                # print "f"
                found = True

        if found: continue


        print "#Unknown", location, offset, target
    except:
        import sys
        print "Unexpected error:", sys.exc_info()[0]
        print line
        raise