import sys
import trace_container

if len(sys.argv) != 2:
    print 'Usage tracereader.py trace_file'
    sys.exit(1)

tcr = trace_container.TraceContainerReader(sys.argv[1])

for i in xrange(0, tcr.num_frames):
    f = tcr.get_frame()

    if f.HasField('std_frame'):
        print f.std_frame

