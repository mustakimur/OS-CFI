import sys


def main():
    tagLabelMap = dict()
    osCFG = dict()
    csCFG = dict()
    ciCFG = dict()

    bFile = str(sys.argv[1]) + "dump_table"
    with open(bFile, 'r') as fp:
        rLine = fp.readline()
        while rLine:
            if (len(rLine.strip().split(' ')) == 7):
                items = rLine.strip().split(' ')
                tag = (str(items[2][::-1]) + str(items[1][::-1]))
                tag = ''.join(
                    [tag[x:x + 2][::-1] for x in range(0, len(tag), 2)])
                label = (str(items[4][::-1]) + str(items[3][::-1]))
                label = ''.join(
                    [label[x:x + 2][::-1] for x in range(0, len(label), 2)])
                tagLabelMap[int(tag, 16)] = int(label, 16)
            rLine = fp.readline()
    fp.close()

    eFile = str(sys.argv[1]) + "errs.txt"
    with open(eFile, 'r') as fp:
        eLine = fp.readline()
        while eLine:
            items = eLine.strip().split('\t')
            if (items[0] == '2'):
                if (not items[1] in osCFG):
                    osCFG[items[1]] = []
                if (len(items) == 5):
                    osCFG[items[1]].append((tagLabelMap[int(items[2], 10)],
                                            int(items[3], 10), tagLabelMap[int(
                                                items[4], 10)]))
                else:
                    osCFG[items[1]].append((tagLabelMap[int(items[2], 10)],
                                            int(items[3], 10), 0))
            if (items[0] == '3'):
                if (not items[1] in csCFG):
                    csCFG[items[1]] = []
                tmp = []
                for x in range(2, len(items), 1):
                    tmp.append(tagLabelMap[int(items[x], 10)])
                csCFG[items[1]].append(tuple(tmp))

            if (items[0] == '4'):
                if (not items[1] in ciCFG):
                    ciCFG[items[1]] = []
                ciCFG[items[1]].append(tagLabelMap[int(items[2], 10)])

            eLine = fp.readline()
    fp.close()

    osFile = str(sys.argv[1]) + "osCFG.bin"
    fw = open(osFile, "w")
    for k, v in osCFG.iteritems():
        for item in v:
            fw.write(
                str(k) + '\t' + str(item[0]) + '\t' + str(item[1]) + '\t' +
                str(item[2]) + '\n')
    fw.close()

    csFile = str(sys.argv[1]) + "csCFG.bin"
    fw = open(csFile, "w")
    for k, v in csCFG.iteritems():
        for item in v:
            fw.write(str(k))
            for ii in item:
                fw.write('\t' + str(ii))
            fw.write('\n')
    fw.close()

    ciFile = str(sys.argv[1]) + "ciCFG.bin"
    fw = open(ciFile, "w")
    for k, v in ciCFG.iteritems():
        for item in v:
            fw.write(str(k) + '\t' + str(item) + '\n')
    fw.close()


if (__name__ == '__main__'):
    main()