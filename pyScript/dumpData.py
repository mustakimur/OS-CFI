import sys
import r2pipe

tagLabelMap = dict()


def preprocess():
    bFile = str(sys.argv[1]) + str(sys.argv[2])
    r2 = r2pipe.open(bFile)
    r2.cmd("aaa")
    res = []
    for x in (r2.cmd("afl").split("\n")):
        if (len(x) > 0):
            res.append(int((x.split(' ')[0]), 16))

    for k, v in tagLabelMap.iteritems():
        r2.cmd("s " + hex(v))
        r2.cmd("sf.")

        if (not v in res):
            item = r2.cmd("/c jmp " + hex(v))
            if (len(item) > 0):
                tagLabelMap[k] = int(item.strip().split(' ')[0], 16)
            else:
                item = r2.cmd("/c jne " + hex(v))
                if (len(item) > 0):
                    item = r2.cmd("pd -1")
                    tagLabelMap[k] = int(item.strip().split(' ')[0], 16)

    r2.quit()


def main():
    osCFG = dict()
    csCFG = dict()
    ciCFG = dict()

    bFile = str(sys.argv[1]) + "dump_table.bin"
    with open(bFile, 'r') as fp:
        rLine = fp.readline()
        while rLine:
            if (rLine[0] == ' ' and len(rLine.strip().split(' ')) >= 7):
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

    preprocess()

    eFile = str(sys.argv[1]) + "stats.bin"
    with open(eFile, 'r') as fp:
        eLine = fp.readline()
        while eLine:
            items = eLine.strip().split('\t')
            if (items[0] == '2'):
                if (len(items) == 6):
                    key = (items[1], items[2], int(items[4], 10),
                           tagLabelMap[int(items[5], 10)])
                else:
                    key = (items[1], items[2], int(items[4], 10), 0)

                if (not key in osCFG):
                    osCFG[key] = []
                osCFG[key].append(tagLabelMap[int(items[3], 10)])
            if (items[0] == '3'):
                tmp = []
                tmp.append(items[1])
                tmp.append(items[2])
                for x in range(4, len(items), 1):
                    tmp.append(tagLabelMap[int(items[x], 10)])
                key = tuple(tmp)
                if (not key in csCFG):
                    csCFG[key] = []

                csCFG[key].append(tagLabelMap[int(items[3], 10)])

            if (items[0] == '4'):
                key = (items[1], items[2])
                if (not key in ciCFG):
                    ciCFG[key] = []
                ciCFG[key].append(tagLabelMap[int(items[3], 10)])

            eLine = fp.readline()
    fp.close()

    osChoice = dict()
    csChoice = dict()
    ciChoice = dict()

    for k, v in ciCFG.iteritems():
        ototal = 0
        ocount = 0
        itotal = 0
        icount = 0
        osChoice[k] = 9999
        csChoice[k] = 9999
        ciChoice[k] = 9999

        for ok, ov in osCFG.iteritems():
            if (k[1] == ok[1]):
                ototal += len(set(ov))
                ocount += 1
        if (ocount > 0):
            osChoice[k] = ((float)(ototal) / (float)(ocount))

        ctotal = 0
        ccount = 0
        for ck, cv in csCFG.iteritems():
            if (k[1] == ck[1]):
                ctotal += len(set(cv))
                ccount += 1
        if (ccount > 0):
            csChoice[k] = ((float)(ctotal) / (float)(ccount))

        itotal += len(set(v))
        icount += 1
        if (icount > 0):
            ciChoice[k] = ((float)(itotal) / (float)(icount))

    fChoice = dict()
    for k, v in ciCFG.iteritems():
        if (ciChoice[k] <= osChoice[k] and ciChoice[k] <= csChoice[k]):
            fChoice[k] = 1
        elif (osChoice[k] < csChoice[k] and osChoice[k] < ciChoice[k]):
            fChoice[k] = 2
        elif (csChoice[k] <= osChoice[k] and csChoice[k] < ciChoice[k]):
            fChoice[k] = 3

    osFile = str(sys.argv[1]) + "osCFG.bin"
    # cpoint, origin, originctx, target
    fw = open(osFile, "w")
    for k, v in osCFG.iteritems():
        if (fChoice[(k[0], k[1])] == 2):
            for item in v:
                fw.write(
                    str(k[0]) + '\t' + str(k[1]) + '\t' + str(k[2]) + '\t' +
                    str(k[3]) + '\t' + str(item) + '\n')
    fw.close()

    cs1File = str(sys.argv[1]) + "cs1CFG.bin"
    cs2File = str(sys.argv[1]) + "cs2CFG.bin"
    cs3File = str(sys.argv[1]) + "cs3CFG.bin"
    fw1 = open(cs1File, "w")
    fw2 = open(cs2File, "w")
    fw3 = open(cs3File, "w")

    for k, v in csCFG.iteritems():
        if (fChoice[(k[0], k[1])] == 3):
            ctx = ''
            c = 0
            for ii in k:
                if (c > 5):
                    break
                ctx += (str(ii) + '\t')
                c += 1

            for item in v:
                if (len(k) == 3):
                    fw1.write(ctx + '\t' + str(item) + '\n')
                elif (len(k) == 4):
                    fw2.write(ctx + '\t' + str(item) + '\n')
                else:
                    fw3.write(ctx + '\t' + str(item) + '\n')
    fw1.close()
    fw2.close()
    fw3.close()

    ciFile = str(sys.argv[1]) + "ciCFG.bin"
    fw = open(ciFile, "w")
    for k, v in ciCFG.iteritems():
        if (fChoice[(k[0], k[1])] == 1):
            for item in v:
                fw.write(
                    str(k[0]) + '\t' + str(k[1]) + '\t' + str(item) + '\n')
    fw.close()


if (__name__ == '__main__'):
    main()