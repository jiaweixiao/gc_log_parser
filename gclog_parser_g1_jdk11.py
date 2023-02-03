# coding: utf-8

#!/usr/bin/python -O 

import re
import sys, os
import json

"""
This is a parser of G1 log of OpenJDk11.

Required JVM option: 
    -XX:+UseG1 
    -Xlog:gc*:file=gc.log:time,uptime,tid,level

Usage:
    python2 -O this.py gclog_dir
    # If there are gc1.log and gc2.log in gclog_dir,
    # it will save the results in files gc1.json and gc2.json respectively.

You can get all data as a python dictionary structure
in your analyer as follows:

import sys
import json

list = []
for line in sys.stdin:
    line.rstrip()
    list.append(dict(json.loads(line)))
        
"""

################################################################################
# Parser generator from regular expression.
################################################################################

"""
Generate a parser from regex pattern and modifier.

Parser try to match input text by the pattern.
If matched, call data_modifier with list of matched strings.
The modifier add/update tag_str of the dictionary.

regexStr :: String
dataModifier :: (a, [String]) -> a | None
return :: (String, a) -> (String, a)
a :: ANY

dataModifier must not throw exceptions.
When some errors occur inside dataModifier, a must be not modified.

"""
def newP(regexStr, dataModifier):
    p = re.compile("(^%s)" % regexStr)
    def parse_(line, data):
        m = p.match(line)
        if m:
            if dataModifier is not None:
                data = dataModifier(data, m.groups()[1:])
            return (line[len(m.group(1)):], data)
        else:
            msg = "Parse failed: pattern \"%s\" for \"%s\"" % (regexStr, line)
            raise ParseError(msg)
    return parse_

################################################################################
# Utilities.
################################################################################

"""
Just modify data during parse.

dataModifier :: (a, [String]) -> a
return :: (String, a) -> (String, a)
a :: ANY

"""
def appP(dataModifier):
    def modify_(line, data):
        if dataModifier is not None:
            data = dataModifier(data)
        return (line, data)
    return modify_


# [String] -> String
def toString(strL):
    ret = "[%s" % strL[0]
    for str in strL[1:]:
        ret += ", %s" % str
    ret += "]"
    return ret


# Error type for parser.
class ParseError(Exception):
    pass


################################################################################
# Parser combinators.
################################################################################

"""
Parser combinator AND.

parsers :: [Parser]
return :: Parser

"""
def andP(parsers):
    def parseAnd_(text, data):
        text0 = text
        data0 = data
        for parser in parsers:
            (text1, data1) = parser(text0, data0)
            text0 = text1
            data0 = data1
        return (text0, data0)
    return parseAnd_

"""
Parser combinator OR.

parsers :: [Parser]
return :: Parser

"""
def orP(parsers):
    def parseOr_(text, data):
        msgL = []
        for parser in parsers:
            try:
                (ret_text, ret_data) = parser(text, data)
                return (ret_text, ret_data)
            except ParseError, msg:
                msgL.append(msg)
        msgs = toString(msgL)
        raise ParseError(msgs)
    return parseOr_

"""
Parser combinator MANY.
parsers :: [Parser]
return :: Parser

"""
def manyP(parser):
    def parseMany_(text, data):
        text0 = text
        data0 = data
        text1 = text
        data1 = data
        try:
            while True:
                (text1, data1) = parser(text0, data0)
                text0 = text1
                data0 = data1
        except ParseError, msg:
            if __debug__:
                print msg
        return (text1, data1)
    return parseMany_


################################################################################
# Utilities.
################################################################################

"""
A modifier for dictionary data.

tagStr :: String
dataConstructor :: [String] -> ANY
return :: (Dictionary, [String]) -> Dictionary

"""
def mkDictModifier(tagStr, dataConstructor):
    def modifyNothing_(dictData, matchStringL):
        return dictData
    if tagStr is None or dataConstructor is None:
        return modifyNothing_
    def modifyDict_(dictData, matchStringL):
        dictData[tagStr] = dataConstructor(matchStringL)
        return dictData
    return modifyDict_

"""
Behave like newP but that parses anything, just modify dictionary.

key :: String
value :: ANY
return :: (String, Dictionary) -> (String, Dictionary)

"""
def mkTagger(key, value):
    def tagger_(line, dictData):
        dictData[key] = value
        return (line, dictData)
    return tagger_


# match_strL :: [String] # length must be 1.
# return :: Float
def get_float(match_strL):
    assert len(match_strL) == 1
    return float(match_strL[0])

# match_strL :: [String] # length must be 1.
# return :: Int 
def get_int(match_strL):
    assert len(match_strL) == 1
    return int(match_strL[0])

# match_strL :: [String] # length must be 3.
# return :: [Int] # length is 3.
def get_int3(match_strL):
    assert len(match_strL) == 3
    return [int(match_strL[0]), int(match_strL[1]), int(match_strL[2])]

# match_strL :: [String]
# return :: True
def get_true(match_strL):
    return True

# match_strL :: [String]
# return :: String
def get_string(match_strL):
    return match_strL[0]


################################################################################
# Regexp aliases.
################################################################################

regexp_timestamp = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d+\.\d+\+\d{4}"
regexp_float = r"(\d+\.\d+)"
regexp_heap_info = regexp_float + r"\s\(" + regexp_float + r"\s\)->" + \
                   regexp_float + r"\s\(" + regexp_float + r"\s\)\s*"
regexp_float_secs = regexp_float + r"\s*secs\s*"
regexp_basic_string = r"([0-9a-zA-Z_-]+)"


################################################################################
# Parsers for gc log entries.
################################################################################

parseG1PauseYoungNormal = andP([
        mkTagger("type", "G1 Pause Young Normal"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Pause\sYoung\s\(Normal\).+M\)\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-09-10T15:23:34.217+0800][123.534s][76035][info] GC(33) Pause Young (Normal) (G1 Evacuation Pause) 4269M->3358M(16384M) 170.022ms"
    (ret, data) = parseG1PauseYoungNormal(text, {})
    print text
    print len(ret)
    print data

parseG1PauseYoungConcStart = andP([
        mkTagger("type", "G1 Pause Young Concurrent Start"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Pause\sYoung\s\(Concurrent Start\).+M\)\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-09-13T09:52:04.024+0800][334.724s][43043][info] GC(126) Pause Young (Concurrent Start) (Metadata GC Threshold) 28810M->27895M(32768M) 406.544ms"
    (ret, data) = parseG1PauseYoungConcStart(text, {})
    print text
    print len(ret)
    print data

parseG1ConcClearClaimedMarks = andP([
        mkTagger("type", "G1 Concurrent Clear Claimed Marks"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Concurrent\sClear\sClaimed\sMarks\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-09-13T09:52:04.024+0800][334.725s][43039][info] GC(127) Concurrent Clear Claimed Marks 0.289ms"
    (ret, data) = parseG1ConcClearClaimedMarks(text, {})
    print text
    print len(ret)
    print data

parseG1ConcScanRootRegions = andP([
        mkTagger("type", "G1 Concurrent Scan Root Regions"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Concurrent\sScan\sRoot\sRegions\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-09-13T09:52:04.382+0800][335.083s][43039][info] GC(127) Concurrent Scan Root Regions 357.650ms"
    (ret, data) = parseG1ConcScanRootRegions(text, {})
    print text
    print len(ret)
    print data

parseG1ConcMarkFromRoots = andP([
        mkTagger("type", "G1 Concurrent Mark From Roots"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Concurrent\sMark\sFrom\sRoots\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-09-13T09:52:04.382+0800][335.083s][43039][info] GC(127) Concurrent Mark From Roots 95457.427ms"
    (ret, data) = parseG1ConcMarkFromRoots(text, {})
    print text
    print len(ret)
    print data
    
parseG1ConcPreclean = andP([
        mkTagger("type", "G1 Concurrent Preclean"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Concurrent\sPreclean\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-09-13T09:52:04.382+0800][335.083s][43039][info] GC(127) Concurrent Preclean 23.327ms"
    (ret, data) = parseG1ConcPreclean(text, {})
    print text
    print len(ret)
    print data

parseG1ConcMark = andP([
        mkTagger("type", "G1 Concurrent Mark"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Concurrent\sMark\s\(.+\)\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-09-13T09:52:04.382+0800][335.083s][43039][info] GC(127) Concurrent Mark (335.083s, 430.567s) 95484.072ms"
    (ret, data) = parseG1ConcMark(text, {})
    print text
    print len(ret)
    print data

parseG1PauseRemark = andP([
        mkTagger("type", "G1 Pause Remark"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Pause\sRemark.+\)\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-09-13T09:52:04.382+0800][335.083s][43039][info] GC(127) Pause Remark 28680M->28632M(32768M) 236.947ms"
    (ret, data) = parseG1PauseRemark(text, {})
    print text
    print len(ret)
    print data

parseG1ConcRebuildRemSets = andP([
        mkTagger("type", "G1 Concurrent Rebuild Remembered Sets"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Concurrent\sRebuild\sRemembered\sSets\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-09-13T09:52:04.382+0800][335.083s][43039][info] GC(127) Concurrent Rebuild Remembered Sets 64694.748ms"
    (ret, data) = parseG1ConcRebuildRemSets(text, {})
    print text
    print len(ret)
    print data

parseG1PauseCleanup = andP([
        mkTagger("type", "G1 Pause Cleanup"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Pause\sCleanup\s.+\)\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-09-13T09:52:04.382+0800][335.083s][43039][info] GC(1) Pause Cleanup 29333M->29333M(32768M) 123.489ms"
    (ret, data) = parseG1PauseCleanup(text, {})
    print text
    print len(ret)
    print data

parseG1ConcCleanupForNextMark = andP([
        mkTagger("type", "G1 Concurrent Cleanup"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Concurrent\sCleanup\sfor\sNext\sMark\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-09-13T09:52:04.382+0800][335.083s][43039][info] GC(1) Concurrent Cleanup for Next Mark 1450.105ms"
    (ret, data) = parseG1ConcCleanupForNextMark(text, {})
    print text
    print len(ret)
    print data

parseG1ConcCycle = andP([
        mkTagger("type", "G1 Concurrent Cycle"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Concurrent\sCycle\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-09-13T09:52:04.382+0800][335.083s][43039][info] GC(1) Concurrent Cycle 162378.486ms"
    (ret, data) = parseG1ConcCycle(text, {})
    print text
    print len(ret)
    print data

parseG1PauseFull = andP([
        mkTagger("type", "G1 Pause Full"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Pause\sFull\s\(G1\sEva.+M\)\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-12-01T11:12:32.486+0800][411.094s][13338][info] GC(203) Pause Full (G1 Evacuation Pause) 15656M->13641M(16384M) 4391.867ms"
    (ret, data) = parseG1PauseFull(text, {})
    print text
    print len(ret)
    print data

"""
Java GC Log parser.
This supports almost kinds of GC provided by JVM.

"""
parseJavaGcLog = orP([
        parseG1PauseYoungNormal,
        parseG1ConcCycle,
        parseG1PauseFull,
        parseG1ConcClearClaimedMarks,
        parseG1ConcScanRootRegions,
        parseG1ConcMark,
        parseG1ConcMarkFromRoots,
        parseG1ConcPreclean,
        parseG1PauseRemark,
        parseG1ConcRebuildRemSets,
        parseG1PauseCleanup,
        parseG1ConcCleanupForNextMark,
    ])


################################################################################
# Parser of list of integer. This is for test.
################################################################################

"""
A modifier for list.

return :: ([[String]], [String]) -> [String]

"""
def mkListAppender():
    def listAppend_(list, matchStringL):
        if len(matchStringL) > 0:
            list.append(matchStringL[0])
        return list
    return listAppend_

"""
Convert last element to Int.

list :: [Int, Int, ..., Int, String]
return :: [Int, Int, ..., Int, Int]

"""
def convertLastToInt(list):
    list[-1] = int(list[-1])
    return list

# Parser of list of integer. This is for test.
parseIntList = andP([
        newP(r"\s*\[\s*", None), 
        manyP(
                andP([
                        newP(r"(\d+)\s*(?:,\s*)?", mkListAppender()),
                        appP(convertLastToInt), 
                    ])
             ), 
        newP(r"\s*\]\s*", None), 
    ])
if __debug__:
    text = r"[10, 20, 30]"
    (ret, data) = parseIntList(text, [])
    print text
    print len(ret)
    print data


################################################################################
# main
################################################################################
def process_file(filename):
   with open(dirs+filename,'r') as fd:
       data_prev = None
       output = []
       for line in fd.readlines():
           try:
               text = line.rstrip()
               #print texts
               (ret, data) = parseJavaGcLog(text, {})
               #print(file)
               if __debug__:
                   print ("len: %d" % len(ret))
               # print json.dumps(data)
               output.append(data)
           except ParseError, msg:
               # print msg
               #print ("###%s" % text)
               pass
       with open(dirs+filename+'.json','w') as fd:
           fd.write(json.dumps(output))

if __name__=='__main__':
    from multiprocessing import Pool

    dirs = sys.argv[1]
    allfiles = os.listdir(dirs)
    files = []
    for f in allfiles:
        if f.endswith('gclog'):
            files.append(f)

    if len(files) == 0:
        print('No gclog to parse')
        exit(0)
    pool = Pool(processes=len(files))
    multi_results = []

    for filename in files:
        i = files.index(filename)
        print("Thread %d for %s"%(i,filename))
        multi_results.append(
            pool.apply_async(
                process_file,
                (filename,)
            )
        )
    print('Waiting for results ...')
    for res in multi_results:
        res.get()
    print('Finished to process %d gclogs'%len(files))
# end of file.
