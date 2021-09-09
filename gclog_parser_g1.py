# coding: utf-8

import re
import sys, os
import json

"""
This is a parser of G1 GC log of OpenJDk8.

Required JVM option: -Xloggc:${GC_LOG_FILE} -XX:+PrintGCDateStamps -XX:+PrintGCDetails

Usage:
   java ${JVM_OPTIONS} ${ANY_OTHER_OPTIONS}
   this.py < ${GC_LOG_FILE} | grep -v ^### | ${YOUR_ANALYZER}

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

regexp_timestamp = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d+\.\d+\+\d{4}:\s+"
regexp_float = r"(\d+\.\d+)"
regexp_time_float_colon = regexp_timestamp + regexp_float + r":\s+"
regexp_heap_info = regexp_float + r"\s\(" + regexp_float + r"\s\)->" + \
                   regexp_float + r"\s\(" + regexp_float + r"\s\)\s*"
regexp_float_secs = regexp_float + r"\s*secs\s*"
regexp_basic_string = r"([0-9a-zA-Z_-]+)"


################################################################################
# Parsers for gc log entries.
################################################################################

parseG1PauseYoung = andP([ \
        mkTagger("type", "G1 Pause Young"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        #newP(r"\[GC\s+\(G1\sEva\s+Pause\)\s\(young\)\s*", None), \
        newP(r"\[GC.+\(G1\sEvacuation\sPause\)\s\(young\)", None), \
        newP(r",\s*", None), \
        newP(regexp_float_secs + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-06-10T11:40:25.687+0800: 3.066: [GC pause (G1 Evacuation Pause) (young), 0.0038546 secs]"
    (ret, data) = parseG1PauseYoung(text, {})
    print text
    print len(ret)
    print data

parseG1PauseMixed = andP([ \
        mkTagger("type", "G1 Pause Mixed"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[GC.+\(G1\sEvacuation\sPause\)\s\(mixed\)", None), \
        newP(r",\s*", None), \
        newP(regexp_float_secs + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T03:08:03.860+0800: 182.656: [GC pause (G1 Evacuation Pause) (mixed), 0.0511657 secs]"
    (ret, data) = parseG1PauseMixed(text, {})
    print text
    print len(ret)
    print data

parseG1ConcRootScan = andP([ \
        mkTagger("type", "G1 Conc Root Scan"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[GC\sconcurrent-root-region-scan-end", None), \
        newP(r",\s*", None), \
        newP(regexp_float_secs + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T03:08:02.756+0800: 181.552: [GC concurrent-root-region-scan-end, 0.0059357 secs]"
    (ret, data) = parseG1ConcRootScan(text, {})
    print text
    print len(ret)
    print data

parseG1ConcMark = andP([ \
        mkTagger("type", "G1 Conc Mark"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[GC\sconcurrent-mark-end", None), \
        newP(r",\s*", None), \
        newP(regexp_float_secs + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T03:08:03.662+0800: 182.458: [GC concurrent-mark-end, 0.9060729 secs]"
    (ret, data) = parseG1ConcMark(text, {})
    print text
    print len(ret)
    print data

parseG1PauseRemark = andP([ \
        mkTagger("type", "G1 Pause Remark"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[GC\sremark.+\],\s", None), \
        newP(regexp_float_secs + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T03:08:03.663+0800: 182.458: [GC remark 2020-11-12T03:08:03.663+0800: 182.458: [Finalize Marking, 0.0001829 secs] 2020-11-12T03:08:03.663+0800: 182.458: [GC ref-proc, 0.0001047 secs] 2020-11-12T03:08:03.663+0800: 182.458: [Unloading, 0.0017033 secs], 0.0067513 secs]"
    (ret, data) = parseG1PauseRemark(text, {})
    print text
    print len(ret)
    print data

parseG1PauseCleanup = andP([ \
        mkTagger("type", "G1 Pause Cleanup"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[GC\scleanup.+,\s", None), \
        newP(regexp_float_secs + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T03:08:03.669+0800: 182.465: [GC cleanup 5472M->5466M(8192M), 0.0030983 secs]"
    (ret, data) = parseG1PauseCleanup(text, {})
    print text
    print len(ret)
    print data

parseG1ConcCleanup = andP([ \
        mkTagger("type", "G1 Conc Cleanup"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[GC\sconcurrent-cleanup-end,\s", None), \
        newP(regexp_float_secs + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T03:08:03.673+0800: 182.468: [GC concurrent-cleanup-end, 0.0000225 secs]"
    (ret, data) = parseG1ConcCleanup(text, {})
    print text
    print len(ret)
    print data


parseHeap = andP([ \
        newP(r"\[Eden:\s+" + regexp_heap_info, mkDictModifier("Eden", get_string)), \
        newP(r"Survivors:\s+" + regexp_heap_info, mkDictModifier("Survivors", get_string)), \
        newP(r"Heap:\s+" + regexp_heap_info + r"\]\s*", mkDictModifier("Heap", get_string)), \
    ])

"""
Java GC Log parser.
This supports almost kinds of GC provided by JVM.

-XX:+UseG1GC 

parse pause {young, mixed, remark, cleanup}
parse concurrent {root-scan, mark, cleanup}

"""
parseJavaGcLog = orP([ \
        parseG1PauseYoung, \
        parseG1PauseMixed, \
        parseG1ConcRootScan, \
        parseG1ConcMark, \
        parseG1PauseRemark, \
        parseG1PauseCleanup, \
        parseG1ConcCleanup, \
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
    
dirs = sys.argv[1]
allfiles = os.listdir(dirs)
files = []
for f in allfiles:
    if f.startswith('gclog') and f.endswith('log'):
        files.append(f)

for file in files:
    print(file)
    with open(dirs+file,'r') as fd:
        data_prev = None
        output = []
        for line in fd.readlines():
            try:
                text = line.rstrip()
                #print texts
                (ret, data) = parseJavaGcLog(text, {})
                print(file)
                if __debug__:
                    print ("len: %d" % len(ret))
                # print json.dumps(data)
                output.append(data)
            except ParseError, msg:
                print msg
                #print ("###%s" % text)
        with open(dirs+file+'_2','w') as fd:
            fd.write(json.dumps(output))

# end of file.
