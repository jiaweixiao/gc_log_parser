# coding: utf-8

import re
import sys, os
import json

"""
This is a parser of Shenandoah GC log of OpenJDk8.

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

regexp_timestamp = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d+\.\d+\+\d{4}"
regexp_float = r"(\d+\.\d+)"
regexp_heap_info = regexp_float + r"\s\(" + regexp_float + r"\s\)->" + \
                   regexp_float + r"\s\(" + regexp_float + r"\s\)\s*"
regexp_basic_string = r"([0-9a-zA-Z_-]+)"


################################################################################
# Parsers for gc log entries.
################################################################################

parseSheConcReset = andP([
        mkTagger("type", "She Conc Reset"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Concurrent\sreset\s", None),
        newP(regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-12-04T01:36:05.999+0800][2079.214s][9112 ][info] GC(1247) Concurrent reset 0.564ms"
    (ret, data) = parseSheConcReset(text, {})
    print text
    print len(ret)
    print data

parseShePauseInitMark = andP([
        mkTagger("type", "She Pause Init Mark"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Pause\sInit\sMark\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-12-04T01:36:06.008+0800][2079.224s][9113 ][info] GC(1247) Pause Init Mark 2.837ms"
    (ret, data) = parseShePauseInitMark(text, {})
    print text
    print len(ret)
    print data

parseSheConcMark = andP([
        mkTagger("type", "She Conc Mark"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Concurrent\smarking\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-12-04T01:36:07.200+0800][2080.416s][9112 ][info] GC(1247) Concurrent marking 1191.750ms"
    (ret, data) = parseSheConcMark(text, {})
    print text
    print len(ret)
    print data

parseShePauseFinalMark = andP([
        mkTagger("type", "She Pause Final Mark"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Pause\sFinal\sMark\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-12-04T01:36:18.177+0800][2091.393s][9113 ][info] GC(1258) Pause Final Mark 3.618ms"
    (ret, data) = parseShePauseFinalMark(text, {})
    print text
    print len(ret)
    print data

parseSheConcCleanup = andP([
        mkTagger("type", "She Conc Cleanup"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Concurrent\scleanup\s.+M\)\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-12-04T01:36:18.178+0800][2091.393s][9112 ][info] GC(1258) Concurrent cleanup 9386M->9536M(16384M) 0.255ms"
    (ret, data) = parseSheConcCleanup(text, {})
    print text
    print len(ret)
    print data

parseSheConcEvac = andP([ \
        mkTagger("type", "She Conc Evacuation"), \
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Concurrent\sevacuation\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-12-04T01:36:18.189+0800][2091.405s][9112 ][info] GC(1258) Concurrent evacuation 11.407ms"
    (ret, data) = parseSheConcEvac(text, {})
    print text
    print len(ret)
    print data

parseShePauseInitUpdateRefs = andP([
        mkTagger("type", "She Pause Init Update Refs"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Pause\sInit\sUpdate\sRefs\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-12-04T01:36:18.191+0800][2091.407s][9113 ][info] GC(1258) Pause Init Update Refs 0.150ms"
    (ret, data) = parseShePauseInitUpdateRefs(text, {})
    print text
    print len(ret)
    print data

parseSheConcUpdateRefs = andP([
        mkTagger("type", "She Conc Update Refs"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Concurrent\supdate\sreferences\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-12-04T01:36:18.672+0800][2091.887s][9112 ][info] GC(1258) Concurrent update references 480.551ms"
    (ret, data) = parseSheConcUpdateRefs(text, {})
    print text
    print len(ret)
    print data

parseShePauseFinalUpdateRefs = andP([
        mkTagger("type", "She Pause Final Update Refs"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Pause\sFinal\sUpdate\sRefs\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-12-04T01:36:18.675+0800][2091.890s][9113 ][info] GC(1258) Pause Final Update Refs 0.814ms"
    (ret, data) = parseShePauseFinalUpdateRefs(text, {})
    print text
    print len(ret)
    print data

parseShePauseFull = andP([
        mkTagger("type", "She Pause Full"),
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)),
        newP(r"\[" + regexp_float + r"s\]", mkDictModifier("end_sec", get_float)),
        newP(r"\[\d+\]\[info\]\sGC\(\d+\)\s", None),
        newP(r"Pause\sFull\s.+M\)\s" + regexp_float + r"ms$", mkDictModifier("dur_ms", get_float)),
    ])
if __debug__:
    text = r"[2021-12-03T22:17:35.493+0800][122.471s][77549][info] GC(18) Pause Full 15546M->5928M(16384M) 2699.792ms"
    (ret, data) = parseShePauseInitUpdateRefs(text, {})
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

-XX:+UseShenandoahGC
Events:
  ConcReset
  PauseInitMark
  ConcMark
  PauseFinalMark
  ConcCleanup
  ConcEvac
  PauseInitUpdateRefs
  ConcUpdateRefs
  PauseFinalUpdateRefs
  PauseFull
"""
parseJavaGcLog = orP([
        parseSheConcReset,
        parseShePauseInitMark,
        parseSheConcMark,
        parseShePauseFinalMark,
        parseSheConcCleanup,
        parseSheConcEvac,
        parseShePauseInitUpdateRefs,
        parseSheConcUpdateRefs,
        parseShePauseFinalUpdateRefs,
        parseShePauseFull,
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
    if f.startswith('gc_She') and f.endswith('log'):
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
                #print(file)
                if __debug__:
                    print ("len: %d" % len(ret))
                # print json.dumps(data)
                output.append(data)
            except ParseError, msg:
                #print msg
                #print ("###%s" % text)
                pass
        with open(dirs+file[0:-3]+'json','w') as fd:
            fd.write(json.dumps(output))

# end of file.
