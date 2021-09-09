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

regexp_timestamp = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d+\.\d+\+\d{4}:\s+"
regexp_float = r"(\d+\.\d+)"
regexp_time_float_colon = regexp_timestamp + regexp_float + r":\s+"
regexp_heap_info = regexp_float + r"\s\(" + regexp_float + r"\s\)->" + \
                   regexp_float + r"\s\(" + regexp_float + r"\s\)\s*"
regexp_float_secs = regexp_float + r"\s*secs\s*"
regexp_float_ms = regexp_float + r"\s*ms\s*"
regexp_basic_string = r"([0-9a-zA-Z_-]+)"


################################################################################
# Parsers for gc log entries.
################################################################################

parseSheConcReset = andP([ \
        mkTagger("type", "She Conc Reset"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[Concurrent\sreset,\s", None), \
        newP(regexp_float_ms + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T16:03:29.598+0800: 2.197: [Concurrent reset, 0.249 ms]"
    (ret, data) = parseSheConcReset(text, {})
    print text
    print len(ret)
    print data

parseShePauseInitMark = andP([ \
        mkTagger("type", "She Pause Init Mark"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[Pause\sInit\sMark.*,\s", None), \
        newP(regexp_float_ms + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T16:03:29.599+0800: 2.198: [Pause Init Mark (process weakrefs), 0.659 ms]"
    (ret, data) = parseShePauseInitMark(text, {})
    print text
    print len(ret)
    print data

parseSheConcMark = andP([ \
        mkTagger("type", "She Conc Mark"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[Concurrent\smarking.*,\s", None), \
        newP(regexp_float_ms + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T16:03:29.624+0800: 2.222: [Concurrent marking (process weakrefs), 24.366 ms]"
    (ret, data) = parseSheConcMark(text, {})
    print text
    print len(ret)
    print data

parseSheConcPreclean = andP([ \
        mkTagger("type", "She Conc Preclean"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[Concurrent\sprecleaning,\s", None), \
        newP(regexp_float_ms + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T16:03:29.624+0800: 2.222: [Concurrent precleaning, 0.162 ms]"
    (ret, data) = parseSheConcPreclean(text, {})
    print text
    print len(ret)
    print data

parseShePauseFinalMark = andP([ \
        mkTagger("type", "She Pause Final Mark"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[Pause\sFinal\sMark.*,\s", None), \
        newP(regexp_float_ms + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T16:03:29.627+0800: 2.225: [Pause Final Mark (process weakrefs), 1.074 ms]"
    (ret, data) = parseShePauseFinalMark(text, {})
    print text
    print len(ret)
    print data

parseSheConcCleanup = andP([ \
        mkTagger("type", "She Conc Cleanup"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[Concurrent\scleanup.*,\s", None), \
        newP(regexp_float_ms + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T16:03:29.627+0800: 2.225: [Concurrent cleanup 2159M->2162M(8192M), 0.073 ms]"
    (ret, data) = parseSheConcCleanup(text, {})
    print text
    print len(ret)
    print data

parseSheConcEvac = andP([ \
        mkTagger("type", "She Conc Evacuation"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[Concurrent\sevacuation,\s", None), \
        newP(regexp_float_ms + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T16:03:29.642+0800: 2.240: [Concurrent evacuation, 14.473 ms]"
    (ret, data) = parseSheConcEvac(text, {})
    print text
    print len(ret)
    print data

parseShePauseInitUpdateRefs = andP([ \
        mkTagger("type", "She Pause Init Update Refs"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[Pause\sInit\sUpdate\sRefs,\s", None), \
        newP(regexp_float_ms + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T16:03:29.642+0800: 2.240: [Pause Init Update Refs, 0.014 ms]"
    (ret, data) = parseShePauseInitUpdateRefs(text, {})
    print text
    print len(ret)
    print data

parseSheConcUpdateRefs = andP([ \
        mkTagger("type", "She Conc Update Refs"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[Concurrent\supdate\sreferences,\s", None), \
        newP(regexp_float_ms + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T16:03:29.659+0800: 2.257: [Concurrent update references, 16.968 ms]"
    (ret, data) = parseSheConcUpdateRefs(text, {})
    print text
    print len(ret)
    print data

parseShePauseFinalUpdateRefs = andP([ \
        mkTagger("type", "She Pause Final Update Refs"), \
        newP(regexp_time_float_colon, mkDictModifier("timestamp", get_float)), \
        newP(r"\[Pause\sFinal\sUpdate\sRefs,\s", None), \
        newP(regexp_float_ms + r"\]$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"2020-11-12T16:03:29.660+0800: 2.259: [Pause Final Update Refs, 0.127 ms]"
    (ret, data) = parseShePauseFinalUpdateRefs(text, {})
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
  ConcPreclean
  ConcCleanup
  ConcEvac
  PauseInitUpdateRefs
  ConcUpdateRefs
  PauseFinalUpdateRefs

"""
parseJavaGcLog = orP([ \
        parseSheConcReset, \
        parseShePauseInitMark, \
        parseSheConcMark, \
        parseShePauseFinalMark, \
        parseSheConcPreclean, \
        parseSheConcCleanup, \
        parseSheConcEvac, \
        parseShePauseInitUpdateRefs, \
        parseSheConcUpdateRefs, \
        parseShePauseFinalUpdateRefs, \
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
