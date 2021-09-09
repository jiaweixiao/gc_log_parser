# coding: utf-8

#!/usr/bin/python -O 

import re
import sys, os
import json

"""
This is a parser of G1 log of OpenJDk12.

Required JVM option: -XX:+UnlockExperimentalVMOptions -XX:+UseZGC 
    -Xlog:gc*=info:${GC_LOG_FILE}:utc,tm,level,tags

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

parseG1PauseYoungNormal = andP([ \
        mkTagger("type", "G1 Evacuation Pause Young"), \
        newP(r"\[(" + regexp_timestamp + r")\]", mkDictModifier("utc", get_string)), \
        newP(r"\[(\d+)ms\]", mkDictModifier("timestamp", get_int)), \
        newP(r"\[info\]\[gc\s*\]\sGC\(\d+\)\s", None), \
        newP(r"Pause\sYoung\s\(Normal\).+" + regexp_float + r"ms$", mkDictModifier("response", get_float)), \
    ])
if __debug__:
    text = r"[2021-04-26T14:10:19.910+0000][1619446219910ms][info][gc ] GC(1) Pause Young (Normal) (G1 Evacuation Pause) 620M->10M(8192M) 3.803ms"
    (ret, data) = parseG1PauseYoungNormal(text, {})
    print text
    print len(ret)
    print data

parseG1Ignore = andP([ \
        mkTagger("type", "G1 Ignore"), \
        newP(r"\[(" + regexp_timestamp + r")\]", None), \
        newP(r"\[(\d+)ms\]", None), \
        newP(r"\[info\]\[gc,.+\].+$", None), \
    ])
if __debug__:
    text = r"[2021-04-26T14:16:47.634+0000][1619446607634ms][info][gc,heap,exit ] Heap"
    (ret, data) = parseG1Ignore(text, {})
    print text
    print len(ret)
    print data


"""
Java GC Log parser.
This supports almost kinds of GC provided by JVM.

"""
parseJavaGcLog = orP([ \
        parseG1PauseYoungNormal, parseG1Ignore\
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
                #print msg
                print ("###%s" % text)
        with open(dirs+file+'_2','w') as fd:
            fd.write(json.dumps(output))

# end of file.
