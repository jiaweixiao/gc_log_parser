# coding: utf-8

import re
import sys, os
import json

"""
This is a parser of GC log of Sun HotSpot JVM Version 6.

Required JVM option: -Xloggc=${GC_LOG_FILE} -XX:+PrintGCDetails

Usage:
   java -Xloggc=${GC_LOG_FILE} -XX:+PrintGCDetails ${ANY_OTHER_OPTIONS}
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


################################################################################
# Regexp aliases.
################################################################################

regexp_timestamp = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d+\.\d+\+\d{4}:\s+"
regexp_float = r"(\d+\.\d*)"
regexp_float_colon = regexp_timestamp + regexp_float + r":\s+"
regexp_heap_info = r"(\d+)K->(\d+)K\((\d+)K\)"
regexp_float_secs = regexp_float + r"\s*secs\s+"
regexp_basic_string = r"([0-9a-zA-Z_-]+)"


################################################################################
# Parsers for gc log entries.
################################################################################

parseParNew = andP([ \
	mkTagger("type", "ParNew"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r"\[GC\s+\(Allocation\sFailure\)\s+", None), \
	newP(regexp_float_colon, None), \
	newP(r"\[ParNew:\s+", None), \
	newP(regexp_heap_info + r",\s+", mkDictModifier("heap_new", get_int3)), \
	newP(regexp_float + r"\s*secs\]\s*", None), \
	newP(regexp_heap_info, mkDictModifier("heap_all", get_int3)), \
	newP(r"(?:\sicms_dc=\d+\s*)?,\s*", None), \
	newP(regexp_float + r"\s*secs\]\s*", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
if __debug__:
    text = r"2019-12-05T04:17:14.531+0800: 5.388: [GC (Allocation Failure) 2019-12-05T04:17:14.531+0800: 5.388: [ParNew: 5070147K->61055K(5662336K), 0.1314250 secs] 5070147K->61055K(7759488K), 0.1315435 secs] [Times: user=0.10 sys=0.02, real=0.13 secs]"
    (ret, data) = parseParNew(text, {})
    print text
    print len(ret)
    print data
    text = r"2020-12-18T17:01:30.868+0800: 4.116: [GC (Allocation Failure) 2020-12-18T17:01:30.868+0800: 4.116: [ParNew: 4293887K->126107K(4718592K), 0.0122479 secs] 4293887K->126107K(7864320K) icms_dc=5 , 0.0123032 secs] [Times: user=0.08 sys=0.02, real=0.01 secs]"
    (ret, data) = parseParNew(text, {})
    print text
    print len(ret)
    print data
# if __debug__:
#     text = r"9.815: [GC 9.815: [ParNew: 32768K->10796K(49152K), 0.0286700 secs] 52540K->30568K(114688K) icms_dc=0 , 0.0287550 secs] [Times: user=0.09 sys=0.00, real=0.03 secs]"
#     (ret, data) = parseParNew(text, {})
#     print text
#     print len(ret)
#     print data
    

parseInitialMark = andP([ \
	mkTagger("type", "CMS-initial-mark"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r".*CMS-initial-mark:\s+\d+K\(\d+K\)\]\s*", None), \
	newP(r"\d+K\(\d+K\),\s*", None), \
	newP(regexp_float + r"\s*secs\]\s*", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
if __debug__:
    text = r"2019-12-05T04:20:59.201+0800: 230.059: [GC (CMS Initial Mark) [1 CMS-initial-mark: 1930270K(2097152K)] 1968958K(7759488K), 0.0045541 secs] [Times: user=0.00 sys=0.00, real=0.01 secs]"
    (ret, data) = parseInitialMark(text, {})
    print text
    print len(ret)
    print data


parseMarkStart = andP([ \
	mkTagger("type", "CMS-concurrent-mark-start"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r".*CMS-concurrent-mark-start.*$", None), ])
if __debug__:
    text = r"2019-12-05T04:22:50.833+0800: 341.691: [CMS-concurrent-mark-start]"
    (ret, data) = parseMarkStart(text, {})
    print text
    print len(ret)
    print data


parseMark = andP([ \
	mkTagger("type", "CMS-concurrent-mark"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r"\[CMS-concurrent-mark:\s+", None), \
	newP(regexp_float + r"/", None), \
	newP(regexp_float + r"\s+secs\]\s+", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
if __debug__:
    text = r"2019-12-05T04:26:03.302+0800: 534.159: [CMS-concurrent-mark: 1.720/1.897 secs] [Times: user=11.94 sys=1.69, real=1.89 secs]"
    (ret, data) = parseMark(text, {})
    print text
    print len(ret)
    print data


parsePrecleanStart = andP([ \
	mkTagger("type", "CMS-concurrent-preclean-start"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r".*CMS-concurrent-preclean-start.*$", None), ])
if __debug__:
    text = r"2019-12-05T04:26:03.302+0800: 534.159: [CMS-concurrent-preclean-start]"
    (ret, data) = parsePrecleanStart(text, {})
    print text
    print len(ret)
    print data


parsePreclean = andP([ \
	mkTagger("type", "CMS-concurrent-preclean"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r"\[CMS-concurrent-preclean:\s+", None), \
	newP(regexp_float + r"/", None), \
	newP(regexp_float + r"\s+secs\]\s+", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
if __debug__:
    text = r"2019-12-05T04:26:03.390+0800: 534.248: [CMS-concurrent-preclean: 0.014/0.018 secs] [Times: user=0.07 sys=0.00, real=0.01 secs]"
    (ret, data) = parsePreclean(text, {})
    print text
    print len(ret)
    print data


parseAbortablePrecleanStart = andP([ \
	mkTagger("type", "CMS-concurrent-abortable-preclean-start"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r".*CMS-concurrent-abortable-preclean-start.*$", None), ])
if __debug__:
    text = r"2019-12-05T04:26:03.390+0800: 534.248: [CMS-concurrent-abortable-preclean-start]"
    (ret, data) = parseAbortablePrecleanStart(text, {})
    print text
    print len(ret)
    print data


parseAbortablePreclean = andP([ \
	mkTagger("type", "CMS-concurrent-abortable-preclean"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r"\[CMS-concurrent-abortable-preclean:\s+", None), \
	newP(regexp_float + r"/", None), \
	newP(regexp_float + r"\s+secs\]\s+", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
if __debug__:
    text = r"2019-12-05T04:18:32.874+0800: 83.732: [CMS-concurrent-abortable-preclean: 0.793/0.954 secs] [Times: user=3.78 sys=0.38, real=0.96 secs]"
    (ret, data) = parseAbortablePreclean(text, {})
    print text
    print len(ret)
    print data


parseAbortablePrecleanFullGC0 = andP([ \
	mkTagger("type", "CMS-concurrent-abortable-preclean-fullgc0"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	orP([newP(r"\[Full GC\s*\(System\.gc\(\)\)\s*" + regexp_float_colon, mkDictModifier("system", get_true)),\
             newP(r"\[Full GC\s*" + regexp_float_colon, None), \
             newP(r"\[GC\s*\(Allocation Failure\).*" + r"\[ParNew.*secs\]" + regexp_float_colon, None),]), \
	newP(r"\[CMS" + regexp_float_colon, None), \
	newP(r"\[CMS-concurrent-(abortable-)?preclean:\s+", None), \
	newP(regexp_float + r"/", None), \
	newP(regexp_float + r"\s+secs\]\s*", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
if __debug__:
    #text = r"2019-12-11T12:07:18.104+0800: 415.160: [GC (Allocation Failure) 2019-12-11T12:07:18.104+0800: 415.160: [ParNew: 6606079K->6606079K(6606080K), 0.0000257 secs]2019-12-11T12:07:18.104+0800: 415.160: [CMS2019-12-11T12:07:18.459+0800: 415.515: [CMS-concurrent-mark: 0.392/0.393 secs] [Times: user=0.92 sys=0.02, real=0.39 secs]"
    #(ret, data) = parseAbortablePrecleanFullGC0(text, {})
    #print text
    #print len(ret)
    #print data
    text = r"2019-12-11T12:08:29.924+0800: 486.981: [GC (Allocation Failure) 2019-12-11T12:08:29.924+0800: 486.981: [ParNew (promotion failed): 6606079K->6220947K(6606080K), 2.4837939 secs]2019-12-11T12:08:32.408+0800: 489.464: [CMS2019-12-11T12:08:32.499+0800: 489.555: [CMS-concurrent-abortable-preclean: 1.989/4.482 secs] [Times: user=10.84 sys=1.27, real=4.48 secs]"
    (ret, data) = parseAbortablePrecleanFullGC0(text, {})
    print text
    print len(ret)
    print data
    text = r"2019-12-04T00:37:21.246+0800: 597.159: [Full GC (System.gc()) 2019-12-04T00:37:21.246+0800: 597.159: [CMS2019-12-04T00:37:21.289+0800: 597.203: [CMS-concurrent-abortable-preclean: 0.260/0.363 secs] [Times: user=1.70 sys=0.21, real=0.36 secs]"
    (ret, data) = parseAbortablePrecleanFullGC0(text, {})
    print text
    print len(ret)
    print data
    text = r"2020-12-14T14:17:54.480+0800: 279.738: [Full GC (System.gc()) 2020-12-14T14:17:54.480+0800: 279.738: [CMS2020-12-14T14:18:06.180+0800: 291.438: [CMS-concurrent-preclean: 17.116/19.199 secs] [Times: user=41.64 sys=5.74, real=19.20 secs]"
    (ret, data) = parseAbortablePrecleanFullGC0(text, {})
    print text
    print len(ret)
    print data



parseAbortablePrecleanFullGC1 = andP([ \
	mkTagger("type", "CMS-concurrent-abortable-preclean-fullgc1"), \
	newP(r"\s*\(concurrent mode (failure|interrupted)\):\s+", None), \
	newP(regexp_heap_info + r",\s+", mkDictModifier("heap_1", get_int3)), \
	newP(regexp_float + r"\s+secs\s*\]\s+", None), \
	newP(regexp_heap_info + r",\s+", mkDictModifier("heap_2", get_int3)), \
	newP(r"\[Metaspace:\s+", None), \
	newP(regexp_heap_info + r"\],\s+", mkDictModifier("meta", get_int3)), \
	newP(regexp_float + r"\s*secs\s*\]\s*", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
if __debug__:
    text = r" (concurrent mode failure): 1041940K->1048575K(1048576K), 3.0127238 secs] 7646509K->1423853K(7654656K), [Metaspace: 9132K->9132K(1058816K)], 5.3052202 secs] [Times: user=5.14 sys=0.17, real=5.30 secs]"
    (ret, data) = parseAbortablePrecleanFullGC1(text, {})
    print text
    print len(ret)
    print data
    text = r" (concurrent mode interrupted): 2013395K->2013633K(2097152K), 2.4888282 secs] 2177198K->2013633K(7759488K), [Metaspace: 9214K->9214K(1058816K)], 2.4890482 secs] [Times: user=2.49 sys=0.00, real=2.49 secs]"
    (ret, data) = parseAbortablePrecleanFullGC1(text, {})
    print text
    print len(ret)
    print data


parseAbortablePrecleanFailureTime = andP([ \
	mkTagger("type", "CMS-concurrent-abortable-preclean-failure-time"), \
	newP(r"\s*CMS:\s*abort preclean due to time\s*", None), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r"\[CMS-concurrent-abortable-preclean:\s*", None), \
	newP(regexp_float + r"/", None), \
	newP(regexp_float + r"\s*secs\s*\]\s*", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
if __debug__:
    text = r" CMS: abort preclean due to time 2019-12-11T12:08:12.632+0800: 469.688: [CMS-concurrent-abortable-preclean: 0.128/5.034 secs] [Times: user=16.42 sys=3.59, real=5.04 secs]"
    (ret, data) = parseAbortablePrecleanFailureTime(text, {})
    print text
    print len(ret)
    print data
    # text = r"3.368: [GC [1 CMS-initial-mark: 7015K(65536K)] 7224K(114688K), 0.0004900 secs] [Times: user=0.00 sys=0.00, real=0.00 secs]"
    # (ret, data) = parseInitialMark(text, {})
    # print text
    # print len(ret)
    # print data
    # text = r"3.428: [CMS-concurrent-mark: 0.059/0.060 secs] [Times: user=0.22 sys=0.00, real=0.06 secs]"
    # (ret, data) = parseMark(text, {})
    # print text
    # print len(ret)
    # print data
    # text = r"3.431: [CMS-concurrent-preclean: 0.002/0.002 secs] [Times: user=0.00 sys=0.00, real=0.00 secs]"
    # (ret, data) = parsePreclean(text, {})
    # print text
    # print len(ret)
    # print data


parseRemark = andP([ \
	mkTagger("type", "CMS-remark"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r"\[GC\s+\(CMS Final Remark\)\s+\[YG occupancy.+CMS-remark:\s+\d+K\(\d+K\)\]\s*", None), \
	newP(r"\d+K\(\d+K\),\s*", None), \
	newP(regexp_float + r"\s*secs\]\s*", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
if __debug__:
    text = r"2019-12-05T04:58:15.792+0800: 335.407: [GC (CMS Final Remark) [YG occupancy: 2668048 K (5662336 K)]2019-12-05T04:58:15.792+0800: 335.407: [Rescan (parallel) , 0.8799493 secs]2019-12-05T04:58:16.672+0800: 336.287: [weak refs processing, 0.0000365 secs]2019-12-05T04:58:16.672+0800: 336.287: [class unloading, 0.0067348 secs]2019-12-05T04:58:16.679+0800: 336.294: [scrub symbol table, 0.0027506 secs]2019-12-05T04:58:16.682+0800: 336.297: [scrub string table, 0.0002704 secs][1 CMS-remark: 1939770K(2097152K)] 4607818K(7759488K), 0.8898802 secs] [Times: user=0.88 sys=0.01, real=0.88 secs]"
    (ret, data) = parseRemark(text, {})
    print text
    print len(ret)
    print data


parseSweepStart = andP([ \
	mkTagger("type", "CMS-concurrent-sweep-start"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r"\[CMS-concurrent-sweep-start\]$", None), ])
if __debug__:
    text = r"2019-12-05T04:58:16.682+0800: 336.297: [CMS-concurrent-sweep-start]"
    (ret, data) = parseSweepStart(text, {})
    print text
    print len(ret)
    print data


parseSweep = andP([ \
	mkTagger("type", "CMS-concurrent-sweep"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r"\[CMS-concurrent-sweep:\s+", None), \
	newP(regexp_float + r"/", None), \
	newP(regexp_float + r"\s+secs\]\s+", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
if __debug__:
    text = r"2019-12-05T04:58:17.259+0800: 336.873: [CMS-concurrent-sweep: 0.483/0.576 secs] [Times: user=3.43 sys=0.44, real=0.58 secs]"
    (ret, data) = parseSweep(text, {})
    print text
    print len(ret)
    print data


parseResetStart = andP([ \
	mkTagger("type", "CMS-concurrent-reset-start"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r"\[CMS-concurrent-reset-start\]$", None), ])
if __debug__:
    text = r"2019-12-05T04:58:17.259+0800: 336.874: [CMS-concurrent-reset-start]"
    (ret, data) = parseResetStart(text, {})
    print text
    print len(ret)
    print data


parseReset = andP([ \
	mkTagger("type", "CMS-concurrent-reset"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r"\[CMS-concurrent-reset:\s+", None), \
	newP(regexp_float + r"/", None), \
	newP(regexp_float + r"\s+secs\]\s+", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
if __debug__:
    text = r"2019-12-05T04:58:17.265+0800: 336.880: [CMS-concurrent-reset: 0.007/0.007 secs] [Times: user=0.05 sys=0.01, real=0.01 secs]"
    (ret, data) = parseReset(text, {})
    print text
    print len(ret)
    print data


parseFullGC = andP([ \
	mkTagger("type", "FullGC"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	orP([newP(r"\[Full GC\s*\(System\.gc\(\)\)\s*", mkDictModifier("system", get_true)), \
		newP(r"\[Full GC\s*", None), ]), \
	newP(regexp_float_colon, None), \
	newP(r"\[CMS:\s+", None), \
	newP(regexp_heap_info + r",\s+", mkDictModifier("heap_old", get_int3)), \
	newP(regexp_float + r"\s*secs\]\s*", None), \
	newP(regexp_heap_info, mkDictModifier("heap_all", get_int3)), \
	newP(r"\s*,\s*\[Metaspace\s*:\s*", None), \
	newP(regexp_heap_info, mkDictModifier("meta", get_int3)), \
	newP(r"\]\s*(?:icms_dc=\d+\s*)?", None), \
	newP(r",\s*", None), \
	newP(regexp_float + r"\s*secs\]\s*", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
if __debug__:
    # text = r"7.992: [Full GC 7.992: [CMS: 6887K->19772K(65536K), 0.4137230 secs] 34678K->19772K(114688K), [CMS Perm : 54004K->53982K(54152K)] icms_dc=0 , 0.4140100 secs] [Times: user=0.68 sys=0.14, real=0.41 secs]"
    # (ret, data) = parseFullGC(text, {})
    # print text
    # print len(ret)
    # print data
    text = r"2019-12-04T00:47:07.645+0800: 572.678: [Full GC (System.gc()) 2019-12-04T00:47:07.645+0800: 572.678: [CMS: 1980092K->1992900K(2097152K), 2.6211334 secs] 3193337K->1992900K(7759488K), [Metaspace: 9222K->9222K(1058816K)], 2.6213695 secs] [Times: user=2.62 sys=0.00, real=2.62 secs]"
    (ret, data) = parseFullGC(text, {})
    print text
    print len(ret)
    print data

# This is for -XX:+UseParallelGC
parseParallelGC = andP([ \
	mkTagger("type", "ParallelGC"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r"\[GC\s+\[PSYoungGen:\s*", None), \
	newP(regexp_heap_info + r"\s*\]\s*", mkDictModifier("heap_new", get_int3)), \
	newP(regexp_heap_info + r"\s*,\s*", mkDictModifier("heap_all", get_int3)), \
	newP(regexp_float + r"\s*secs\s*\]\s*", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
# if __debug__:
#     text = r"162.002: [GC [PSYoungGen: 39323K->3653K(49152K)] 87187K->56999K(114688K), 0.0207580 secs] [Times: user=0.08 sys=0.00, real=0.02 secs]"
#     (ret, data) = parseParallelGC(text, {})
#     print text
#     print len(ret)
#     print data


# This is for -XX:+UseParallelGC
parseParallelFullGC = andP([ \
	mkTagger("type", "ParallelFullGC"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	orP([newP(r"\[Full GC\s*\(System\)\s*\[PSYoungGen:\s*", mkDictModifier("system", get_true)), \
		newP(r"\[Full GC\s*\[PSYoungGen:\s*", None), ]), \
	newP(regexp_heap_info + r"\s*\]\s*", mkDictModifier("heap_new", get_int3)), \
	newP(r"\[PSOldGen:\s*", None), \
	newP(regexp_heap_info + r"\s*\]\s*", mkDictModifier("heap_old", get_int3)), \
	newP(regexp_heap_info + r"\s*", mkDictModifier("heap_all", get_int3)), \
	newP(r"\[PSPermGen:\s*", None), \
	newP(regexp_heap_info + r"\s*\]\s*,\s*", mkDictModifier("meta", get_int3)), \
	newP(regexp_float + r"\s*secs\s*\]\s*", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
# if __debug__:
#     text = r"162.657: [Full GC [PSYoungGen: 6189K->0K(50752K)] [PSOldGen: 58712K->43071K(65536K)] 64902K->43071K(116288K) [PSPermGen: 81060K->81060K(81152K)], 0.3032230 secs] [Times: user=0.30 sys=0.00, real=0.30 secs]"
#     (ret, data) = parseParallelFullGC(text, {})
#     print text
#     print len(ret)
#     print data


# This is for -XX:+UseSerialGC
parseSerialGC = andP([ \
	mkTagger("type", "SerialGC"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r"\[GC\s+", None), \
	newP(regexp_float_colon + r"\[DefNew:\s*", None), \
	newP(regexp_heap_info + r"\s*,\s*", mkDictModifier("heap_new", get_int3)), \
	newP(regexp_float + r"\s*secs\s*\]\s*", None), \
	newP(regexp_heap_info + r"\s*,\s*", mkDictModifier("heap_all", get_int3)), \
	newP(regexp_float + r"\s*secs\s*\]\s*", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
# if __debug__:
#     text = r"4.687: [GC 4.687: [DefNew: 33343K->649K(49152K), 0.0021450 secs] 45309K->12616K(114688K), 0.0021800 secs] [Times: user=0.00 sys=0.00, real=0.00 secs]"
#     (ret, data) = parseSerialGC(text, {})
#     print text
#     print len(ret)
#     print data


# This is for -XX:+UseSerialGC
parseSerialFullGC = andP([ \
	mkTagger("type", "SerialFullGC"), \
	newP(regexp_float_colon, mkDictModifier("timestamp", get_float)), \
	newP(r"\[Full GC\s+", None), \
	newP(regexp_float_colon + r"\s*", None), \
	newP(r"\[Tenured:\s*", None), \
	newP(regexp_heap_info + r"\s*,\s*", mkDictModifier("heap_old", get_int3)), \
	newP(regexp_float + r"\s*secs\]\s*", None), \
	newP(regexp_heap_info + r"\s*,\s*", mkDictModifier("heap_all", get_int3)), \
	newP(r"\[Perm\s*:\s*", None), \
	newP(regexp_heap_info + r"\s*\]\s*,\s*", mkDictModifier("meta", get_int3)), \
	newP(regexp_float + r"\s*secs\s*\]\s*", mkDictModifier("response", get_float)), \
	newP(r"\[Times:.*\]$", None), ])
# if __debug__:
#     text = r"4.899: [Full GC 4.899: [Tenured: 11966K->12899K(65536K), 0.1237750 secs] 22655K->12899K(114688K), [Perm : 32122K->32122K(32128K)], 0.1238590 secs] [Times: user=0.11 sys=0.00, real=0.13 secs]"
#     (ret, data) = parseSerialFullGC(text, {})
#     print text
#     print len(ret)
#     print data


"""
Java GC Log parser.
This supports almost kinds of GC provided by JVM.

-XX:+UseConcSweepGC (-XX:+UseParNewGC)
 parseParNew
 parseFullGC

-XX:+UseConcSweepGC -XX:CMSIncrementalMode (-XX:+UseParNewGC)
 parseParNew, parseFullGC,
 parse{InitialMark, MarkStart, Mark, PrecleanStart, Preclean,
       AbortablePrecleanStart, AbortablePreclean,
       AbortablePrecleanFullGC0, AbortablePrecleanFullGC1,
       AbortablePrecleanFailureTime,
       Remark,
       SweepStart, Sweep, ResetStart, Reset}
  parseAbortablePrecleanFullGC0 and parseAbortablePrecleanFullGC1
  must be always together.

-XX:+UseParallelGC
  parseParallelFullGC, parseParallelGC.

-XX:+UseSerialGC
  parseSerialFullGC, parseSerialGC.
  
"""
parseJavaGcLog = orP([ \
	parseParNew, parseFullGC, parseInitialMark, parseMarkStart, parseMark, parsePrecleanStart, parsePreclean, \
	parseAbortablePrecleanStart, parseAbortablePreclean, parseAbortablePrecleanFullGC0, parseAbortablePrecleanFullGC1, \
	parseAbortablePrecleanFailureTime, \
	parseRemark, \
    parseSweepStart, parseSweep, \
    parseResetStart, parseReset, \
    parseParallelFullGC, \
    parseParallelGC, \
    parseSerialFullGC, \
    parseSerialGC, \
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
			appP(convertLastToInt), ])), 
	newP(r"\s*\]\s*", None), ])
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
                #print(file)
                if data["type"] == "CMS-concurrent-abortable-preclean-fullgc0":
                    data_prev = data
                    continue
                if data["type"] == "CMS-concurrent-abortable-preclean-fullgc1":
                    assert data_prev["type"] == "CMS-concurrent-abortable-preclean-fullgc0"
                    data_prev.update(data)
                    data = data_prev
                    data_prev = None
                    data["type"] = "CMS-concurrent-abortable-preclean-fullgc"
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
