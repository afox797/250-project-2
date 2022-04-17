# coding=utf8
# the above tag defines encoding for this document and is for Python 2.x compatibility

import re

regex = r"(\d+\.\d+)(?=\s*free)"

test_str = ("top - 17:01:31 up  4:55,  1 user,  load average: 1.63, 0.82, 0.75\n"
            "Tasks: 384 total,   1 running, 383 sleeping,   0 stopped,   0 zombie\n"
            "%Cpu(s):  2.5 us,  3.4 sy,  0.0 ni, 94.1 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\n"
            "MiB Mem :  15365.3 total,   5253.5 free,   6090.4 used,   4021.4 buff/cache\n"
            "MiB Swap:   7813.0 total,   7813.0 free,      0.0 used.   8791.4 avail Mem\n\n"
            "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n"
            "   2522 afox      20   0   40.9g 400300 163404 S  12.5   2.5   8:01.82 Discord\n"
            "   4383 afox      20   0   11.6g   2.5g 540688 S  12.5  16.5  16:19.19 java\n"
            "   1559 afox      20   0 4161964 220016 101768 S   6.2   1.4   5:11.66 cinnamon\n"
            "   1601 afox      20   0 3312016 609384 198184 S   6.2   3.9   2:37.52 thunder+\n"
            "  11215 afox      20   0  568740 175996  79048 S   6.2   1.1   2:14.81 Discord\n"
            "  12210 afox      20   0   20.5g 146600 108000 S   6.2   0.9   0:05.89 code\n"
            "  13891 root      20   0       0      0      0 I   6.2   0.0   0:00.51 kworker+\n"
            "  14160 afox      20   0   12120   3900   3136 R   6.2   0.0   0:00.01 top\n"
            "      1 root      20   0  167768  11644   8360 S   0.0   0.1   0:00.98 systemd\n"
            "      2 root      20   0       0      0      0 S   0.0   0.0   0:00.02 kthreadd\n"
            "      3 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 rcu_gp\n"
            "      4 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 rcu_par+\n"
            "      6 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kworker+\n"
            "      9 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 mm_perc+\n"
            "     10 root      20   0       0      0      0 S   0.0   0.0   0:00.00 rcu_tas+\n"
            "     11 root      20   0       0      0      0 S   0.0   0.0   0:00.00 rcu_tas+\n"
            "     12 root      20   0       0      0      0 S   0.0   0.0   0:00.44 ksoftir+\n")

matches = re.finditer(regex, test_str)

for matchNum, match in enumerate(matches, start=1):

    print("Match {matchNum} was found at {start}-{end}: {match}".format(matchNum=matchNum, start=match.start(),
                                                                        end=match.end(), match=match.group()))

    for groupNum in range(0, len(match.groups())):
        groupNum = groupNum + 1

        print("Group {groupNum} found at {start}-{end}: {group}".format(groupNum=groupNum, start=match.start(groupNum),
                                                                        end=match.end(groupNum),
                                                                        group=match.group(groupNum)))

# Note: for Python 2.7 compatibility, use ur"" to prefix the regex and u"" to prefix the test string and substitution.
