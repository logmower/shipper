import ujson
import re


def int64(value):
    """
    Clamp integers for Mongo
    """
    value = int(value)
    if value < -9223372036854775808:
        raise ValueError("Integer value %s too low" % value)
    elif value > 9223372036854775807:
        raise ValueError("Integer value %s too high" % value)
    return value


class DecodeStringJSON():
    """
    Match and extract JSON strings
    """
    @classmethod
    def match(cls, record):
        return record["message"].startswith("{\"")

    @classmethod
    def extract(cls, record, m):
        record["json"] = ujson.loads(record["message"])


class DecodeStringRegex():
    """
    Match and extract fields based on regular expressions
    """
    @classmethod
    def match(cls, record):
        return cls.PATTERN.match(record["message"])

    @classmethod
    def extract(cls, record, m):
        for key, value in m.groupdict().items():
            record[key] = value


class DecodeStringGoLogger(DecodeStringRegex):
    PATTERN = re.compile(
        "time=\"([0-9][0-9][0-9][0-9]\\-[0-9][0-9]\\-[0-9][0-9]T[0-9][0-9]\\:[0-9][0-9]\\:[0-9][0-9]Z)\" "
        "level=([a-z]+) "
        "msg=\"(.*?)"
        "( resource=(.*?))?\"$")

    @classmethod
    def extract(cls, record, m):
        _, level, msg, _, _ = m.groups()
        record["message"] = msg
        record["log"]["level"] = level


class DecodeStringCLF(DecodeStringRegex):
    PATTERN = re.compile("(\\S+) \\S+ (\\S+) \\[([^\\]]+)\\] "
        "\"([A-Z]+) ([^ \"]+)? HTTP/[0-9.]+\" ([0-9]{3}) ([0-9]+|-)")

    @classmethod
    def extract(cls, record, m):
        client, userid, _, method, request, status, size = m.groups()
        record["message"] = "%s %s" % (method, request)
        record["event"]["type"] = "access"
        if userid:
            record["client"]["user"] = userid
        record["client"]["address"] = client
        record["http"]["request"]["method"] = method
        record["http"]["response"]["bytes"] = int64(size)
        record["http"]["response"]["status_code"] = int64(status)


class ExtractSanic():
    FIELDS = {"type", "response_time", "status_code", "path", "method",
        "remote", "user_agent", "host", "logger", "level", "timestamp",
        "worker", "req_id"}

    @classmethod
    def match(cls, record):
        return "json" in record and cls.FIELDS.issubset(record["json"].keys())

    @classmethod
    def extract(cls, record, m):
        j = record.pop("json")
        if "traceback" in j:
            record["error"]["stack_trace"] = j["traceback"]
        record["log"]["level"] = j["level"]
        record["message"] = "%s %s" % (j["method"], j["path"])
        record["event"]["type"] = "access"
        record["client"]["address"] = j["remote"]
        record["http"]["request"]["path"] = j["path"]
        record["http"]["request"]["method"] = j["method"]
        record["http"]["response"]["status_code"] = int64(j["status_code"])
        # TODO: timestamp, type, user_agent, response_time, req_id, logger, worker
        # TODO: optional length


class ExtractElasticCommonSchema():
    @classmethod
    def match(cls, record):
        json_keys = record.get("json", {}).keys()
        return "@timestamp" in json_keys and "message" in json_keys

    @classmethod
    def extract(cls, record, m):
        record.update(record.pop("json"))


class NormalizeLogLevel():
    MAPPING = {
        # Syslog level emergency (0), should not be used by applications
        "emerg": "emergency",
        "panic": "emergency",

        # Syslog level alert (1)
        "a": "alert",

        # Syslog level critical (2), likely results in program exit
        "crit": "critical",
        "fatal": "critical",
        "f": "critical",

        # Syslog level error (3)
        "err": "error",
        "e": "error",

        # Syslog level warning (4)
        "warn": "warning",
        "w": "warning",

        # Following log levels should not be enabled by default

        # Syslog level notice (5)
        "n": "notice",

        # Syslog level informational (6)
        "informational": "info",
        "i": "info",

        # Syslog level debug (7)
        "d": "debug",
        "d1": "debug",
        "d2": "debug",
        "d3": "debug",
        "d4": "debug",
        "d5": "debug",
        "trace": "debug",
    }

    @classmethod
    def match(cls, record):
        return "level" in record.get("log", "")

    @classmethod
    def extract(cls, record, m):
        z = record["log"]["level"].strip().lower()
        record["log"]["level"] = cls.MAPPING.get(z, z)


class BestEffortTopLevelMerge():
    @classmethod
    def match(cls, record):
        json_keys = record.get("json", {}).keys()
        return "level" in json_keys and ("msg" in json_keys or "message" in json_keys)

    @classmethod
    def extract(cls, record, m):
        j = record["json"]
        record["message"] = j.get("message") or j.get("msg")
        record["log"]["level"] = j["level"]


string_decoders = (
    DecodeStringJSON,
    DecodeStringCLF,
    DecodeStringGoLogger
)

record_manglers = (
    ExtractElasticCommonSchema,
    ExtractSanic,
    BestEffortTopLevelMerge,
    NormalizeLogLevel
)


def process(rec):
    rec["heuristics"] = []
    for decode_pass in string_decoders, record_manglers:
        for heuristic in decode_pass:
            m = heuristic.match(rec)
            if m:
                rec["heuristics"].append(heuristic.__name__)
                heuristic.extract(rec, m)
