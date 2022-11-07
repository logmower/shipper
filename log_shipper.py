#!/usr/local/bin/python3 -OO
import argparse
import asyncio
import collections
import os
import re
import socket
import ujson
import pymongo
from asyncinotify import Inotify, Mask
from datetime import datetime
from math import inf
from motor.motor_asyncio import AsyncIOMotorClient
from prometheus_client import Counter, Gauge, Histogram
from prometheus_client.exposition import generate_latest
from pymongo.errors import CollectionInvalid
from sanic import Sanic, text
from time import time

"""
To install dependencies:
pip3 install ujson pymongo motor asyncinotify prometheus_client sanic
"""

parser = argparse.ArgumentParser(description="Log shipper",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--dry-run", action="store_true",
    help="Do not insert anything into database")
parser.add_argument("--namespace", type=str,
    help="Namespace to monitor, all by default")
parser.add_argument("--exclude-pod-prefixes", nargs="*", type=str, default=["logmower-"],
    help="Pod prefixes to exclude")
parser.add_argument("--max-upload-queue-size", type=int, default=10000,
    help="Max upload queue size in records")
parser.add_argument("--max-connection-pool-size", type=int, default=1,
    help="Max MongoDB connection pool size")
parser.add_argument("--max-record-size", type=int, default=128 * 1024,
    help="Max record size in bytes, 128k by default")
parser.add_argument("--max-record-retention", type=int,
    help="Record retention in seconds, never by default")
parser.add_argument("--max-collection-size", type=int,
    help="MongoDB collection size limit in bytes, by default disabled")
parser.add_argument("--bulk-insertion-size", type=int, default=1000,
    help="MongoDB bulk insertion size in records")
parser.add_argument("--heuristic-parse-json", action="store_true",
    help="Attempt automatically unwrapping JSON records")
parser.add_argument("--heuristic-normalize-log-level", action="store_true",
    help="Normalize log.level values to Syslog defined keywords")

args = parser.parse_args()

ROOT = "/var/log/containers"
app = Sanic("tail")
tasks = dict()

with open("/etc/machine-id") as fh:
    machine_id = fh.read().strip()

host_info = {
    "id": machine_id,
    "architecture": os.uname().machine,
    "name": os.environ.get("NODE_NAME", socket.getfqdn())
}


log_files = dict()

gauge_log_files = Gauge(
    "logmower_log_file_count",
    "Number of tracked log files",
    ["state"])
gauge_queue_entries = Gauge(
    "logmower_queue_record_count",
    "Records queued for submission")
counter_unexpected_filenames = Counter(
    "logmower_invalid_filename_count",
    "Count of unexpected filenames in logs directory")
counter_inotify_events = Counter(
    "logmower_inotify_event_count",
    "Count of inotify events",
    ["mask"])
counter_skipped_bytes = Counter(
    "logmower_skipped_bytes",
    "Bytes that were skipped during startup due to being already present in data store")
counter_dropped_lines = Counter(
    "logmower_dropped_lines",
    "Lines dropped due to being part of too long record")
counter_heuristic_failures = Counter(
    "logmower_heuristic_failed_record_count",
    "Heuristic failures",
    ["mode"])
counter_records = Counter(
    "logmower_record_count",
    "Record count",
    ["stage"])
counter_insertion_errors = Counter(
    "logmower_insertion_error_count",
    "Exceptions caught during insertion of single event",
    ["exception"])
counter_bulk_insertions = Counter(
    "logmower_bulk_insertion_count",
    "Count of bulk insertions to database",
    ["status"])
histogram_bulk_submission_size = Histogram(
    "logmower_bulk_submission_message_count",
    "Bulk submission message count",
    buckets=(1, 5, 10, 50, 100, 500, 1000, 5000, 10000))
histogram_database_operation_latency = Histogram(
    "logmower_database_operation_latency",
    "Database operation latency",
    ["operation"],
    buckets=(0.1, 0.2, 0.5, 1, 5, 10, 50))
histogram_bulk_submission_latency = Histogram(
    "logmower_bulk_submission_latency",
    "Bulk submission latency",
    buckets=(0.1, 0.2, 0.5, 1, 5, 10, 50))
histogram_line_size = Histogram(
    "logmower_line_size_bytes",
    "Log file line size in sizes",
    buckets=(80, 160, 320, 640, 1280, inf))


NORMALIZED_LOG_LEVELS = {
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


async def uploader(coll, queue):
    then = time()
    kwargs = {}
    if args.max_record_retention:
        kwargs["expireAfterSeconds"] = args.max_record_retention
    await coll.create_index([("@timestamp", 1)], **kwargs)

    # Following index is used to look up where to resume submitting logs
    # after restart/crash
    await coll.create_index([("log.file.path", 1),
                             ("log.offset", 1)],
                            unique=True)

    # Indexes used for frequent searches
    await coll.create_index([("host.name", 1)])
    await coll.create_index([("kubernetes.pod.name", 1)],
                            sparse=True)
    await coll.create_index([("kubernetes.namespace", 1),
                             ("kubernetes.pod.name", 1),
                             ("kubernetes.container.name", 1)],
                            sparse=True)
    histogram_database_operation_latency.labels("create-index").observe(time() - then)

    messages = []
    while True:
        while len(messages) < args.bulk_insertion_size:
            try:
                o = await asyncio.wait_for(queue.get(), timeout=0.1)
            except asyncio.exceptions.TimeoutError:
                break
            gauge_queue_entries.set(queue.qsize())
            o["event"]["ingested"] = datetime.utcnow()
            messages.append(o)
        if not messages:
            continue
        try:
            # TODO: Don't retry submitting messages commit by bulk insert above
            then = time()
            await coll.insert_many(messages)
            histogram_database_operation_latency.labels("insert-many").observe(time() - then)
        except pymongo.errors.ServerSelectionTimeoutError:
            continue
        except pymongo.errors.BulkWriteError:
            counter_bulk_insertions.labels("failed").inc()
            for o in messages:
                o.pop("_id", None)
                o["event"]["ingested"] = datetime.utcnow()
                try:
                    then = time()
                    await coll.insert_one(o)
                    histogram_database_operation_latency.labels("insert-one").observe(time() - then)
                except Exception as e:
                    j = "%s.%s" % (e.__class__.__module__, e.__class__.__name__)
                    counter_insertion_errors.labels(j).inc()
                    counter_records.labels("dropped").inc()
                    print("Failed to insert (%s): %s" % (j, o))
                else:
                    counter_records.labels("commited").inc()
        else:
            counter_bulk_insertions.labels("successful").inc()
            histogram_bulk_submission_size.observe(len(messages))
            counter_records.labels("commited").inc(len(messages))
        messages = []


class LogFile(object):
    def __init__(self, loop, coll, queue, path, namespace_name, pod_name, container_name, start=False):
        self.path = path
        self.tail = 0
        self.more_content = asyncio.Event()
        self.fh = open(path, "rb")
        self.queue = queue
        self.namespace_name = namespace_name
        self.pod_name = pod_name
        self.container_name = container_name
        self.running = True
        self.coll = coll
        self.poke()
        self.state = "seeking"
        self.done = False
        self.loop = loop
        if start:
            self.start()

    def start(self):
        self.loop.create_task(self.handler_loop())

    def poke(self):
        self.tail = self.fh.seek(0, os.SEEK_END)
        self.more_content.set()

    def close(self):
        self.done = True
        self.poke()

    async def handler_loop(self):
        message = ""
        record_size = 0
        self.head = 0
        skip_next = False
        if not args.dry_run:
            then = time()
            last_record = await self.coll.find_one({
                "host.id": host_info["id"],
                "log.file.path": self.path
            }, sort=[("log.offset", -1)])
            histogram_database_operation_latency.labels("find-replay-offset").observe(time() - then)
            if last_record:
                self.head = last_record["log"]["offset"]
                counter_skipped_bytes.inc(self.head)
                skip_next = True

        self.state = "replaying"
        offset = self.head
        while self.running:
            while self.head >= self.tail:
                self.state = "watching"
                if self.done:
                    break
                await self.more_content.wait()
                self.more_content.clear()
            assert self.head < self.tail
            self.fh.seek(self.head)
            buf = self.fh.readline()

            try:
                reason = "unicode-encoding"
                line = buf.decode("utf-8")
                if len(line) < 45:
                    reason = "line-short"
                    raise ValueError()
                if not line[-1] == "\n":
                    reason = "no-newline  %s" % repr((buf))
                    raise ValueError()
                if not re.match("^(.+) (stdout|stderr)( (.))? (.*)$", line[:-1]):
                    reason = "no-regex-match"
                    raise ValueError()
                reason = "invalid-timestamp"
                event_created = datetime.strptime(line[:23], "%Y-%m-%dT%H:%M:%S.%f")
            except ValueError:
                print("Failed to parse file %s at offset %d, reason: %s" % (self.path, self.head, reason))
                break

            histogram_line_size.observe(len(buf))
            self.head += len(buf)
            record_size += len(buf)

            if record_size < args.max_record_size:
                # TODO: Support Docker runtime on EKS
                message += line[45:-1]

            state = line[43]
            if state == "P":
                # This is partial message
                continue
            assert state == "F", "Unknown line state"
            o = {}
            o["message"] = message
            o["log"] = {}
            message = ""
            record_size = 0

            if record_size > args.max_record_size:
                counter_records.labels("too-large").inc()
                # TODO: Log portion of the message
                continue

            stream = line[36:42].strip()
            if args.heuristic_parse_json and o["message"].startswith("{\""):
                # TODO: Follow Filebeat hints
                try:
                    j = ujson.loads(message)
                except ujson.JSONDecodeError:
                    counter_heuristic_failures.labels("invalid-json").inc()
                else:
                    # Merge only if parsed JSON message looks like it's
                    # conforming to ECS schema
                    if "@timestamp" in j and "message" in j:
                        o.update(j)
                    else:
                        o["json"] = j

            o["kubernetes"] = {
                "container": {
                    "name": self.container_name,
                },
                "namespace": self.namespace_name,
                "pod": {
                    "name": self.pod_name
                }
            }
            o["log"]["file"] = {
                "path": self.path
            }
            o["log"]["offset"] = offset
            o["host"] = host_info
            o["stream"] = stream
            o["event"] = {
                "created": event_created
            }

            if args.heuristic_normalize_log_level:
                if "level" in o["log"]:
                    level = o["log"]["level"].strip().lower()
                    try:
                        o["log"]["level"] = NORMALIZED_LOG_LEVELS[level]
                    except KeyError:
                        counter_heuristic_failures.labels("invalid-log-level").inc()
                else:
                    o["log"]["level"] = "error" if stream == "stderr" else "info"

            if "@timestamp" not in o:
                o["@timestamp"] = o["event"]["created"]
            o.pop("_id", None)

            if not skip_next:
                await self.queue.put(o)
                gauge_queue_entries.set(self.queue.qsize())
            skip_next = False
            offset = self.head
        self.state = "closing"
        self.fh.close()
        log_files.pop(self.path)


async def watcher(loop, queue, coll):
    print("Starting watching")
    with Inotify() as inotify:
        def add_file(path, done=False, start=False):
            if path in log_files:
                log_files[path].done = done
                return log_files[path]
            print("Adding file: %s" % path)

            m = re.match("/var/log/pods/(.*)_(.*)_.*/(.*)/[0-9]+\\.log$", path)

            if not m:
                print("Unexpected filename:", path)
                counter_unexpected_filenames.inc()
                return
            namespace_name, pod_name, container_name = m.groups()
            if args.namespace and args.namespace == namespace_name:
                return
            for prefix in args.exclude_pod_prefixes:
                if pod_name.startswith(prefix):
                    return
            if args.namespace and namespace_name != args.namespace:
                return
            lf = log_files[path] = LogFile(loop, coll, queue, path, namespace_name, pod_name, container_name)
            lf.done = done
            lf.start()
            inotify.add_watch(path, Mask.MODIFY | Mask.CLOSE_WRITE)
            return lf

        inotify.add_watch(ROOT, Mask.CREATE | Mask.ONLYDIR)

        # Register all existing log files
        for pod_dir in os.listdir("/var/log/pods"):
            m = re.match("(.*)_(.*)_(.*)$", pod_dir)
            if not m:
                print("Unexpected directory", pod_dir)
                continue
            namespace_name, pod_name, pod_id = m.groups()
            for container_name in os.listdir(os.path.join("/var/log/pods", pod_dir)):
                if not re.match("^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$", container_name):
                    print("Unexpected directory:", container_name)
                    continue
                for filename in os.listdir(os.path.join("/var/log/pods", pod_dir, container_name)):
                    m = re.match("[0-9]+\\.log$", filename)
                    if not m:
                        print("Unexpected filename:", filename)
                        continue
                    path = os.path.join("/var/log/pods", pod_dir, container_name, filename)
                    add_file(path, done=True)

        # Inspect currently running containers
        for filename in os.listdir("/var/log/containers"):
            path = os.path.realpath(os.path.join(os.path.join("/var/log/containers", filename)))
            add_file(path, done=False)

        for log_file in log_files.values():
            log_file.start()

        async for event in inotify:
            # Events for /var/log/pods
            if event.mask & Mask.CREATE:
                counter_inotify_events.labels("create").inc()
                add_file(os.path.realpath(event.path), start=True)

            # Events for /var/log/pods
            elif event.mask & Mask.CLOSE_WRITE:
                print("File closed: %s" % event.path)
                counter_inotify_events.labels("close_write").inc()
                log_file = log_files.get(str(event.path))
                log_file.close()
            elif event.mask & Mask.MODIFY:
                counter_inotify_events.labels("modify").inc()
                log_file = log_files.get(str(event.path))
                if log_file:
                    # TODO: Count cases where log_file is None
                    log_file.poke()
            elif event.mask & Mask.IGNORED:
                counter_inotify_events.labels("ignored").inc()
            else:
                raise NotImplementedError("Unhandled inotify event: %s" % event)


@app.route("/metrics")
async def handler(request):
    c = collections.Counter([j.state for j in log_files.values()])
    for key in ("seeking", "replaying", "watching", "closing"):
        gauge_log_files.labels(key).set(c[key])
    return text(generate_latest().decode("utf-8"))


async def dumper(queue):
    while True:
        try:
            o = await asyncio.wait_for(queue.get(), timeout=0.1)
        except asyncio.exceptions.TimeoutError:
            break
        else:
            gauge_queue_entries.set(queue.qsize())
            print(o)


@app.listener("before_server_start")
async def init(sanic, loop):
    queue = asyncio.Queue(args.max_upload_queue_size)
    if not args.dry_run:
        db = AsyncIOMotorClient(os.environ["MONGODB_HOST"],
            maxPoolSize=args.max_connection_pool_size).get_default_database()
        try:
            await db.create_collection("log",
                capped=bool(args.max_collection_size),
                size=args.max_collection_size)
        except CollectionInvalid:
            pass
        coll = db["log"]
        loop.create_task(uploader(coll, queue))
    else:
        coll = None
        loop.create_task(dumper(queue))
    loop.create_task(watcher(loop, queue, coll))


app.run(host="0.0.0.0", single_process=True)
