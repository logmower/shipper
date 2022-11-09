#!/usr/local/bin/python3
import argparse
import asyncio
import collections
import os
import re
import socket
import ujson
import prometheus_async
import pymongo
from aiofile import async_open
from asyncinotify import Inotify, Mask
from datetime import datetime
from math import inf
from motor.motor_asyncio import AsyncIOMotorClient
from prometheus_client import Counter, Gauge, Histogram
from pymongo.errors import CollectionInvalid
from time import time

parser = argparse.ArgumentParser(description="Log shipper",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--dry-run", action="store_true",
    help="Do not insert anything into database")

# Target selectors
parser.add_argument("--namespace", type=str,
    help="Namespace to watch, all by default")
parser.add_argument("--exclude-pod-prefixes", nargs="*", type=str, default=["logmower-"],
    help="Pod prefixes to exclude in any of the watched namespaces")

# Tunables
parser.add_argument("--max-upload-queue-size", type=int, default=10000,
    help="Max upload queue size in records")
parser.add_argument("--max-connection-pool-size", type=int, default=1,
    help="Max MongoDB connection pool size")
parser.add_argument("--max-record-size", type=int, default=128 * 1024,
    help="Max record size in bytes, 128k by default")
parser.add_argument("--bulk-insertion-size", type=int, default=1000,
    help="MongoDB bulk insertion size in records")

# Retention
parser.add_argument("--max-record-retention", type=int,
    help="Record retention in seconds, never by default")
parser.add_argument("--max-collection-size", type=int,
    help="MongoDB collection size limit in bytes, by default disabled")

# Optional heuristics
parser.add_argument("--parse-json", action="store_true",
    help="Parse log records that look like JSON")
parser.add_argument("--merge-top-level", action="store_true",
    help="Merge decoded JSON records on top level if '@timestamp' and 'message' fields are present (looks like ECS schema)")
parser.add_argument("--normalize-log-level", action="store_true",
    help="Normalize log.level values to Syslog defined keywords")
parser.add_argument("--stream-to-log-level", action="store_true",
    help="Upon missing log.level map stderr to 'error' and stdout to 'info'")

args = parser.parse_args()

ROOT = "/var/log/containers"
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
counter_bulk_insertion_errors = Counter(
    "logmower_bulk_insertion_error_count",
    "Exceptions caught during bulk insertions",
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
            else:
                gauge_queue_entries.set(queue.qsize())
                messages.append(o)
        if not messages:
            continue

        # Set ingestion timestamp
        now = datetime.utcnow()
        for o in messages:
            o["event"]["ingested"] = now

        try:
            then = time()
            await coll.insert_many(messages)
            histogram_database_operation_latency.labels("insert-many").observe(time() - then)
        except pymongo.errors.ServerSelectionTimeoutError:
            counter_bulk_insertions.labels("timed-out").inc()
            continue
        except pymongo.errors.NotPrimaryError:
            counter_bulk_insertions.labels("not-primary").inc()
            continue
        except pymongo.errors.BulkWriteError as e:
            counter_bulk_insertions.labels("retried-as-singles").inc()
            j = "%s.%s" % (e.__class__.__module__, e.__class__.__name__)
            counter_bulk_insertion_errors.labels(j).inc()
            print("Bulk insert failed: %s" % j)
            for o in messages:
                # Remove ObjectID set during insert_many,
                # as we want duplicate errors to be caused only by
                # combination of log.file and log.offset collisions
                o.pop("_id", None)

                # Reset ingestion timestamp
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
    def __init__(self, coll, queue, path, namespace_name, pod_name, container_name, start=False, lookup_offset=True):
        self.offset = 0
        self.path = path
        self.buf = b""
        self.finished = False
        self.more_content = asyncio.Event()
        self.queue = queue
        self.namespace_name = namespace_name
        self.pod_name = pod_name
        self.container_name = container_name
        self.coll = coll
        self._state = None
        self.state = "init"
        self.lookup_offset = lookup_offset
        if start:
            self.start()

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        self._state = value
        c = collections.Counter([j.state for j in log_files.values()])
        for key in ("seeking", "replaying", "watching", "closing"):
            gauge_log_files.labels(key).set(c[key])

    def done(self):
        # Do not expect more content in this file
        self.finished = True
        self.notify()

    def notify(self):
        # Signal that there is more content in this file
        self.more_content.set()

    def start(self):
        asyncio.create_task(self.handler_loop())

    async def handler_loop(self):
        self.state = "seeking"
        message = ""
        record_size = 0
        skip_next = False
        if not args.dry_run:
            then = time()
            last_record = await self.coll.find_one({
                "host.id": host_info["id"],
                "log.file.path": self.path
            }, sort=[("log.offset", -1)])
            histogram_database_operation_latency.labels("offset-lookup").observe(time() - then)
            if last_record:
                self.offset = last_record["log"]["offset"]
                counter_skipped_bytes.inc(self.offset)
                print("Skipping", self.offset, "bytes for", self.path)
                skip_next = True

        self.state = "replaying"
        record_offset = self.offset
        line_offset = self.offset

        async with async_open(self.path, "rb") as fp:
            fp.seek(self.offset)
            while True:
                buf = await fp.readline()
                self.offset += len(buf)
                if not buf and self.finished:
                    break
                if not buf and self.state != "watching":
                    print("Finished replaying:", self.path)
                    self.state = "watching"
                self.buf += buf
                if not buf or not buf.endswith(b"\n"):
                    await self.more_content.wait()
                    self.more_content.clear()
                    continue

                line_size = len(self.buf)
                line = self.buf[:-1].decode("utf-8")

                record_offset = line_offset
                line_offset = self.offset
                self.buf = b""

                try:
                    reason = "unicode-encoding"
                    if len(line) < 45:
                        reason = "line-short"
                        raise ValueError()
                    if not re.match("^(.+) (stdout|stderr)( (.))? (.*)$", line):
                        reason = "no-regex-match"
                        raise ValueError()
                    reason = "invalid-timestamp"
                    event_created = datetime.strptime(line[:23], "%Y-%m-%dT%H:%M:%S.%f")
                except ValueError:
                    print("Failed to parse file %s at offset %d, reason %s: %s" % (self.path, line_offset, reason, repr(line)))
                    break

                histogram_line_size.observe(line_size)
                record_size += line_size

                if record_size < args.max_record_size:
                    # TODO: Support Docker runtime on EKS
                    message += line[45:]

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
                if args.parse_json and o["message"].startswith("{\""):
                    # TODO: Follow Filebeat hints
                    try:
                        j = ujson.loads(message)
                    except ujson.JSONDecodeError:
                        counter_heuristic_failures.labels("invalid-json").inc()
                    else:
                        # Merge only if parsed JSON message looks like it's
                        # conforming to ECS schema
                        if args.merge_top_level and "@timestamp" in j and "message" in j:
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
                o["log"]["offset"] = record_offset
                o["host"] = host_info
                o["stream"] = stream
                o["event"] = {
                    "created": event_created
                }

                if args.normalize_log_level and "level" in o["log"]:
                    level = o["log"]["level"].strip().lower()
                    try:
                        o["log"]["level"] = NORMALIZED_LOG_LEVELS[level]
                    except KeyError:
                        counter_heuristic_failures.labels("invalid-log-level").inc()
                if args.stream_to_log_level and "level" not in o["log"]:
                    o["log"]["level"] = "error" if stream == "stderr" else "info"

                if "@timestamp" not in o:
                    o["@timestamp"] = o["event"]["created"]
                o.pop("_id", None)

                if not skip_next:
                    await self.queue.put(o)
                    gauge_queue_entries.set(self.queue.qsize())
                skip_next = False
                record_offset = line_offset
        self.state = "closing"
        log_files.pop(self.path)


async def watcher(queue, coll):
    print("Starting watching")
    with Inotify() as inotify:
        def add_file(path, finished=False, start=False, lookup_offset=True):
            if path in log_files:
                log_files[path].finished = finished
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
            lf = log_files[path] = LogFile(coll, queue, path, namespace_name,
                pod_name, container_name, start, lookup_offset)
            lf.finished = finished
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
                    add_file(path, finished=True)

        # Add currently running containers as not finished
        for filename in os.listdir("/var/log/containers"):
            path = os.path.realpath(os.path.join(os.path.join("/var/log/containers", filename)))
            add_file(path, finished=False)

        # Start coroutines after we know for sure which ones have finished
        for log_file in log_files.values():
            log_file.start()

        async for event in inotify:
            # Events for /var/log/containers
            if event.mask & Mask.CREATE:
                counter_inotify_events.labels("create").inc()
                add_file(os.path.realpath(event.path), start=True, lookup_offset=False)

            # Events for /var/log/pods
            elif event.mask & Mask.CLOSE_WRITE:
                print("File closed: %s" % event.path)
                counter_inotify_events.labels("close_write").inc()
                log_file = log_files.get(str(event.path))
                if log_file:
                    # TODO: Why does this happen?
                    log_file.done()
            elif event.mask & Mask.MODIFY:
                counter_inotify_events.labels("modify").inc()
                log_file = log_files.get(str(event.path))
                if log_file:
                    # In some cases MODIFY events are triggered after CLOSE_WRITE
                    log_file.notify()
            elif event.mask & Mask.IGNORED:
                counter_inotify_events.labels("ignored").inc()
            else:
                raise NotImplementedError("Unhandled inotify event: %s" % event)


async def dumper(queue):
    while True:
        try:
            o = await asyncio.wait_for(queue.get(), timeout=0.1)
        except asyncio.exceptions.TimeoutError:
            break
        else:
            gauge_queue_entries.set(queue.qsize())
            print(o)


async def main():
    queue = asyncio.Queue(args.max_upload_queue_size)
    tasks = []
    if not args.dry_run:
        db = AsyncIOMotorClient(os.environ["MONGO_URI"],
            maxPoolSize=args.max_connection_pool_size).get_default_database()
        try:
            await db.create_collection("log",
                capped=bool(args.max_collection_size),
                size=args.max_collection_size)
        except CollectionInvalid:
            pass
        coll = db["log"]
        tasks.append(uploader(coll, queue))
    else:
        coll = None
        tasks.append(dumper(queue))
    tasks.append(prometheus_async.aio.web.start_http_server(addr="0.0.0.0", port=8000))
    tasks.append(watcher(queue, coll))
    await asyncio.gather(*tasks)

asyncio.run(main())
