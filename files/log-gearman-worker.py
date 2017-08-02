#!/usr/bin/python2
#
# Copyright 2013 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import argparse
import cStringIO
import daemon
import gear
import gzip
import json
import logging
import os
import Queue
import re
import select
import socket
import subprocess
import sys
import threading
import time
import urllib2
import yaml

import paho.mqtt.publish as publish

try:
    import daemon.pidlockfile as pidfile_mod
except ImportError:
    import daemon.pidfile as pidfile_mod


def semi_busy_wait(seconds):
    # time.sleep() may return early. If it does sleep() again and repeat
    # until at least the number of seconds specified has elapsed.
    start_time = time.time()
    while True:
        time.sleep(seconds)
        cur_time = time.time()
        seconds = seconds - (cur_time - start_time)
        if seconds <= 0.0:
            return


class FilterException(Exception):
    pass


class CRM114Filter(object):
    def __init__(self, script, path, build_status):
        self.p = None
        self.script = script
        self.path = path
        self.build_status = build_status
        if build_status not in ['SUCCESS', 'FAILURE']:
            return
        if not os.path.exists(path):
            os.makedirs(path)
        args = [script, path, build_status]
        self.p = subprocess.Popen(args,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  stdin=subprocess.PIPE,
                                  close_fds=True)

    def process(self, data):
        if not self.p:
            return
        self.p.stdin.write(data['message'].encode('utf-8') + '\n')
        (r, w, x) = select.select([self.p.stdout], [],
                                  [self.p.stdin, self.p.stdout], 20)
        if not r:
            self.p.kill()
            raise FilterException('Timeout reading from CRM114')
        r = self.p.stdout.readline()
        if not r:
            err = self.p.stderr.read()
            if err:
                raise FilterException(err)
            else:
                raise FilterException('Early EOF from CRM114')
        r = r.strip()
        data['error_pr'] = float(r)

    def _catchOSError(self, method):
        try:
            method()
        except OSError:
            logging.exception("Subprocess cleanup failed.")

    def close(self):
        if not self.p:
            return
        # CRM114 should die when its stdinput is closed. Close that
        # fd along with stdout and stderr then return.
        self._catchOSError(self.p.stdin.close)
        self._catchOSError(self.p.stdout.close)
        self._catchOSError(self.p.stderr.close)
        self._catchOSError(self.p.wait)


class CRM114FilterFactory(object):
    name = "CRM114"

    def __init__(self, script, basepath):
        self.script = script
        self.basepath = basepath

    def create(self, fields):
        filename = re.sub('\.', '_', fields['filename'])
        path = os.path.join(self.basepath, filename)
        return CRM114Filter(self.script, path, fields['build_status'])


class LogRetriever(threading.Thread):
    def __init__(self, gearman_worker, filters, logq, mqtt=None):
        threading.Thread.__init__(self)
        self.gearman_worker = gearman_worker
        self.filters = filters
        self.logq = logq
        self.mqtt = mqtt

    def run(self):
        while True:
            try:
                self._handle_event()
            except:
                logging.exception("Exception retrieving log event.")

    def _handle_event(self):
        fields = {}
        source_url = ''
        job = self.gearman_worker.getJob()
        try:
            arguments = json.loads(job.arguments.decode('utf-8'))
            source_url = arguments['source_url']
            retry = arguments['retry']
            event = arguments['event']
            logging.debug("Handling event: " + json.dumps(event))
            fields = event.get('fields') or event.get('@fields')
            tags = event.get('tags') or event.get('@tags')
            if fields['build_status'] != 'ABORTED':
                # Handle events ignoring aborted builds. These builds are
                # discarded by zuul.
                log_lines = self._retrieve_log(source_url, retry)

                try:
                    all_filters = []
                    for f in self.filters:
                        logging.debug("Adding filter: %s" % f.name)
                        all_filters.append(f.create(fields))
                    filters = all_filters

                    logging.debug("Pushing " + str(len(log_lines)) +
                                  " log lines.")
                    base_event = {}
                    base_event.update(fields)
                    base_event["tags"] = tags
                    for line in log_lines:
                        out_event = base_event.copy()
                        out_event["message"] = line
                        new_filters = []
                        for f in filters:
                            try:
                                f.process(out_event)
                                new_filters.append(f)
                            except FilterException:
                                logging.exception("Exception filtering event: "
                                                  "%s" % line.encode("utf-8"))
                        filters = new_filters
                        self.logq.put(out_event)
                finally:
                    for f in all_filters:
                        f.close()
            job.sendWorkComplete()
            if self.mqtt:
                msg = json.dumps({
                    'build_uuid': fields.get('build_uuid'),
                    'source_url': source_url,
                    'status': 'success',
                })
                self.mqtt.publish_single(msg, fields.get('project'),
                                         fields.get('build_change'),
                                         'retrieve_logs')
        except Exception as e:
            logging.exception("Exception handling log event.")
            job.sendWorkException(str(e).encode('utf-8'))
            if self.mqtt:
                msg = json.dumps({
                    'build_uuid': fields.get('build_uuid'),
                    'source_url': source_url,
                    'status': 'failure',
                })
                self.mqtt.publish_single(msg, fields.get('project'),
                                         fields.get('build_change'),
                                         'retrieve_logs')

    def _retrieve_log(self, source_url, retry):
        # TODO (clarkb): This should check the content type instead of file
        # extension for determining if gzip was used.
        gzipped = False
        raw_buf = b''
        try:
            gzipped, raw_buf = self._get_log_data(source_url, retry)
        except urllib2.HTTPError as e:
            if e.code == 404:
                logging.info("Unable to retrieve %s: HTTP error 404" %
                             source_url)
            else:
                logging.exception("Unable to get log data.")
        except Exception:
            # Silently drop fatal errors when retrieving logs.
            # TODO (clarkb): Handle these errors.
            # Perhaps simply add a log message to raw_buf?
            logging.exception("Unable to get log data.")
        if gzipped:
            logging.debug("Decompressing gzipped source file.")
            raw_strIO = cStringIO.StringIO(raw_buf)
            f = gzip.GzipFile(fileobj=raw_strIO)
            buf = f.read().decode('utf-8')
            raw_strIO.close()
            f.close()
        else:
            logging.debug("Decoding source file.")
            buf = raw_buf.decode('utf-8')
        return buf.splitlines()

    def _get_log_data(self, source_url, retry):
        gzipped = False
        try:
            # TODO(clarkb): We really should be using requests instead
            # of urllib2. urllib2 will automatically perform a POST
            # instead of a GET if we provide urlencoded data to urlopen
            # but we need to do a GET. The parameters are currently
            # hardcoded so this should be ok for now.
            logging.debug("Retrieving: " + source_url + ".gz?level=INFO")
            req = urllib2.Request(source_url + ".gz?level=INFO")
            req.add_header('Accept-encoding', 'gzip')
            r = urllib2.urlopen(req)
        except urllib2.URLError:
            try:
                # Fallback on GETting unzipped data.
                logging.debug("Retrieving: " + source_url + "?level=INFO")
                r = urllib2.urlopen(source_url + "?level=INFO")
            except:
                logging.exception("Unable to retrieve source file.")
                raise
        except:
            logging.exception("Unable to retrieve source file.")
            raise
        if ('gzip' in r.info().get('Content-Type', '') or
            'gzip' in r.info().get('Content-Encoding', '')):
            gzipped = True

        raw_buf = r.read()
        # Hack to read all of Jenkins console logs as they upload
        # asynchronously. After each attempt do an exponential backup before
        # the next request for up to 255 seconds total, if we do not
        # retrieve the entire file. Short circuit when the end of file string
        # for console logs, '\n</pre>\n', is read.
        if (retry and not gzipped and
            raw_buf[-8:].decode('utf-8') != '\n</pre>\n'):
            content_len = len(raw_buf)
            backoff = 1
            while backoff < 129:
                # Try for up to 255 seconds to retrieve the complete log file.
                try:
                    logging.debug(str(backoff) + " Retrying fetch of: " +
                                  source_url + "?level=INFO")
                    logging.debug("Fetching bytes=" + str(content_len) + '-')
                    req = urllib2.Request(source_url + "?level=INFO")
                    req.add_header('Range', 'bytes=' + str(content_len) + '-')
                    r = urllib2.urlopen(req)
                    raw_buf += r.read()
                    content_len = len(raw_buf)
                except urllib2.HTTPError as e:
                    if e.code == 416:
                        logging.exception("Index out of range.")
                    else:
                        raise
                finally:
                    if raw_buf[-8:].decode('utf-8') == '\n</pre>\n':
                        break
                    semi_busy_wait(backoff)
                    backoff += backoff

        return gzipped, raw_buf


class StdOutLogProcessor(object):
    def __init__(self, logq, pretty_print=False, mqtt=None):
        self.logq = logq
        self.pretty_print = pretty_print
        self.mqtt = mqtt

    def handle_log_event(self):
        log = self.logq.get()
        if self.pretty_print:
            print(json.dumps(log, sort_keys=True,
                  indent=4, separators=(',', ': ')))
        else:
            print(json.dumps(log))
        # Push each log event through to keep logstash up to date.
        sys.stdout.flush()
        if self.mqtt:
            msg = json.dumps({
                'build_uuid': log.get('build_uuid'),
                'source_url': log.get('log_url'),
                'status': 'success',
            })
            self.mqtt.publish_single(msg, log.get('project'),
                                     log.get('build_change'),
                                     'logs_to_logstash')


class INETLogProcessor(object):
    socket_type = None

    def __init__(self, logq, host, port, mqtt=None):
        self.logq = logq
        self.host = host
        self.port = port
        self.socket = None
        self.mqtt = mqtt

    def _connect_socket(self):
        logging.debug("Creating socket.")
        self.socket = socket.socket(socket.AF_INET, self.socket_type)
        self.socket.connect((self.host, self.port))

    def handle_log_event(self):
        log = self.logq.get()
        try:
            if self.socket is None:
                self._connect_socket()
            self.socket.sendall((json.dumps(log) + '\n').encode('utf-8'))
            if self.mqtt:
                msg = json.dumps({
                    'build_uuid': log.get('build_uuid'),
                    'source_url': log.get('log_url'),
                    'status': 'success',
                })
                self.mqtt.publish_single(msg, log.get('project'),
                                         log.get('build_change'),
                                         'logs_to_logstash')
        except:
            logging.exception("Exception sending INET event.")
            # Logstash seems to take about a minute to start again. Wait 90
            # seconds before attempting to reconnect. If logstash is not
            # available after 90 seconds we will throw another exception and
            # die.
            semi_busy_wait(90)
            self._connect_socket()
            self.socket.sendall((json.dumps(log) + '\n').encode('utf-8'))
             if self.mqtt:
                 msg = json.dumps({
                     'build_uuid': log.get('build_uuid'),
                     'status': 'success',
                 })
                 self.mqtt.publish_single(msg, log.get('project'),
                                          log.get('build_change'),
                                          'logs_to_logstash')


class UDPLogProcessor(INETLogProcessor):
    socket_type = socket.SOCK_DGRAM


class TCPLogProcessor(INETLogProcessor):
    socket_type = socket.SOCK_STREAM


class PushMQTT(object):
    def __init__(self, hostname, base_topic, port=1883, client_id=None,
                 keepalive=60, will=None, auth=None, tls=None, qos=0):
        self.hostname = hostname
        self.port = port
        self.client_id = client_id
        self.keepalive = 60
        self.will = will
        self.auth = auth
        self.tls = tls
        self.qos = qos
        self.base_topic = base_topic

    def _generate_topic(self, project, job_id, action):
        return '/'.join([self.base_topic, project, job_id, action])

    def publish_single(self, msg, project, job_id, action):
        topic = _generate_topic(project, job_id)
        publish.single(topic, msg, hostname=self.hostname,
                       port=self.port, client_id=self.client_id,
                       keepalive=self.keepalive, will=self.will,
                       auth=self.auth, tls=self.tls, qos=self.qos)


class Server(object):
    def __init__(self, config, debuglog):
        # Config init.
        self.config = config
        self.gearman_host = self.config['gearman-host']
        self.gearman_port = self.config['gearman-port']
        self.output_host = self.config['output-host']
        self.output_port = self.config['output-port']
        self.output_mode = self.config['output-mode']
        mqtt_host = self.config.get('mqtt-host')
        mqtt_port = self.config.get('mqtt-port', 1883)
        mqtt_user = self.config.get('mqtt-user')
        mqtt_pass = self.config.get('mqtt-pass')
        mqtt_topic = self.configget('mqtt-topic', 'gearman-subunit')
        mqtt_ca_certs = self.config.get('mqtt-ca-certs')
        mqtt_certfile = self.config.get('mqtt-certfile')
        mqtt_keyfile = self.config.get('mqtt-keyfile')
        # Pythong logging output file.
        self.debuglog = debuglog
        self.retriever = None
        self.logqueue = Queue.Queue(131072)
        self.processor = None
        self.filter_factories = []
        crmscript = self.config.get('crm114-script')
        crmdata = self.config.get('crm114-data')
        if crmscript and crmdata:
            self.filter_factories.append(
                CRM114FilterFactory(crmscript, crmdata))
        # Setup MQTT
        self.mqtt = None
        if mqtt_host:
            auth = None
            if mqtt_user:
                auth = {'username': mqtt_user}
            if mqtt_pass:
                auth['password'] = mqtt_pass
            tls = None
            if mqtt_ca_certs:
                tls = {'ca_certs': mqtt_ca_certs, 'certfile': mqtt_certfile,
                        'keyfile': mqtt_keyfile}

            self.mqtt = PushMQTT(mqtt_host, mqtt_topic, port=mqtt_port,
                                 auth=auth, tls=tls)

    def setup_logging(self):
        if self.debuglog:
            logging.basicConfig(format='%(asctime)s %(message)s',
                                filename=self.debuglog, level=logging.DEBUG)
        else:
            # Prevent leakage into the logstash log stream.
            logging.basicConfig(level=logging.CRITICAL)
        logging.debug("Log pusher starting.")

    def wait_for_name_resolution(self, host, port):
        while True:
            try:
                socket.getaddrinfo(host, port)
            except socket.gaierror as e:
                if e.errno == socket.EAI_AGAIN:
                    logging.debug("Temporary failure in name resolution")
                    time.sleep(2)
                    continue
                else:
                    raise
            break

    def setup_retriever(self):
        hostname = socket.gethostname()
        gearman_worker = gear.Worker(hostname + b'-pusher')
        self.wait_for_name_resolution(self.gearman_host, self.gearman_port)
        gearman_worker.addServer(self.gearman_host,
                                 self.gearman_port)
        gearman_worker.registerFunction(b'push-log')
        self.retriever = LogRetriever(gearman_worker, self.filter_factories,
                                      self.logqueue, mqtt=self.mqtt)

    def setup_processor(self):
        if self.output_mode == "tcp":
            self.processor = TCPLogProcessor(self.logqueue,
                                             self.output_host,
                                             self.output_port,
                                             mqtt=self.mqtt)
        elif self.output_mode == "udp":
            self.processor = UDPLogProcessor(self.logqueue,
                                             self.output_host,
                                             self.output_port,
                                             mqtt=self.mqtt)
        else:
            # Note this processor will not work if the process is run as a
            # daemon. You must use the --foreground option.
            self.processor = StdOutLogProcessor(self.logqueue, mqtt=self.mqtt)

    def main(self):
        self.setup_retriever()
        self.setup_processor()

        self.retriever.daemon = True
        self.retriever.start()

        while True:
            try:
                self.processor.handle_log_event()
            except:
                logging.exception("Exception processing log event.")
                raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", required=True,
                        help="Path to yaml config file.")
    parser.add_argument("-d", "--debuglog",
                        help="Enable debug log. "
                             "Specifies file to write log to.")
    parser.add_argument("--foreground", action='store_true',
                        help="Run in the foreground.")
    parser.add_argument("-p", "--pidfile",
                        default="/var/run/jenkins-log-pusher/"
                                "jenkins-log-gearman-worker.pid",
                        help="PID file to lock during daemonization.")
    args = parser.parse_args()

    with open(args.config, 'r') as config_stream:
        config = yaml.load(config_stream)
    server = Server(config, args.debuglog)

    if args.foreground:
        server.setup_logging()
        server.main()
    else:
        pidfile = pidfile_mod.TimeoutPIDLockFile(args.pidfile, 10)
        with daemon.DaemonContext(pidfile=pidfile):
            server.setup_logging()
            server.main()


if __name__ == '__main__':
    main()
