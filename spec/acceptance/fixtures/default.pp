$worker_config = 'gearman-host: localhost
gearman-port: 4730
output-host: localhost
output-port: 9999
output-mode: tcp
crm114-script: /usr/local/bin/classify-log.crm
crm114-data: /var/lib/crm114
mqtt-host: firehose.openstack.org
mqtt-port: 8883
mqtt-topic: gearman-logstash/localhost
mqtt-user: infra
mqtt-pass: mqtt_password
mqtt-ca-certs: /etc/logstash/mqtt-root-CA.pem.crt'

$client_config = 'source-url: http://localhost
zmq-publishers: []
subunit-files:
  - name: logs/testrepository.subunit
    build-queue-filter: gate
source-files:
  - name: console.html
    tags:
      - console'

file { '/tmp/jenkins-log-client.yaml':
  ensure  => present,
  content => $client_config,
}

file { '/etc/logprocessor/worker.yaml':
  ensure  => present,
  owner   => 'root',
  group   => 'root',
  mode    => '0644',
  content => $worker_config,
  require => Class['::log_processor'],
}

class { 'log_processor': }

class { 'log_processor::client':
  config_file => '/tmp/jenkins-log-client.yaml',
  statsd_host => 'graphite.openstack.org',
}

log_processor::worker { 'A':
  config_file => '/etc/logprocessor/worker.yaml',
  require     => File['/etc/logprocessor/worker.yaml'],
}
