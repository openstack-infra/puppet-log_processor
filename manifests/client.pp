# Copyright 2012-2013 Hewlett-Packard Development Company, L.P.
# Copyright 2013 OpenStack Foundation
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

# == Class: log_processor::client
#
class log_processor::client (
  $config_file,
  $statsd_host = undef,
) {

  file { '/etc/logprocessor/jenkins-log-client.yaml':
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0555',
    source  => $config_file,
    require => File['/etc/logprocessor'],
  }

  file { '/etc/init.d/jenkins-log-client':
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0555',
    source  => 'puppet:///modules/log_processor/jenkins-log-client.init',
    require => [
      File['/usr/local/bin/log-gearman-client.py'],
      File['/etc/logprocessor/jenkins-log-client.yaml'],
      File['/etc/default/jenkins-log-client'],
    ],
  }

  file { '/etc/default/jenkins-log-client':
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0444',
    content => template('log_processor/jenkins-log-client.default.erb'),
  }

  service { 'jenkins-log-client':
    enable     => true,
    hasrestart => true,
    subscribe  => File['/etc/logprocessor/jenkins-log-client.yaml'],
    require    => File['/etc/init.d/jenkins-log-client'],
  }

  include ::logrotate
  logrotate::file { 'log-client-debug.log':
    log     => '/var/log/logprocessor/log-client-debug.log',
    options => [
      'compress',
      'copytruncate',
      'missingok',
      'rotate 7',
      'daily',
      'notifempty',
    ],
    require => Service['jenkins-log-client'],
  }
}
