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

# == Class: log_processor
#
class log_processor (
) {
  if ! defined(Package['python-daemon']) {
    package { 'python-daemon':
      ensure => present,
    }
  }

  group { 'logprocessor':
    ensure => present,
  }
  user { 'logprocessor':
    ensure     => present,
    comment    => 'Log Processor User',
    home       => '/etc/logprocessor',
    gid        => 'logprocessor',
    shell      => '/bin/bash',
    membership => 'minimum',
    require    => Group['logprocessor'],
  }

  file { '/etc/logprocessor':
    ensure  => directory,
    owner   => 'logprocessor',
    group   => 'logprocessor',
    mode    => '0755',
    require => User['logprocessor'],
  }

  file { '/var/log/logprocessor':
    ensure  => directory,
    owner   => 'logprocessor',
    group   => 'logprocessor',
    mode    => '0755',
    require => User['logprocessor'],
  }

  package { 'python-zmq':
    ensure => present,
  }

  package { 'python-yaml':
    ensure => present,
  }

  package { 'crm114':
    ensure => present,
  }

  include ::pip
  package { 'gear':
    ensure   => latest,
    provider => openstack_pip,
    require  => Class['pip'],
  }

  if ! defined(Package['statsd']) {
    package { 'statsd':
      # NOTE(cmurphy) If this is not pinned, the openstack_pip provider will
      # attempt to install latest and conflict with the <3 cap from
      # os-performance-tools. Unpin this when os-performance-tools raises its
      # cap.
      # NOTE (clarkb) we also install it here because geard can report stats
      # with statsd so need it even if subunit2sql is not used.
      ensure   => '2.1.2',
      provider => openstack_pip,
      require  => Class['pip']
    }
  }

  # Temporarily pin paho-mqtt to 1.2.3 since 1.3.0 won't support TLS on
  # Trusty's Python 2.7.
  if ! defined(Package['paho-mqtt']) {
    package { 'paho-mqtt':
      ensure   => '1.2.3',
      provider => openstack_pip,
      require  => Class['pip'],
    }
  }

  file { '/var/lib/crm114':
    ensure  => directory,
    owner   => 'logprocessor',
    group   => 'logprocessor',
    require => User['logprocessor'],
  }

  file { '/usr/local/bin/classify-log.crm':
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    source  => 'puppet:///modules/log_processor/classify-log.crm',
    require => [
      Package['crm114'],
    ],
  }

  file { '/usr/local/bin/log-gearman-client.py':
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    source  => 'puppet:///modules/log_processor/log-gearman-client.py',
    require => [
      Package['python-daemon'],
      Package['python-zmq'],
      Package['python-yaml'],
      Package['gear'],
    ],
  }

  file { '/usr/local/bin/log-gearman-worker.py':
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    source  => 'puppet:///modules/log_processor/log-gearman-worker.py',
    require => [
      Package['python-daemon'],
      Package['python-zmq'],
      Package['python-yaml'],
      Package['gear'],
    ],
  }
}
