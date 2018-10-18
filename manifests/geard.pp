# Copyright 2012-2013 Hewlett-Packard Development Company, L.P.
# Copyright 2017 OpenStack Foundation
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

# == Class: log_processor::geard
#
# Run geard as system service
class log_processor::geard (
  $statsd_host = undef,
  $geard_port  = '4730',
) {
  file { '/var/log/geard':
    ensure  => directory,
    owner   => 'logprocessor',
    group   => 'logprocessor',
    mode    => '0755',
    require => User['logprocessor'],
  }

  file { '/etc/init.d/geard':
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0555',
    source  => 'puppet:///modules/log_processor/geard.init',
    require => [
      Package['gear'],
      File['/etc/default/geard'],
    ],
  }

  file { '/etc/default/geard':
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0444',
    content => template('log_processor/geard.default.erb'),
  }

  if ($::operatingsystem == 'Ubuntu') and ($::operatingsystemrelease >= '16.04') {
    # This is a hack to make sure that systemd is aware of the new service
    # before we attempt to start it.
    exec { 'geard-systemd-daemon-reload':
      command     => '/bin/systemctl daemon-reload',
      before      => Service['geard'],
      subscribe   => File['/etc/init.d/geard'],
      refreshonly => true,
    }
  }

  service { 'geard':
    enable     => true,
    hasrestart => true,
    subscribe  => File['/etc/default/geard'],
    require    => [
      File['/etc/init.d/geard'],
      File['/var/log/geard'],
    ],
  }

  include ::logrotate
  logrotate::file { 'rotate-geard.log':
    log     => '/var/log/geard/geard.log',
    options => [
      'compress',
      'copytruncate',
      'missingok',
      'rotate 7',
      'daily',
      'notifempty',
    ],
    require => Service['geard'],
  }
}
