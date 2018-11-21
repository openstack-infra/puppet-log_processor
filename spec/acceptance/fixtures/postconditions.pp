service { 'jenkins-log-client':
  ensure => running,
}

service { 'jenkins-log-worker-A':
  ensure => running,
}
