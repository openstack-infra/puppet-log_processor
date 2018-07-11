require 'puppet-openstack_infra_spec_helper/spec_helper_acceptance'

describe 'log_processor', if: os[:family] == 'ubuntu' do

  def pp_path
    base_path = File.dirname(__FILE__)
    File.join(base_path, 'fixtures')
  end

  def puppet_manifest
    manifest_path = File.join(pp_path, 'default.pp')
    File.read(manifest_path)
  end

  def postconditions_puppet_manifest
    manifest_path = File.join(pp_path, 'postconditions.pp')
    File.read(manifest_path)
  end

  it 'should work with no errors' do
    apply_manifest(puppet_manifest, catch_failures: true)
  end

  it 'should be idempotent' do
    apply_manifest(puppet_manifest, catch_changes: true)
  end

  it 'should start' do
    apply_manifest(postconditions_puppet_manifest, catch_failures: true)
  end

  ['jenkins-log-client', 'jenkins-log-worker-A'].each do |service|
    describe service(service) do
      it { should be_running }
    end
  end

end
