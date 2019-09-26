#
# Cookbook:: users
# Resources:: manage
#
# Copyright:: 2011-2017, Eric G. Wolfe
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Data bag user object needs an "action": "remove" tag to actually be removed by the action.
actions :create, :remove, :remove_non_payment_groups

# :data_bag is the object to search
# :search_group is the groups name to search for, defaults to resource name
# :group_name is the string name of the group to create, defaults to resource name
# :group_id is the numeric id of the group to create, default is to allow the OS to pick next
# :cookbook is the name of the cookbook that the authorized_keys template should be found in
property :data_bag, String, default: 'users'
property :search_group, String, name_property: true
property :group_name, String, name_property: true
property :group_id, Integer
property :cookbook, String, default: 'users'
property :manage_nfs_home_dirs, [true, false], default: true

def initialize(*args)
  super
  @action = :create
end

use_inline_resources if defined?(use_inline_resources)

def whyrun_supported?
  true
end

def chef_solo_search_installed?
  klass = ::Search::const_get('Helper')
  return klass.is_a?(Class)
rescue NameError
  return false
end

def coupa_pay?
  node['coupa-base']['deployment'].match(/pay/) ? true : false
end

def execute_command(cmd = nil)
  require 'open3'
  out, st = Open3.capture2e(cmd)
  if st.success?
    out
  else
    false
  end
end

def customelogger(is_user_exists_on_system, is_user_session_active, custom_action, username, expiration_date = nil)
  require 'logger'
  logger = Logger.new("/var/log/secure-ssh.json")
  logger.formatter = proc do |severity, datetime, progname, msg|
    %Q|{timestamp: "#{datetime.to_s}", message: "#{msg}"}\n|
  end

  if is_user_exists_on_system && custom_action.to_s.eql?('remove')
    if is_user_session_active
      logger.info("User #{username} is having active session but expired at #{expiration_date}.")
      Chef::Log.info("User #{username} is having active session but expired at #{expiration_date}.")
    else
      logger.info("Removing user #{username} from system, which got expired at #{expiration_date}.")
      Chef::Log.info("Removing user #{username} from system, which got expired at #{expiration_date}.")
    end
  elsif !is_user_exists_on_system && custom_action.to_s.eql?('create')
    logger.info("Creating user #{username} on system.")
    Chef::Log.info("Creating user #{username} on system.")
  end
end

action :create do
  security_group = Array.new
  whitelist_groups = data_bag_item(node['coupa-base']['data_bag'], 'whitelist_groups') rescue []

  if Chef::Config[:solo] and not chef_solo_search_installed?
    Chef::Log.warn("This recipe uses search. Chef Solo does not support search unless you install the chef-solo-search cookbook.")
  else
    search(new_resource.data_bag, "groups:#{new_resource.search_group} AND NOT action:remove") do |u|
      u['username'] ||= u['id']

      if node['apache'] and node['apache']['allowed_openids']
        Array(u['openid']).compact.each do |oid|
          node.default['apache']['allowed_openids'] << oid unless node['apache']['allowed_openids'].include?(oid)
        end
      end

      # Set home_basedir based on platform_family
      case node['platform_family']
      when 'mac_os_x'
          home_basedir = '/Users'
      when 'debian', 'rhel', 'fedora', 'arch', 'suse', 'freebsd'
          home_basedir = '/home'
      end

      # Set home to location in data bag,
      # or a reasonable default ($home_basedir/$user).
      if u['home']
        home_dir = u['home']
      else
        home_dir = "#{home_basedir}/#{u['username']}"
      end

      is_user_active, is_deployment_match, is_role_match = [ true, true, true ]
      if coupa_pay? && !whitelist_groups['group_list'].include?(new_resource.group_name)
        # calculate action for group and user resources
        is_user_active = u['expiration_date'] ? Time.parse(u['expiration_date']) >= Time.now : false

        # checking for deployment matcher for specific user
        is_deployment_match = u['match_deployments'] ? u['match_deployments'].include?(node['coupa-base']['deployment']) : true

        # checking for role matcher for specific user
        is_role_match = u['match_roles'] ? u['match_roles'].include?(node['coupa-base']['role']) : true
      end

      is_action_create = u['action'] ? u['action'].to_s.eql?('create') : true

      custom_action = (is_user_active && is_action_create && is_deployment_match && is_role_match) ? :create : :remove

      # The user block will fail if the group does not yet exist.
      # See the -g option limitations in man 8 useradd for an explanation.
      # This should correct that without breaking functionality.
      if u['gid'] and u['gid'].kind_of?(Numeric)
        group u['username'] do
          gid u['gid']
        end
      end

      # checking if user session is active
      is_user_session_active = execute_command("who | grep #{u['username']} | awk '{print $1}'").split("\n").count >= 1
      is_user_exists_on_system = execute_command("id #{u['username']}") ? true : false

      customelogger(is_user_exists_on_system, is_user_session_active, custom_action, u['username'], u['expiration_date'])

      user u['username'] do
        uid u['uid']
        if u['gid']
          gid u['gid']
        end
        shell u['shell']
        comment u['comment']
        password u['password'] if u['password']
        if home_dir == "/dev/null"
          supports :manage_home => false
        else
          supports :manage_home => true
        end
        home home_dir
        action custom_action
        not_if { is_user_session_active && !custom_action.to_s.eql?('create') }
      end

      next unless is_user_active && is_action_create && is_deployment_match && is_role_match
      security_group << u['username'] if u['groups'].include?(new_resource.group_name)

    	if home_dir != "/dev/null"
    	  converge_by("would create #{home_dir}/.ssh") do
      	    directory "#{home_dir}/.ssh" do
      	      owner u['username']
      	      group u['gid'] || u['username']
      	      mode "0700"
      	  end
      	end

        if u['ssh_keys']
          template "#{home_dir}/.ssh/authorized_keys" do
            source "authorized_keys.erb"
            cookbook new_resource.cookbook
            owner u['username']
            group u['gid'] || u['username']
            mode "0600"
            variables :ssh_keys => u['ssh_keys']
          end
        end

        if u['ssh_private_key']
          key_type = u['ssh_private_key'].include?("BEGIN RSA PRIVATE KEY") ? "rsa" : "dsa"
          template "#{home_dir}/.ssh/id_#{key_type}" do
            source "private_key.erb"
            cookbook new_resource.cookbook
            owner u['id']
            group u['gid'] || u['id']
            mode "0400"
            variables :private_key => u['ssh_private_key']
          end
        end

        if u['ssh_public_key']
          key_type = u['ssh_public_key'].include?("ssh-rsa") ? "rsa" : "dsa"
          template "#{home_dir}/.ssh/id_#{key_type}.pub" do
            source "public_key.pub.erb"
            cookbook new_resource.cookbook
            owner u['id']
            group u['gid'] || u['id']
            mode "0400"
            variables :public_key => u['ssh_public_key']
          end
        end
      end
    end
  end

  group new_resource.group_name do
    if new_resource.group_id
      gid new_resource.group_id
    end
    members security_group
  end

end

action :remove do
  if Chef::Config[:solo] and not chef_solo_search_installed?
    Chef::Log.warn("This recipe uses search. Chef Solo does not support search unless you install the chef-solo-search cookbook.")
  else
    search(new_resource.data_bag, "groups:#{new_resource.search_group} AND action:remove") do |rm_user|
      user rm_user['username'] ||= rm_user['id'] do
        action :remove
      end
    end
  end
end

action :remove_non_payment_groups do
  valid_users = []
  available_users = data_bag('users')
  data_bag('groups').each do |group|
    (valid_users << search(new_resource.data_bag, "groups:#{group} AND NOT action:remove").map {|u| u['id']}).flatten!
  end
  invalid_users = (available_users - valid_users.uniq)
  unless invalid_users.empty?
    invalid_users.each { |user|
      is_user_exists_on_system = execute_command("id #{user}") ? true : false
      next unless is_user_exists_on_system
      is_user_session_active = execute_command("who | grep #{user} | awk '{print $1}'").split("\n").count >= 1
      customelogger(true, is_user_session_active, 'remove', user)
      user "#{user}" do
        action :remove
        not_if { is_user_session_active }
      end
    }
  else
    Chef::Log.info("No invalid users found on the system")
  end
end

action_class do
  include ::Users::Helpers
  include ::Users::OsxHelper

  def manage_home_files?(home_dir, _user)
    # Don't manage home dir if it's NFS mount
    # and manage_nfs_home_dirs is disabled
    if home_dir == '/dev/null'
      false
    elsif fs_remote?(home_dir)
      new_resource.manage_nfs_home_dirs ? true : false
    else
      true
    end
  end
end
