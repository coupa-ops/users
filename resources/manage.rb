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

action :create do
  users_groups = {}
  whitelist_groups = data_bag_item(node['coupa-base']['data_bag'], 'whitelist_groups') rescue []

  users_groups[new_resource.group_name] = []
  users = search_users(new_resource.data_bag, "groups:#{new_resource.search_group} AND NOT action:remove")
  users.each do |u|
    u['username'] ||= u['id']
    u['groups'].each do |g|
      users_groups[g] = [] unless users_groups.key?(g)
      users_groups[g] << u['username']
    end

    # Set home to location in data bag,
    # or a reasonable default ($home_basedir/$user).
    home_dir = (u['home'] || "#{home_basedir}/#{u['username']}")

    # check whether home dir is null
    manage_home = !(home_dir == '/dev/null')

    # The user block will fail if the group does not yet exist.
    # See the -g option limitations in man 8 useradd for an explanation.
    # This should correct that without breaking functionality.
    group u['username'] do # ~FC022
      case node['platform_family']
      when 'mac_os_x'
        gid validate_id(u['gid']) unless gid_used?(validate_id(u['gid'])) || new_resource.group_name == u['username']
      else
        gid validate_id(u['gid'])
      end
      only_if { u['gid'] && u['gid'].is_a?(Numeric) }
    end

    is_user_active, is_deployment_match, is_role_match = [ true, true, true ]
    if coupa_pay? && !whitelist_groups['group_list'].include?(new_resource.group_name)
      is_user_active = u['expiration_date'] ? Time.parse(u['expiration_date']) >= Time.now : false
      is_deployment_match = u['match_deployments'] ? u['match_deployments'].include?(node['coupa-base']['deployment']) : true
      is_role_match = u['match_roles'] ? u['match_roles'].include?(node['coupa-base']['role']) : true
    end
    is_action_create = u['action'] ? u['action'].to_s.eql?('create') : true
    custom_action = (is_user_active && is_action_create && is_deployment_match && is_role_match) ? :create : :remove
    customelogger(custom_action, u['username'], u['expiration_date'])

    # Create user object.
    # Do NOT try to manage null home directories.
    user u['username'] do
      uid validate_id(u['uid'])
      gid validate_id(u['gid']) if u['gid']
      shell shell_is_valid?(u['shell']) ? u['shell'] : '/bin/sh'
      comment u['comment']
      password u['password'] if u['password']
      salt u['salt'] if u['salt']
      iterations u['iterations'] if u['iterations']
      manage_home manage_home
      home home_dir
      action custom_action
      not_if { is_user_session_active?(u['username']) && !custom_action.to_s.eql?('create') }
    end

    next unless is_user_active && is_action_create && is_deployment_match && is_role_match

    if manage_home_files?(home_dir, u['username'])
      Chef::Log.debug("Managing home files for #{u['username']}")

      directory "#{home_dir}/.ssh" do
        recursive true
        owner u['uid'] ? validate_id(u['uid']) : u['username']
        group validate_id(u['gid']) if u['gid']
        mode '0700'
        only_if { !!(u['ssh_keys'] || u['ssh_private_key'] || u['ssh_public_key']) }
      end

      # loop over the keys and if we have a URL we should add each key
      # from the url response and append it to the list of keys
      ssh_keys = []
      if u['ssh_keys']
        Array(u['ssh_keys']).each do |key|
          if key.start_with?('https')
            ssh_keys += keys_from_url(key)
          else
            ssh_keys << key
          end
        end
      end

      # use the keyfile defined in the databag or fallback to the standard file in the home dir
      key_file = u['authorized_keys_file'] || "#{home_dir}/.ssh/authorized_keys"

      template key_file do # ~FC022
        source 'authorized_keys.erb'
        cookbook new_resource.cookbook
        owner u['uid'] ? validate_id(u['uid']) : u['username']
        group validate_id(u['gid']) if u['gid']
        mode '0600'
        sensitive true
        # ssh_keys should be a combination of u['ssh_keys'] and any keys
        # returned from a specified URL
        variables ssh_keys: ssh_keys
        only_if { !!(u['ssh_keys']) }
      end

      if u['ssh_private_key']
        key_type = u['ssh_private_key'].include?('BEGIN RSA PRIVATE KEY') ? 'rsa' : 'dsa'
        template "#{home_dir}/.ssh/id_#{key_type}" do
          source 'private_key.erb'
          cookbook new_resource.cookbook
          owner u['uid'] ? validate_id(u['uid']) : u['username']
          group validate_id(u['gid']) if u['gid']
          mode '0400'
          variables private_key: u['ssh_private_key']
        end
      end

      if u['ssh_public_key']
        key_type = u['ssh_public_key'].include?('ssh-rsa') ? 'rsa' : 'dsa'
        template "#{home_dir}/.ssh/id_#{key_type}.pub" do
          source 'public_key.pub.erb'
          cookbook new_resource.cookbook
          owner u['uid'] ? validate_id(u['uid']) : u['username']
          group validate_id(u['gid']) if u['gid']
          mode '0400'
          variables public_key: u['ssh_public_key']
        end
      end
    else
      Chef::Log.debug("Not managing home files for #{u['username']}")
    end
  end
  # Populating users to appropriates groups
  users_groups.each do |g, u|
    group g do
      members u
      append true
      action :manage # Do nothing if group doesn't exist
    end unless g == new_resource.group_name # Dealing with managed group later
  end

  group new_resource.group_name do
    case node['platform_family']
    when 'mac_os_x'
      gid new_resource.group_id unless gid_used?(new_resource.group_id)
    else
      gid new_resource.group_id
    end
    members users_groups[new_resource.group_name]
  end
end

action :remove do
  users = search_users(new_resource.data_bag, "groups:#{new_resource.search_group} AND action:remove")
  users.each do |rm_user|
    user rm_user['username'] ||= rm_user['id'] do
      action :remove
      force rm_user['force'] ||= false
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
      next unless is_user_exists_on_system?(user)
      customelogger('remove', user)
      user "#{user}" do
        action :remove
        not_if { is_user_session_active?(user) }
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

  def search_users(data_bag, query)
    max_retries = Chef::Config[:http_retry_count]
    Chef::Log.debug("Searching for users with query '#{query}' from data bag #{data_bag} and #{max_retries} retry count")
    begin
      search(data_bag, query)
    rescue Net::HTTPServerException => e
      if e.response.code == '400'
        retries ||= 0
        if retries < max_retries
          retries += 1
          Chef::Log.error("Got 400 bad request on '#{data_bag}' search with query '#{query}' - Retrying #{retries}/#{max_retries}")
          retry
        else
          Chef::Log.error("Got 400 bad request on '#{data_bag}' search with query '#{query}' after #{max_retries} retries. Error - #{e.message}")
          raise e
        end
      else
        Chef::Log.error("Got http #{e.response.code} on '#{data_bag}' search with query '#{query}'. Error - #{e.message}")
        raise e
      end
    end  
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

  def is_user_session_active?(username)
    execute_command("who | grep #{username} | awk '{print $1}'").split("\n").count >= 1
  end

  def is_user_exists_on_system?
    execute_command("id #{username}") ? true : false
  end

  def customelogger(action, username, expiration_date = nil)
    is_user_exists = is_user_exists_on_system?(username)
    is_session_active = is_user_session_active?(username)
    require 'logger'
    logger = Logger.new("/var/log/secure-ssh.json")
    logger.formatter = proc do |severity, datetime, progname, msg|
      %Q|{timestamp: "#{datetime.to_s}", message: "#{msg}"}\n|
    end

    if is_user_exists && action.to_s.eql?('remove')
      if is_session_active
        logger.info("User #{username} is having active session but expired at #{expiration_date}.")
        Chef::Log.info("User #{username} is having active session but expired at #{expiration_date}.")
      else
        logger.info("Removing user #{username} from system, which got expired at #{expiration_date}.")
        Chef::Log.info("Removing user #{username} from system, which got expired at #{expiration_date}.")
      end
    elsif !is_user_exists && action.to_s.eql?('create')
      logger.info("Creating user #{username} on system.")
      Chef::Log.info("Creating user #{username} on system.")
    end
  end
end
