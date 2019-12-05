import os
import logging
import time
import uuid
import socket
import argparse

import yaml
import openstack
from fabric.api import settings, run, get, put
from fabric.contrib.files import exists

from cloudify_rest_client.client import CloudifyClient

EXECUTION_POLL_INTERVAL_SECONDS = 20
THIS_DIRECTORY = os.path.dirname(os.path.abspath(__file__))


def _parse_command():
    parser = argparse.ArgumentParser(description='Cloudify Upgrade')
    parser.add_argument('--config-path', dest='config_path',
                        action='store', type=str,
                        required=True, help='Configuration file')
    return parser.parse_args()


def wait_for_ssh(server_ip):
    s = socket.socket()
    address = server_ip
    port = 22
    while True:
        time.sleep(5)
        try:
            s.connect((address, port))
            return
        except Exception as e:
            pass


def prepare_ca_certificate(config):
    if config['cloudify_config']['ca_cert']:
        return
    else:
        os.system('bash scripts/generateCA.sh')
        config['cloudify_config']['ca_cert'] = 'ca_crt.pem'
        config['cloudify_config']['ca_key'] = 'ca_key.pem'


def prepare_host_certificate(ca_cert, ca_key, server_name, server_ip):
    os.system('bash scripts/generateConfFile.sh %s %s' % (server_name,
                                                          server_ip))
    os.system('bash scripts/generateCertificateForHost.sh %s %s %s' % (
        server_name, ca_cert, ca_key))
    return '{}_crt.pem'.format(server_name), \
           '{}_key.pem'.format(server_name)


def get_host_ssh_conf(server_instance, config, server_name):
    network_name = config['server']['network_name']
    server = dict()
    server['ip'] = str(server_instance.addresses[network_name][0]['addr'])
    server['key'] = config['server']['key']
    server['ssh_user'] = config['server']['ssh_user']
    server['name'] = server_name
    server['domain'] = config['server']['dns_domain']
    return server


def get_fabric_settings(host):
    return settings(
        connection_attempts=5,
        disable_known_hosts=True,
        warn_only=True,
        host_string=host['ip'],
        key_filename=os.path.abspath(host['key']),
        user=host['ssh_user'])


def create_openstack_connection(openstack_config):
    return openstack.connect(
        auth_url=openstack_config['auth_url'],
        project_name=openstack_config['project_name'],
        username=openstack_config['username'],
        password=openstack_config['password'],
        region_name=openstack_config['region'],
        user_domain_name='Default',
        project_domain_name='Default'
    )


def create_openstack_server(openstack_connection, server_config, server_name,
                            logger):
    image = openstack_connection.compute.find_image(server_config
                                                    ['image_name'])
    flavor = openstack_connection.compute.find_flavor(server_config
                                                      ['flavor_name'])
    security_group = server_config['security_group']
    network = openstack_connection.network.find_network(
        server_config['network_name'])
    keypair_name = server_config['keypair_name']
    server = openstack_connection.compute.create_server(
        image_id=image.id,
        flavor_id=flavor.id,
        security_groups=[{'name': security_group}],
        networks=[{'uuid': network.id}],
        key_name=keypair_name,
        name=server_name)

    while True:
        logger.info("Waiting for server creation to finish...")
        server = openstack_connection.compute.find_server(server.id,
                                                          ignore_missing=False)
        if server.status == 'ACTIVE':
            break
        elif server.status == 'ERROR':
            raise Exception('Failed creating server')
        else:
            logger.info("Current status: %s, will try again...",
                        server.status)
            time.sleep(2)
    return server


def download_cloudify_rpm(server, rpm_url, logger):
    #logger.info("Downloading RPM from %s", rpm_url)
    logger.info("Copying RPM from Local")
    with get_fabric_settings(server):
        put('cloudify-manager-install.rpm', 'cloudify-manager-install.rpm')
        #run('curl -o cloudify-manager-install.rpm %s' % rpm_url)


def download_cloudify_rpm_locally(rpm_url, logger):
    logger.info("Downloading RPM from %s to local machine", rpm_url)
    os.system('curl %s -o cloudify-manager-install.rpm -C -' % rpm_url)


def install_rpm(server, logger):
    logger.info("Installing new Cloudify Manager RPM")
    with get_fabric_settings(server):
        run('sudo yum -y install cloudify-manager-install.rpm')


def update_config(server, install_config, updated_config, logger):
    # Download config.yaml.
    logger.info("Retrieving default config.yaml file into %s", updated_config)
    with get_fabric_settings(server):
        with open(updated_config, 'w') as config_yaml:
            get('/etc/cloudify/config.yaml', config_yaml)

    with open(updated_config, 'r') as f:
        manager_config = yaml.full_load(f)

    # Now update the config dictionary, preserving all non-modified values.
    def _update(original, updates):
        for k, v in updates.iteritems():
            if isinstance(v, dict):
                if k == 'cluster_members':  # special cases since we add keys
                    original[k] = v
                elif k == 'cluster':
                    original[k] = v
                elif k == 'networks':
                    original[k] = v
                else:
                    _update(original[k], v)
            else:
                original[k] = v

    logger.info("Updating config.yaml file")
    _update(manager_config, install_config)
    with open(updated_config, 'w+t') as f:
        yaml.dump(manager_config, f)

    with get_fabric_settings(server):
        logger.info("Uploading %s into temporary file", updated_config)
        put(updated_config, '/tmp/config.yaml')
        logger.info("Moving temporary file into /etc/cloudify/config.yaml")
        run('sudo mv /tmp/config.yaml /etc/cloudify/config.yaml')


def upload_license(server, config, logger):
    with get_fabric_settings(server):
        logger.info("Uploading license file")
        put(os.path.join(THIS_DIRECTORY, 'resources', 'license.yaml'),
            '/tmp/license.yaml')
        logger.info("Activating license")
        run('cfy license upload /tmp/license.yaml')


def prepare_database_install_config(server, config, db_servers, logger):

    ca_cert = config['cloudify_config']['ca_cert']
    db_pass = config['cloudify_config']['db_pass']
    server_home_path = '/home/{}/'.format(server['ssh_user'])

    host_cert, host_key = config['cloudify_config']['external_cert'], \
                          config['cloudify_config']['external_key']
    # prepare_host_certificate(ca_cert, config['cloudify_config']['ca_key'],
    # server['name'], server['ip'])

    with get_fabric_settings(server):
        logger.info("Uploading Certs")
        run('mkdir {}/.certs'.format(server_home_path))
        put(host_cert, '{}/.certs/postgres_crt.pem'.format(server_home_path))
        put(host_key, '{}/.certs/postgres_key.pem'.format(server_home_path))
        put(ca_cert, '{}/.certs/postgres_ca.pem'.format(server_home_path))

    install_config = dict()

    install_config['manager'] = dict()
    install_config['manager']['cli_local_profile_host_name'] = \
        'local{}'.format(config['server']['dns_domain'])

    install_config['postgresql_server'] = dict()
    install_config['postgresql_server']['enable_remote_connections'] = True
    install_config['postgresql_server']['ssl_enabled'] = True
    install_config['postgresql_server']['ssl_client_verification'] = False
    install_config['postgresql_server']['ssl_only_connections'] = False
    install_config['postgresql_server']['postgres_password'] = db_pass

    install_config['postgresql_server']['cluster'] = dict()
    install_config['postgresql_server']['cluster']['nodes'] = dict()
    for k in sorted(db_servers.keys()):
        install_config['postgresql_server']['cluster']['nodes'][k] = dict()
        install_config['postgresql_server']['cluster']['nodes'][k]['ip'] = \
            k + config['server']['dns_domain']
    install_config['postgresql_server']['cluster']['etcd'] = dict()
    install_config['postgresql_server']['cluster']['etcd']['cluster_token'] = \
        db_pass
    install_config['postgresql_server']['cluster']['etcd']['root_password'] = \
        db_pass
    install_config['postgresql_server']['cluster']['etcd']['patroni_password']\
        = db_pass

    install_config['postgresql_server']['cluster']['patroni'] = dict()
    install_config['postgresql_server']['cluster']['patroni']['rest_password']\
        = db_pass

    install_config['postgresql_server']['cluster']['postgres'] = dict()
    install_config['postgresql_server']['cluster']['postgres'][
        'replicator_password'] = db_pass

    install_config['postgresql_server']['cert_path'] = \
        '{}/.certs/postgres_crt.pem'.format(server_home_path)
    install_config['postgresql_server']['key_path'] = \
        '{}/.certs/postgres_key.pem'.format(server_home_path)
    install_config['postgresql_server']['ca_path'] = \
        '{}/.certs/postgres_ca.pem'.format(server_home_path)
    install_config['ssl_inputs'] = dict()

    install_config['ssl_inputs']['external_ca_cert_path'] = \
        '{}/.certs/postgres_ca.pem'.format(server_home_path)
    install_config['ssl_inputs']['internal_cert_path'] = \
        '{}/.certs/postgres_crt.pem'.format(server_home_path)
    install_config['ssl_inputs']['internal_key_path'] = \
        '{}/.certs/postgres_key.pem'.format(server_home_path)

    install_config['services_to_install'] = ['database_service']

    return install_config


def prepare_rabbitmq_install_config(server, config, rabbit_servers,
                                    first_host, erlang_cookie, logger):

    ca_cert = config['cloudify_config']['ca_cert']
    server_home_path = '/home/{}/'.format(server['ssh_user'])

    host_cert, host_key = config['cloudify_config']['external_cert'], \
                          config['cloudify_config']['external_key']
    # prepare_host_certificate(ca_cert, config['cloudify_config']['ca_key'],
    # server['name'], server['ip'])

    with get_fabric_settings(server):
        logger.info("Uploading Certs")
        run('mkdir {}/.certs'.format(server_home_path))
        put(host_cert, '{}/.certs/rabbitmq_crt.pem'.format(server_home_path))
        put(host_key, '{}/.certs/rabbitmq_key.pem'.format(server_home_path))
        put(ca_cert, '{}/.certs/rabbitmq_ca.pem'.format(server_home_path))

    install_config = dict()

    install_config['manager'] = dict()
    install_config['manager']['cli_local_profile_host_name'] = \
        'local{}'.format(config['server']['dns_domain'])

    install_config['rabbitmq'] = dict()
    install_config['rabbitmq']['cert_path'] = \
        '{}/.certs/rabbitmq_crt.pem'.format(server_home_path)
    install_config['rabbitmq']['key_path'] = \
        '{}/.certs/rabbitmq_key.pem'.format(server_home_path)
    install_config['rabbitmq']['ca_path'] = \
        '{}/.certs/rabbitmq_ca.pem'.format(server_home_path)
    install_config['rabbitmq']['nodename'] = server['name']
    install_config['rabbitmq']['erlang_cookie'] = erlang_cookie

    install_config['rabbitmq']['cluster_members'] = dict()
    for k in sorted(rabbit_servers.keys()):
        install_config['rabbitmq']['cluster_members'][k] = dict()
        install_config['rabbitmq']['cluster_members'][k]['networks'] = dict()
        install_config['rabbitmq']['cluster_members'][k]['networks'][
            'default'] = k + config['server']['dns_domain']

    if not first_host:
        install_config['rabbitmq']['join_cluster'] = \
            sorted(rabbit_servers.keys())[0]

    install_config['networks'] = dict()
    install_config['networks']['default'] = \
        'proxy{}'.format(config['server']['dns_domain'])

    install_config['services_to_install'] = ['queue_service']

    return install_config


def get_node_id(server_ip, config, logger):
    node_id = None
    server = dict()
    server['ip'] = server_ip
    server['key'] = config['server']['key']
    server['ssh_user'] = config['server']['ssh_user']
    with get_fabric_settings(server):
        logger.info('get node id for node')
        output = run('cfy_manager node get-id')
        for line in output.splitlines():
            if line.startswith("The node id is:"):
                node_id = line.split(":")[-1].strip()
                break
    return node_id


def prepare_manager_install_config(server, config, db_servers, db_pass,
                                   rabbit_servers, first, logger):

    ca_cert = config['cloudify_config']['ca_cert']
    server_home_path = '/home/{}/'.format(server['ssh_user'])

    host_cert, host_key = config['cloudify_config']['external_cert'], \
                          config['cloudify_config']['external_key']
    # prepare_host_certificate(ca_cert, config['cloudify_config']['ca_key'],
    # server['name'], server['ip'])

    with get_fabric_settings(server):
        logger.info("Uploading Certs")
        run('mkdir {}/.certs'.format(server_home_path))
        put(host_cert, '{}/.certs/manager_crt.pem'.format(server_home_path))
        put(host_key, '{}/.certs/manager_key.pem'.format(server_home_path))
        put(ca_cert, '{}/.certs/manager_ca.pem'.format(server_home_path))

    cfy4_config = None
    with open('resources/cfy4_config.yaml', 'r') as f:
        cfy4_config = yaml.full_load(f)

    install_config = dict()
    install_config['manager'] = dict()
    install_config['manager']['security'] = dict()
    install_config['manager']['security']['admin_password'] = 'admin'
    install_config['manager']['security']['ssl_enabled'] = True
    install_config['manager']['cli_local_profile_host_name'] = \
        'local{}'.format(config['server']['dns_domain'])

    install_config['rabbitmq'] = dict()
    install_config['rabbitmq']['ca_path'] = \
        '{}/.certs/manager_ca.pem'.format(server_home_path)

    install_config['rabbitmq']['cluster_members'] = dict()

    install_config['rabbitmq']['cluster_members'] = dict()
    for k in sorted(rabbit_servers.keys()):
        install_config['rabbitmq']['cluster_members'][k] = dict()
        install_config['rabbitmq']['cluster_members'][k]['networks'] = dict()
        install_config['rabbitmq']['cluster_members'][k]['networks'][
            'default'] = 'proxy{}'.format(config['server'][
                                                               'dns_domain'])
        install_config['rabbitmq']['cluster_members'][k]['node_id'] = \
            get_node_id(rabbit_servers[k], config, logging)

    install_config['postgresql_server'] = dict()
    install_config['postgresql_server']['ssl_enabled'] = True
    install_config['postgresql_server']['ca_path'] = \
        '{}/.certs/manager_ca.pem'.format(server_home_path)
    install_config['postgresql_server']['postgres_password'] = db_pass

    install_config['postgresql_server']['cluster'] = dict()
    install_config['postgresql_server']['cluster']['nodes'] = dict()
    for k in sorted(db_servers.keys()):
        install_config['postgresql_server']['cluster']['nodes'][k] = dict()
        install_config['postgresql_server']['cluster']['nodes'][k]['ip'] = \
            k + config['server']['dns_domain']
        if first:
            install_config['postgresql_server']['cluster']['nodes'][k][
                'node_id'] = get_node_id(db_servers[k], config, logging)

    install_config['postgresql_client'] = dict()
    install_config['postgresql_client']['ssl_enabled'] = True
    install_config['postgresql_client']['ssl_client_verification'] = False
    install_config['postgresql_client']['server_password'] = db_pass
    install_config['postgresql_client']['ca_path'] = \
        '{}/.certs/manager_ca.pem'.format(server_home_path)
    install_config['postgresql_client']['host'] = \
        'local{}'.format(config['server']['dns_domain'])

    install_config['networks'] = dict()
    install_config['networks']['default'] = \
        'manager-proxy{}'.format(config['server']['dns_domain'])

    install_config['ssl_inputs'] = dict()
    install_config['ssl_inputs']['ca_cert_path'] = \
        '{}/.certs/manager_ca.pem'.format(server_home_path)
    install_config['ssl_inputs']['external_ca_cert_path'] = \
        '{}/.certs/manager_ca.pem'.format(server_home_path)
    install_config['ssl_inputs']['external_cert_path'] = \
        '{}/.certs/manager_crt.pem'.format(server_home_path)
    install_config['ssl_inputs']['external_key_path'] = \
        '{}/.certs/manager_key.pem'.format(server_home_path)
    install_config['ssl_inputs']['internal_cert_path'] = \
        '{}/.certs/manager_crt.pem'.format(server_home_path)
    install_config['ssl_inputs']['internal_key_path'] = \
        '{}/.certs/manager_key.pem'.format(server_home_path)
    install_config['ssl_inputs']['internal_manager_host'] = \
        'local{}'.format(config['server']['dns_domain'])

    install_config['restservice'] = dict()
    install_config['restservice']['ldap'] = dict()
    install_config['restservice']['ldap']['server'] = \
        cfy4_config['restservice']['ldap']['server']
    install_config['restservice']['ldap']['username'] = \
        cfy4_config['restservice']['ldap']['username']
    install_config['restservice']['ldap']['password'] = \
        cfy4_config['restservice']['ldap']['password']
    install_config['restservice']['ldap']['domain'] = \
        cfy4_config['restservice']['ldap']['domain']
    install_config['restservice']['ldap']['is_active_directory'] = \
        cfy4_config['restservice']['ldap']['is_active_directory']

    install_config['provider_context'] = dict()
    install_config['provider_context']['import_resolver'] = dict()
    install_config['provider_context']['import_resolver']['parameters'] = \
        dict()
    install_config['provider_context']['import_resolver']['parameters'][
        'fallback'] = False

    install_config['services_to_install'] = ['manager_service']

    return install_config


def install_manager(server, logger):
    logger.info("Installing Cloudify Manager")
    with get_fabric_settings(server):
        run('cfy_manager install --private-ip %s --public-ip %s'
            % (server['name'] + server['domain'],
               server['name'] + server['domain']))


def upload_resources(server, config, logger):
    already_created = []
    for resource_desc in config['cloudify_config']['resources']:
        source, target = resource_desc['source'], resource_desc['target']
        target_abspath = '/opt/manager/resources/%s' % target
        target_relative_dirname, target_filename = os.path.split(target)
        target_path_parts = target_relative_dirname.split(os.sep)

        with get_fabric_settings(server):
            for i in range(len(target_path_parts)):
                curr_subdir = os.path.join('/opt/manager/resources',
                                           *target_path_parts[0:i+1])
                if curr_subdir not in already_created:
                    run('sudo mkdir -p %s' % curr_subdir)
                    run('sudo chown cfyuser:cfyuser %s' % curr_subdir)
                    run('sudo chmod -R 755 %s' % curr_subdir)
                    already_created.append(curr_subdir)
            logger.info("Downloading: %s -> %s", source, target_abspath)
            run('sudo curl -o %s %s' % (target_abspath, source))
            run('sudo chown cfyuser:cfyuser %s' % target_abspath)


def create_cluster_hosts(openstack_connection, config, logger):
    server_name = config['server']['db_server_name']

    db_servers = dict()
    db_servers[server_name + '1'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '1' , logger)
    db_servers[server_name + '2'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '2', logger)
    db_servers[server_name + '3'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '3', logger)

    server_name = config['server']['rabbit_server_name']
    rabbit_servers = dict()
    rabbit_servers[server_name + '1'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '1', logger)
    rabbit_servers[server_name + '2'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '2', logger)
    rabbit_servers[server_name + '3'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '3', logger)

    server_name = config['server']['manager_server_name']
    manager_servers = dict()
    manager_servers[server_name + '1'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '1', logger)
    manager_servers[server_name + '2'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '2', logger)
    manager_servers[server_name + '3'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '3', logger)

    return db_servers, rabbit_servers, manager_servers


def configure_database_servers(db_servers, config, logger):

    cluster_members = dict()

    for k in sorted(db_servers.keys()):
        server = get_host_ssh_conf(db_servers[k], config, k)
        install_rpm(server, logger)
        install_config = prepare_database_install_config(server,
                                                         config,
                                                         db_servers,
                                                         logger)
        update_config(server, install_config, 'resources/{}.yaml'.format(k),
                      logger)
        install_manager(server, logger)
        cluster_members[k] = server['ip']

    return cluster_members, config['cloudify_config']['db_pass']


def configure_rabbitmq_servers(rabbit_servers, config, logger):

    cluster_members = dict()

    erlang_cookie = str(uuid.uuid4())

    first = True

    for k in sorted(rabbit_servers.keys()):
        server = get_host_ssh_conf(rabbit_servers[k], config, k)
        install_rpm(server, logger)
        install_config = prepare_rabbitmq_install_config(server,
                                                         config,
                                                         rabbit_servers,
                                                         first,
                                                         erlang_cookie,
                                                         logger)
        first = False
        update_config(server, install_config, 'resources/{}.yaml'.format(k),
                      logger)
        install_manager(server, logger)
        cluster_members[k] = server['ip']

    return cluster_members


def configure_cloudify_managers(db_servers, db_pass, rabbitmq_servers,
                                manager_servers, config,  logger):

    cluster_memebers = dict()

    first = True
    for k in sorted(manager_servers.keys()):
        server = get_host_ssh_conf(manager_servers[k], config, k)
        install_rpm(server, logger)
        install_config = prepare_manager_install_config(server,
                                                        config,
                                                        db_servers, db_pass,
                                                        rabbitmq_servers,
                                                        first, logger)
        update_config(server, install_config, 'resources/{}.yaml'.format(k),
                      logger)
        install_manager(server, logger)
        if first:
            upload_license(server, config, logger)
            first = False
        upload_resources(server, config, logger)
        cluster_memebers[k] = server['ip']

    return cluster_memebers


def get_cfy_manager4_active(config):
    for i in config['cloudify_config']['cfy4_ips']:
        try:
            rest_client = CloudifyClient(
                host=i,
                **config['cloudify_config']['rest_client']
            )
            if rest_client.cluster.nodes.list():
                return i
        except:
            pass


def wait_for_terminated_status(client, execution, logger,
                               tolerate_polling_errors=False):
    execution_id = execution.id
    while True:
        try:
            execution = client.executions.get(execution_id)
        except Exception as ex:
            if tolerate_polling_errors:
                logger.warning("Exception encountered waiting for execution "
                               "to finish: %s", str(ex))
                time.sleep(EXECUTION_POLL_INTERVAL_SECONDS)
                continue
            raise

        status = execution['status']
        if status == 'terminated':
            logger.info("Execution ID '%s' ended OK" % execution_id)
            return
        if status == 'pending':
            logger.info("Execution ID '%s' is pending..." % execution_id)
        elif status == 'started':
            logger.info("Execution ID '%s' is running..." % execution_id)
        else:
            raise Exception("Execution '{}' is in an unexpected status: {}".
                            format(execution.id, status))
        time.sleep(EXECUTION_POLL_INTERVAL_SECONDS)


def create_snapshot(config, active_manager, snapshot_id, logger):
    client = CloudifyClient(
        host=active_manager,
        **config['cloudify_config']['rest_client']
    )
    execution = client.snapshots.create(
        snapshot_id,
        include_metrics=False,
        include_credentials=True,
        # include_logs=True,
        # include_events=True
    )
    wait_for_terminated_status(client, execution, logger)


def get_snapshot(config, active_manager, snapshot_id, logger):
    server = dict()
    server['ip'] = active_manager
    server['key'] = config['server']['key']
    server['ssh_user'] = config['server']['ssh_user']
    snapshot_path = '/home/{}/snapshot-4.zip'.format(server['ssh_user'])
    with get_fabric_settings(server):
        logger.info('get snapshot from cloudify 4 active manager')
        run('cfy snapshots download %s -o %s' % (snapshot_id, snapshot_path))
        get(snapshot_path, 'snapshot-4.zip')


def get_cfy4_config(config, active_manager, logger):
    server = dict()
    server['ip'] = active_manager
    server['key'] = config['server']['key']
    server['ssh_user'] = config['server']['ssh_user']
    with get_fabric_settings(server):
        logger.info('get cloudify 4 config file')
        get('/etc/cloudify/config.yaml', 'resources/cfy4_config.yaml')


def get_cfy4_ssh_files(config, active_manager, logger):
    os.system('mkdir resources/.ssh')
    server = dict()
    server['ip'] = active_manager
    server['key'] = config['server']['key']
    server['ssh_user'] = config['server']['ssh_user']
    with get_fabric_settings(server):
        logger.info('get cloudify 4 ssh files')
        if exists('/etc/cloudify/.ssh'):
            get('/etc/cloudify/.ssh/*', 'resources/.ssh/', use_sudo=True)


def put_cfy4_ssh_files_to_cfy5(config, cfy_5_managers, logger):
    for manager in cfy_5_managers.values():
        server = dict()
        server['ip'] = manager
        server['key'] = config['server']['key']
        server['ssh_user'] = config['server']['ssh_user']
        with get_fabric_settings(server):
            logger.info("Uploading ssh files to temporary ")
            run('mkdir /tmp/.ssh')
            put('resources/.ssh/*', '/tmp/.ssh/', use_sudo=True)
            logger.info("Moving temporary files into /etc/cloudify/.ssh")
            run('sudo mv /tmp/.ssh /etc/cloudify/.ssh')
            run('sudo chown -R cfyuser:cfyuser /etc/cloudify/.ssh')
            run('sudo chmod 755 /etc/cloudify/.ssh')
            run('sudo chmod 600 /etc/cloudify/.ssh/*')


def upload_snapshot(config, active_manager, snapshot_id, logger):
    server = dict()
    server['ip'] = active_manager
    server['key'] = config['server']['key']
    server['ssh_user'] = config['server']['ssh_user']
    with get_fabric_settings(server):
        logger.info('put snapshot to cloudify 5 active manager')
        put('snapshot-4.zip', '/tmp/snapshot-4.zip')
        run('cfy snapshots upload %s -s %s' % ('/tmp/snapshot-4.zip',
                                               snapshot_id))


def restore_snapshot(config, active_manager, snapshot_id, logger, f=False):
    server = dict()
    server['ip'] = active_manager
    server['key'] = config['server']['key']
    server['ssh_user'] = config['server']['ssh_user']
    with get_fabric_settings(server):
        logger.info('restore snapshot')
        run("sudo sed -i 's/{0} manager-proxy{1}/{2} manager-proxy{1}/g'  "
            "/etc/hosts ".format(config['cloudify_config']['ha_proxy'],
                                 config['server']['dns_domain'],
                                 active_manager))
        output = ''
        if f:
            output = run('cfy snapshots restore %s --force ' % snapshot_id)
        else:
            output = run('cfy snapshots restore %s ' % snapshot_id)
        execution_id = ''
        for line in output.splitlines():
            if line.startswith("Started workflow execution"):
                execution_id = line.split(".")[1].split()[-1]
                break
        failed = False
        if execution_id:
            wait = True
            while wait:
                try:
                    output = run('cfy executions get %s ' % execution_id)
                    for line in output.splitlines():
                        if len(line.split()) > 1 and line.split()[1] == \
                                execution_id:
                            if line.split("|")[3].strip() == 'completed':
                                wait = False
                            elif line.split("|")[3].strip() == 'failed':
                                failed = True
                                wait = False
                    time.sleep(EXECUTION_POLL_INTERVAL_SECONDS)
                except Exception as e:
                    if str(e).find('Internal error') > -1 or \
                            str(e).find('No active license') > -1:
                        time.sleep(EXECUTION_POLL_INTERVAL_SECONDS)
            run("sudo sed -i 's/{0} manager-proxy{1}/{2} manager-proxy{1}/g'  "
                "/etc/hosts ".format(active_manager,
                                     config['server']['dns_domain'],
                                     config['cloudify_config']['ha_proxy']))
        else:
            failed = True

        if failed:
            restore_snapshot(config, active_manager, snapshot_id, logger, True)


def install_all_agents(config, active_manager, logger):
    server = dict()
    server['ip'] = active_manager
    server['key'] = config['server']['key']
    server['ssh_user'] = config['server']['ssh_user']
    with get_fabric_settings(server):
        logger.info('reinstalling agents')
        run('cfy agents install --all-tenants')


def validate_agents(config, active_manager, logger):
    server = dict()
    server['ip'] = active_manager
    server['key'] = config['server']['key']
    server['ssh_user'] = config['server']['ssh_user']
    with get_fabric_settings(server):
        logger.info('validate agents')
        run('cfy agents validate --all-tenants')


def add_to_hosts_servers(servers_list, db_servers, rabbit_servers,
                         manager_servers, config, logger):
    for k in sorted(servers_list.keys()):
        server = get_host_ssh_conf(servers_list[k], config, k)
        with get_fabric_settings(server):
            logger.info("Adding hosts to /etc/hosts on {}".format(k))
            run("sudo bash -c 'echo {0} {1} >> /etc/hosts'".
                format('127.0.0.1', 'local' + config['server']['dns_domain']))
            run("sudo bash -c 'echo {0} {1} >> /etc/hosts'".
                format(config['cloudify_config']['ha_proxy'],
                       'proxy' + config['server']['dns_domain']))
            run("sudo bash -c 'echo {0} {1} >> /etc/hosts'".
                format(config['cloudify_config']['ha_proxy'],
                       'manager-proxy' + config['server']['dns_domain']))
            for key in sorted(db_servers.keys()):
                run("sudo bash -c 'echo {0} {1} >> /etc/hosts'".
                    format(db_servers[key], key))
            for key in sorted(rabbit_servers.keys()):
                run("sudo bash -c 'echo {0} {1} >> /etc/hosts'".
                    format(rabbit_servers[key], key))
            for key in sorted(manager_servers.keys()):
                run("sudo bash -c 'echo {0} {1} >> /etc/hosts'".
                    format(manager_servers[key], key))


def add_hosts_to_haproxy(db_servers, rabbit_servers, manager_servers, config,
                         logger):
    server = dict()
    server['ip'] = config['cloudify_config']['ha_proxy']
    server['key'] = config['server']['key']
    server['ssh_user'] = config['server']['ssh_user']

    with get_fabric_settings(server):
        logger.info("Adding hosts to /etc/hosts on ha_proxy")
        for key in sorted(db_servers.keys()):
            run("sudo bash -c 'echo {0} {1} >> /etc/hosts'".
                format(db_servers[key], key))
        for key in sorted(rabbit_servers.keys()):
            run("sudo bash -c 'echo {0} {1} >> /etc/hosts'".
                format(rabbit_servers[key], key))
        for key in sorted(manager_servers.keys()):
            run("sudo bash -c 'echo {0} {1} >> /etc/hosts'".
                format(manager_servers[key], key))


def extract_values_from_openstack_servers(config, servers_list):
    servers = dict()
    dns_domain = config['server']['dns_domain']
    for k in sorted(servers_list.keys()):
        servers[k + dns_domain] = \
            get_host_ssh_conf(servers_list[k], config, k)['ip']
    return servers


def add_to_hosts_file(db_servers, rabbit_servers, manager_servers, config,
                      logger):

    extracted_database_info = \
        extract_values_from_openstack_servers(config, db_servers)
    extracted_rabbits_info = \
        extract_values_from_openstack_servers(config, rabbit_servers)
    extracted_managers_info = \
        extract_values_from_openstack_servers(config, manager_servers)

    add_to_hosts_servers(db_servers, extracted_database_info,
                         extracted_rabbits_info, extracted_managers_info,
                         config, logger)
    add_to_hosts_servers(rabbit_servers, extracted_database_info,
                         extracted_rabbits_info, extracted_managers_info,
                         config, logger)
    add_to_hosts_servers(manager_servers, extracted_database_info,
                         extracted_rabbits_info, extracted_managers_info,
                         config, logger)

    add_hosts_to_haproxy(extracted_database_info,
                         extracted_rabbits_info, extracted_managers_info,
                         config, logger)


def copy_cloudify_rpm_to_hosts(db_servers, rabbit_servers, manager_servers,
                               config, logger):

    def copy_rpm_to_server(server):
        with get_fabric_settings(server):
            download_cloudify_rpm(server, config['cloudify_config']['rpm_url'],
                                  logger)

    for k in sorted(db_servers.keys()):
        server = get_host_ssh_conf(db_servers[k], config, k)
        wait_for_ssh(server['ip'])
        copy_rpm_to_server(server)
    for k in sorted(rabbit_servers.keys()):
        server = get_host_ssh_conf(rabbit_servers[k], config, k)
        wait_for_ssh(server['ip'])
        copy_rpm_to_server(server)
    for k in sorted(manager_servers.keys()):
        server = get_host_ssh_conf(manager_servers[k], config, k)
        wait_for_ssh(server['ip'])
        copy_rpm_to_server(server)


def reconfigure_ha_proxy(config, rabbit_servers, manager_servers, logger):
    server = dict()
    server['ip'] = config['cloudify_config']['ha_proxy']
    server['key'] = config['server']['key']
    server['ssh_user'] = config['server']['ssh_user']
    ca_cert = config['cloudify_config']['ca_cert']

    rabbitmq_servers = \
        extract_values_from_openstack_servers(config, rabbit_servers)
    cfy_5_managers = \
        extract_values_from_openstack_servers(config, manager_servers)

    with get_fabric_settings(server):
        logger.info('replace cfy4 ips with cfy5')

        put(ca_cert, '/tmp/ca')
        run("sudo mv /tmp/ca /etc/haproxy/ca")
        run("sudo chown root:root /etc/haproxy/ca")
        run("sudo chmod 644 /etc/haproxy/ca")

        run("sudo sed -i 's/server cm1.*:5671/server {0} {1}:5671/g'  "
            "/etc/haproxy/haproxy.cfg".format(rabbitmq_servers.keys()[0],
                                              rabbitmq_servers.keys()[0]))
        run("sudo sed -i 's/server cm2.*:5671/server {0} {1}:5671/g'  "
            "/etc/haproxy/haproxy.cfg".format(rabbitmq_servers.keys()[1],
                                              rabbitmq_servers.keys()[1]))
        run("sudo sed -i 's/server cm3.*:5671/server {0} {1}:5671/g'  "
            "/etc/haproxy/haproxy.cfg".format(rabbitmq_servers.keys()[2],
                                              rabbitmq_servers.keys()[2]))
        # add port 15671 for ssl rabbits
        config_for_port = """
frontend rabbitmq_ssl_front
   bind proxy{0}:15671 ssl crt /etc/haproxy/cert no-sslv3
   redirect scheme https if !{{ ssl_fc }}
   default_backend rabbitmq_ssl_back
backend rabbitmq_ssl_back
   option forceclose
   option forwardfor
   stick-table type ip size 1m expire 1h
   stick on src
   default-server inter 3s fall 3 rise 2 on-marked-down shutdown-sessions
     server {1} {1}:15671 maxconn 32 ssl check check-ssl port 15671 ca-file {4}
     server {2} {2}:15671 maxconn 32 ssl check check-ssl port 15671 ca-file {4}
     server {3} {3}:15671 maxconn 32 ssl check check-ssl port 15671 ca-file {4}
        """.format(config['server']['dns_domain'],
                   rabbitmq_servers.keys()[0],
                   rabbitmq_servers.keys()[1],
                   rabbitmq_servers.keys()[2], '/etc/haproxy/ca')
        run("sudo bash -c 'echo \"{0}\" >> /etc/haproxy/haproxy.cfg'".
            format(config_for_port))


        run("sudo sed -i 's/server cm1.*:/server {0} {1}:/g'  "
            "/etc/haproxy/haproxy.cfg".format(cfy_5_managers.keys()[0],
                                              cfy_5_managers.keys()[0]))
        run("sudo sed -i 's/server cm2.*:/server {0} {1}:/g'  "
            "/etc/haproxy/haproxy.cfg".format(cfy_5_managers.keys()[1],
                                              cfy_5_managers.keys()[1]))
        run("sudo sed -i 's/server cm3.*:/server {0} {1}:/g'  "
            "/etc/haproxy/haproxy.cfg".format(cfy_5_managers.keys()[2],
                                              cfy_5_managers.keys()[2]))
        run('sudo systemctl restart haproxy')


def prepare_cfy_5_cluster(config, logger):

    #prepare_ca_certificate(config)

    download_cloudify_rpm_locally(config['cloudify_config']['rpm_url'], logger)

    openstack_connection = create_openstack_connection(config['openstack'])

    db_servers, rabbit_servers, manager_servers = create_cluster_hosts(
        openstack_connection, config, logger)

    add_to_hosts_file(db_servers, rabbit_servers, manager_servers, config,
                      logger)

    copy_cloudify_rpm_to_hosts(db_servers, rabbit_servers, manager_servers,
                               config, logger)

    reconfigure_ha_proxy(config, rabbit_servers, manager_servers, logging)

    db_servers, db_pass = configure_database_servers(db_servers, config,
                                                     logger)

    rabbitmq_cluster_members = configure_rabbitmq_servers(rabbit_servers,
                                                          config, logging)

    cloudify_managers = configure_cloudify_managers(db_servers, db_pass,
                                                    rabbitmq_cluster_members,
                                                    manager_servers, config,
                                                    logger)

    return cloudify_managers, rabbitmq_cluster_members


def stop_cfy_5_other_mangers(config, cfy_5_managers, active_manager, logger):
    for manager in cfy_5_managers.values():
        if manager != active_manager:
            server = dict()
            server['ip'] = manager
            server['key'] = config['server']['key']
            server['ssh_user'] = config['server']['ssh_user']
            with get_fabric_settings(server):
                logger.info('stop manager')
                run('cfy_manager stop --force')


def start_cfy_5_other_mangers(config, cfy_5_managers, active_manager, logger):
    for manager in cfy_5_managers.values():
        if manager != active_manager:
            server = dict()
            server['ip'] = manager
            server['key'] = config['server']['key']
            server['ssh_user'] = config['server']['ssh_user']
            with get_fabric_settings(server):
                logger.info('start manager')
                run('cfy_manager start')


def main():
    parse_args = _parse_command()
    with open(parse_args.config_path) as config_file:
        config = yaml.full_load(config_file)

    logging.basicConfig(level=logging.INFO)

    active_cfy4_manager = get_cfy_manager4_active(config)
    logging.info("Active Manager in 4.X Cluster is {}".format(
        active_cfy4_manager))
    get_cfy4_config(config, active_cfy4_manager, logging)
    get_cfy4_ssh_files(config, active_cfy4_manager, logging)
    create_snapshot(config, active_cfy4_manager, 'upgrade-to-cfy5', logging)
    get_snapshot(config, active_cfy4_manager, 'upgrade-to-cfy5', logging)

    cfy5_managers, rabbitmq_servers = prepare_cfy_5_cluster(config, logging)
    active_cfy5_manager = cfy5_managers.values()[0]
    logging.info("Active Manager in 5.X Cluster is {}".format(
        active_cfy5_manager))
    stop_cfy_5_other_mangers(config, cfy5_managers, active_cfy5_manager,
                             logging)
    upload_snapshot(config, active_cfy5_manager, 'upgrade-to-cfy5', logging)
    restore_snapshot(config, active_cfy5_manager, 'upgrade-to-cfy5', logging)
    start_cfy_5_other_mangers(config, cfy5_managers, active_cfy5_manager,
                              logging)
    put_cfy4_ssh_files_to_cfy5(config, cfy5_managers, logging)
    install_all_agents(config, active_cfy5_manager, logging)
    validate_agents(config, active_cfy5_manager, logging)


if __name__ == '__main__':
    main()
