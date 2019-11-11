import argparse
import logging
import yaml
import os
import time
import uuid
import socket

import openstack

from fabric.api import settings, run, get, put

from cloudify_rest_client.client import CloudifyClient

EXECUTION_POLL_INTERVAL_SECONDS = 5
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
    if config['cloudify_config']['ca_cert'] and \
            config['cloudify_config']['ca_key']:
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
    return server


def get_fabric_settings(host):
    return settings(
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
    logger.info("Downloading RPM from %s", rpm_url)
    with get_fabric_settings(server):
        put('cloudify-manager-install.rpm', 'cloudify-manager-install.rpm')
        #run('curl -o cloudify-manager-install.rpm %s' % rpm_url)


def download_cloudify_rpm_locally(rpm_url, logger):
    logger.info("Downloading RPM from %s to local machine", rpm_url)
    os.system('curl -C - -o cloudify-manager-install.rpm %s' % rpm_url)


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
                if k == 'cluster_members':
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


def prepare_database_install_config(server, config, logger):

    ca_cert = config['cloudify_config']['ca_cert']
    ca_key = config['cloudify_config']['ca_key']
    db_pass = config['cloudify_config']['db_pass']
    server_home_path = '/home/{}/'.format(server['ssh_user'])

    host_cert, host_key = \
        prepare_host_certificate(ca_cert, ca_key, server['name'], server['ip'])

    with get_fabric_settings(server):
        logger.info("Uploading Certs")
        run('mkdir {}/.certs'.format(server_home_path))
        put(host_cert, '{}/.certs/postgres_crt.pem'.format(server_home_path))
        put(host_key, '{}/.certs/postgres_key.pem'.format(server_home_path))
        put(ca_cert, '{}/.certs/postgres_ca.pem'.format(server_home_path))
        put(ca_key, '{}/.certs/postgres_ca_key.pem'.format(server_home_path))

    install_config = dict()
    install_config['postgresql_server'] = dict()
    install_config['postgresql_server']['enable_remote_connections'] = True
    install_config['postgresql_server']['ssl_enabled'] = True
    install_config['postgresql_server']['ssl_client_verification'] = False
    install_config['postgresql_server']['ssl_only_connections'] = False
    install_config['postgresql_server']['postgres_password'] = db_pass
    install_config['postgresql_server']['cert_path'] = \
        '{}/.certs/postgres_crt.pem'.format(server_home_path)
    install_config['postgresql_server']['key_path'] = \
        '{}/.certs/postgres_key.pem'.format(server_home_path)
    install_config['postgresql_server']['ca_path'] = \
        '{}/.certs/postgres_ca.pem'.format(server_home_path)
    install_config['ssl_inputs'] = dict()
    install_config['ssl_inputs']['postgresql_server_cert_path'] = \
        '{}/.certs/postgres_crt.pem'.format(server_home_path)
    install_config['ssl_inputs']['postgresql_server_key_path'] = \
        '{}/.certs/postgres_key.pem'.format(server_home_path)
    install_config['ssl_inputs']['ca_cert_path'] = \
        '{}/.certs/postgres_ca.pem'.format(server_home_path)
    install_config['ssl_inputs']['ca_key_path'] = \
        '{}/.certs/postgres_ca_key.pem'.format(server_home_path)

    install_config['services_to_install'] = ['database_service']

    return install_config


def prepare_rabbitmq_install_config(server, config, rabbit_servers,
                                    first_host, erlang_cookie, logger):

    ca_cert = config['cloudify_config']['ca_cert']
    ca_key = config['cloudify_config']['ca_key']
    server_home_path = '/home/{}/'.format(server['ssh_user'])

    host_cert, host_key = \
        prepare_host_certificate(ca_cert, ca_key, server['name'], server['ip'])

    with get_fabric_settings(server):
        logger.info("Uploading Certs")
        run('mkdir {}/.certs'.format(server_home_path))
        put(host_cert, '{}/.certs/rabbitmq_crt.pem'.format(server_home_path))
        put(host_key, '{}/.certs/rabbitmq_key.pem'.format(server_home_path))
        put(ca_cert, '{}/.certs/rabbitmq_ca.pem'.format(server_home_path))
        put(ca_key, '{}/.certs/rabbitmq_ca_key.pem'.format(server_home_path))

    install_config = dict()
    install_config['rabbitmq'] = dict()
    install_config['rabbitmq']['cert_path'] = \
        '{}/.certs/rabbitmq_crt.pem'.format(server_home_path)
    install_config['rabbitmq']['key_path'] = \
        '{}/.certs/rabbitmq_key.pem'.format(server_home_path)
    install_config['rabbitmq']['ca_path'] = \
        '{}/.certs/rabbitmq_ca.pem'.format(server_home_path)
    install_config['rabbitmq']['nodename'] = server['name']
    install_config['rabbitmq']['erlang_cookie'] = erlang_cookie

    network_name = config['server']['network_name']
    install_config['rabbitmq']['cluster_members'] = dict()
    for k in sorted(rabbit_servers.keys()):
        install_config['rabbitmq']['cluster_members'][k] = dict()
        install_config['rabbitmq']['cluster_members'][k]['networks'] = dict()
        install_config['rabbitmq']['cluster_members'][k]['networks']['default'] = \
            str(rabbit_servers[k].addresses[network_name][0]['addr'])

    if not first_host:
        install_config['rabbitmq']['join_cluster'] = \
            sorted(rabbit_servers.keys())[0]

    install_config['services_to_install'] = ['queue_service']

    return install_config


def prepare_manager_install_config(server, config, db_ip, db_pass,
                                   rabbit_servers, logger):

    ca_cert = config['cloudify_config']['ca_cert']
    ca_key = config['cloudify_config']['ca_key']
    server_home_path = '/home/{}/'.format(server['ssh_user'])

    host_cert, host_key = \
        prepare_host_certificate(ca_cert, ca_key, server['name'], server['ip'])

    with get_fabric_settings(server):
        logger.info("Uploading Certs")
        run('mkdir {}/.certs'.format(server_home_path))
        put(host_cert, '{}/.certs/manager_crt.pem'.format(server_home_path))
        put(host_key, '{}/.certs/manager_key.pem'.format(server_home_path))
        put(ca_cert, '{}/.certs/manager_ca.pem'.format(server_home_path))
        put(ca_key, '{}/.certs/manager_ca_key.pem'.format(server_home_path))

    cfy4_config = None
    with open('resources/cfy4_config.yaml', 'r') as f:
        cfy4_config = yaml.full_load(f)

    install_config = dict()
    install_config['manager'] = dict()
    install_config['manager']['security'] = dict()
    install_config['manager']['security']['admin_password'] = 'admin'
    install_config['manager']['security']['ssl_enabled'] = True
    install_config['rabbitmq'] = dict()
    install_config['rabbitmq']['ca_path'] = \
        '{}/.certs/manager_ca.pem'.format(server_home_path)

    install_config['rabbitmq']['cluster_members'] = dict()

    network_name = config['server']['network_name']
    install_config['rabbitmq']['cluster_members'] = dict()
    for k in sorted(rabbit_servers.keys()):
        install_config['rabbitmq']['cluster_members'][k] = dict()
        install_config['rabbitmq']['cluster_members'][k]['networks'] = dict()
        install_config['rabbitmq']['cluster_members'][k]['networks']['default'] = rabbit_servers[k]

    install_config['postgresql_client'] = dict()
    install_config['postgresql_client']['host'] = db_ip
    install_config['postgresql_client']['ssl_enabled'] = True
    install_config['postgresql_client']['ssl_client_verification'] = False
    install_config['postgresql_client']['postgres_password'] = db_pass
    install_config['postgresql_client']['server_password'] = db_pass
    install_config['postgresql_client']['ca_path'] = \
        '{}/.certs/manager_ca.pem'.format(server_home_path)

    install_config['ssl_inputs'] = dict()
    install_config['ssl_inputs']['ca_cert_path'] = \
        '{}/.certs/manager_ca.pem'.format(server_home_path)
    install_config['ssl_inputs']['ca_key_path'] = \
        '{}/.certs/manager_ca_key.pem'.format(server_home_path)


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
    install_config['provider_context']['import_resolver']['parameters']['fallback'] = False

    install_config['services_to_install'] = ['manager_service']

    return install_config


def install_manager(server, logger):
    logger.info("Installing Cloudify Manager")
    with get_fabric_settings(server):
        run('cfy_manager install --private-ip %s --public-ip %s'
            % (server['ip'], server['ip']))


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


def create_database_server(openstack_connection, config, logger):

    server_name = config['server']['db_server_name']
    db_server = create_openstack_server(openstack_connection,
                                        config['server'], server_name,
                                        logger)
    if not db_server:
        return '', ''
    server = get_host_ssh_conf(db_server, config, server_name)
    wait_for_ssh(server['ip'])
    download_cloudify_rpm(server, config['cloudify_config']['rpm_url'], logger)
    install_rpm(server, logger)
    install_config = prepare_database_install_config(server, config, logger)
    update_config(server, install_config, 'resources/{}.yaml'.format(
        server_name), logger)
    install_manager(server, logger)

    return server['ip'], config['cloudify_config']['db_pass']


def create_rabbitmq_servers(openstack_connection, config, logger):

    server_name = config['server']['rabbit_server_name']
    cluster_members = dict()
    rabbit_servers = dict()
    rabbit_servers[server_name+'1'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '1', logger)
    rabbit_servers[server_name+'2'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '2', logger)
    rabbit_servers[server_name+'3'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '3', logger)

    erlang_cookie = str(uuid.uuid4())

    first = True

    for k in sorted(rabbit_servers.keys()):
        server = get_host_ssh_conf(rabbit_servers[k], config, k)
        wait_for_ssh(server['ip'])
        download_cloudify_rpm(server, config['cloudify_config']['rpm_url'],
                              logger)
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


def create_cloudify_managers(openstack_connection, config, db_ip, db_pass,
                             rabbitmq_servers, logger):

    server_name = config['server']['manager_server_name']
    cluster_memebers = dict()
    manager_servers = dict()
    manager_servers[server_name+'1'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '1', logger)
    manager_servers[server_name+'2'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '2', logger)
    manager_servers[server_name+'3'] = create_openstack_server(
        openstack_connection, config['server'], server_name + '3', logger)

    first = True
    for k in sorted(manager_servers.keys()):
        server = get_host_ssh_conf(manager_servers[k], config, k)
        wait_for_ssh(server['ip'])
        download_cloudify_rpm(server, config['cloudify_config']['rpm_url'],
                              logger)
        install_rpm(server, logger)
        install_config = prepare_manager_install_config(server,
                                                        config,
                                                        db_ip, db_pass,
                                                        rabbitmq_servers,
                                                        logger)
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
        include_logs=True,
        include_events=True
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


def restore_snapshot(config, active_manager, snapshot_id, logger):
    client = CloudifyClient(
        host=active_manager,
        **config['cloudify_config']['rest_client']
    )
    execution = client.snapshots.restore(snapshot_id)
    wait_for_terminated_status(client, execution, logger, True)


def install_all_agents(config, active_manager, logger):
    server = dict()
    server['ip'] = active_manager
    server['key'] = config['server']['key']
    server['ssh_user'] = config['server']['ssh_user']
    with get_fabric_settings(server):
        logger.info('reinstalling agents')
        run('cfy agents install --all-tenants')


def prepare_cfy_5_cluster(config, logger):

    prepare_ca_certificate(config)

    download_cloudify_rpm_locally(config['cloudify_config']['rpm_url'], logger)

    openstack_connection = create_openstack_connection(config['openstack'])

    db_ip, db_pass = create_database_server(openstack_connection, config,
                                            logger)
    rabbitmq_cluster_members = create_rabbitmq_servers(openstack_connection,
                                                       config, logging)
    cloudify_managers = create_cloudify_managers(openstack_connection, config,
                                                 db_ip, db_pass,
                                                 rabbitmq_cluster_members,
                                                 logger)
    return cloudify_managers.values()[0]


def main():
    parse_args = _parse_command()
    with open(parse_args.config_path) as config_file:
        config = yaml.full_load(config_file)

    logging.basicConfig(level=logging.INFO)

    active_cfy4_manager = get_cfy_manager4_active(config)
    get_cfy4_config(config, active_cfy4_manager, logging)
    create_snapshot(config, active_cfy4_manager, 'upgrade-to-cfy5', logging)
    get_snapshot(config, active_cfy4_manager, 'upgrade-to-cfy5', logging)

    active_cfy5_manager = prepare_cfy_5_cluster(config, logging)
    upload_snapshot(config, active_cfy5_manager, 'upgrade-to-cfy5', logging)
    restore_snapshot(config, active_cfy5_manager, 'upgrade-to-cfy5', logging)
    install_all_agents(config, active_cfy5_manager, logging)


if __name__ == '__main__':
    main()
