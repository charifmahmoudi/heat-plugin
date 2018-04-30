__author__ = 'Charif'

#from oslo_log import log as logging
from heat.engine import properties
from heat.engine import resource
from gettext import gettext as _
import requests
import json
import time
from time import sleep

LOG = logging.getLogger(__name__)

class ServiceChain(resource.Resource):
    PROPERTIES = (
        NEUTRON_PORTS,
        ODL_USERNAME,
        ODL_PASSWORD,
        SECURITY_CONTROLS) = (
        'neutron_ports',
        'odl_username',
        'odl_password',
        'security_controls')

    properties_schema = {
        NEUTRON_PORTS: properties.Schema(
            data_type=properties.Schema.LIST,
            description=_('IP and port of the node to secure'),
            required=True
        ),
        ODL_USERNAME: properties.Schema(
            data_type=properties.Schema.STRING,
            description=_('User name to be configured for ODL Restconf access'),
            required=True
        ),
        ODL_PASSWORD: properties.Schema(
            data_type=properties.Schema.STRING,
            description=_('Password to be set for ODL Restconf access'),
            required=True
        ),
        SECURITY_CONTROLS: properties.Schema(
            data_type=properties.Schema.STRING,
            description=_('List of the securiy controls to implement'),
            required=True
        )
    }

    def handle_create(self):
        # Time until dependent resources are created.
        # Can vary for different environments (preliminary).
        time.sleep(30)
        odl_username = self.properties.get(self.ODL_USERNAME)
        odl_password = self.properties.get(self.ODL_PASSWORD)
        security_controls = self.properties.get(self.SECURITY_CONTROLS)
        neutron_ports = self.properties.get(self.NEUTRON_PORTS)
        ports = ','.join(neutron_ports)

        create_url = 'restconf/operations/NIST-800-53:create-security-control'
        url = "%s%s:%s@%s/%s" % ('http://',odl_username,odl_password,security_controls,create_url)
        ports_dict = {"input": {"neutron-ports": ports}}
        headers = {'Content-type': 'application/json'}
        LOG.debug('CHAIN_PORTS %s', ports_dict)
        try:
            req = requests.post(url, data=json.dumps(ports_dict), headers=headers)
            if req.json()['output']:
                chainID = req.json()['output']['service-chain-id']
                self.resource_id_set(chainID)
                LOG.debug('chainID %s', chainID)
                return chainID
        except Exception as ex:
            LOG.warn("Failed to fetch chain ID: %s", ex)

    def handle_delete(self):

        odl_username = self.properties.get(self.ODL_USERNAME)
        odl_password = self.properties.get(self.ODL_PASSWORD)
        security_controls = self.properties.get(self.SECURITY_CONTROLS)

        if self.resource_id is None:
            LOG.debug('Delete: Chain ID is empty')
            return
        chain_id = self.resource_id
        delete_url = 'restconf/operations/netfloc:delete-service-chain'
        url = "%s%s:%s@%s/%s" % ('http://',odl_username,odl_password,security_controls,delete_url)
        headers = {'Content-type': 'application/json'}
        body = {"input": {"service-chain-id": str(chain_id)}}
        try:
            req = requests.post(url, data=json.dumps(body), headers=headers)
        except Exception as ex:
             LOG.warn("Failed to delete chain: %s", ex)

def resource_mapping():
    mappings = {}
    mappings['Security::800-53::MultipleControls'] = ServiceChain
    return mappings