import requests

requests.packages.urllib3.disable_warnings()


class IBClient(object):

    def __init__(self, server, username, password, api_version, dns_view="default", network_view="default", verify_ssl=False):
        """
        Class initialization method
        """
        self.server = server
        self.username = username
        self.password = password
        self.dns_view = dns_view
        self.network_view = network_view
        self.verify_ssl = verify_ssl
        self.api_version = api_version
        self.rest_url = "https://{0}/wapi/v{1}/".format(self.server, self.api_version)

    def _get(self, frag):
        """
        Sends GET requests to Infoblox Server
        """
        try:
            r = requests.get(self.rest_url + frag, verify=self.verify_ssl, auth=(self.username, self.password))
            return r
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def _post(self, frag, data=None):
        """
        Sends POST requests to Infoblox Server
        """
        return False

    def _put(self, frag, data=None):
        """
        Sends PUT requests to Infoblox Server
        """
        return False

    def _delete(self, frag, data=None):
        """
        Sends DELETE requests to Infoblox Server
        """
        return False

    def get_network(self, network, fields=None):
        """
        Gets the Network object
        :param network: network in CIDR format (x.x.x.x/yy)
        :param fields: comma separated list of field names (optional)
        """
        if not fields:
            fields = "network,netmask"
        frag = "network?network=" + network + "&_return_fields=" + fields

        record = self._get(frag)

        return record.json()

    def get_network_by_ip(self, ip_address, fields=None):
        """
        Gets the Network object from an IP Address
        :param ip_address: IP Address
        :param fields: comma separated list of field names (optional)
        """
        if not fields:
            fields = "network,netmask"
        frag = "network?contains_address=" + ip_address + "&_return_fields=" + fields
        record = self._get(frag)
        return record.json()

    def get_network_container(self, network):
        """
        Gets the Network Container object
        :param network_container: network in CIDR format (x.x.x.x/yy)
        """
        frag = "network_container?network=" + network
        return self._get(frag)

    def get_dns_record(self, type, record, fields=None):
        """
        Gets the DNS record
        :param type: DNS Record Type (A, PTR, CNAME, MX, etc)
        :param name: Record name
        :param fields: comma separated list of field names (optional)
        """
        frag = "record:" + type + "?record=" + record
        if fields:
            frag += "&_return_fields=" + fields
        return self._get(frag)

    def get_fixedaddress(self, address):
        """
        Gets the Fixed Address Object
        :param address: IP Address of the object
        """
        frag = "fixedaddress?ipv4addr=" + address
        return self._get(frag)

    def get_fixedaddress_by_mac(self, mac_address):
        """
        Gets the Fixed Address Object by MAC Address
        :param mac_address:
        """
        frag = "fixedaddress?mac=" + mac_address
        return self._get(frag)
