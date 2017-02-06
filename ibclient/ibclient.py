import requests

requests.packages.urllib3.disable_warnings()


class IBClient(object):

    def __init__(self, server, username, password, api_version, dns_view="default", network_view="default", verify_ssl=False):
        """
        Class initialization method
        :param server: Infoblox Gridmaster server (either IP or DNS)
        :param username: Username to log into Infoblox
        :param password: password for username
        :param api_version: Infoblox API version
        :param dns_view: DNS View
        :param network_view: Network View
        :param verify_ssl: Verify SSL connection
        :type verify_ssl: Boolean
        """
        self.server = server
        self.credentials = (username, password)
        self.dns_view = dns_view
        self.network_view = network_view
        self.verify_ssl = verify_ssl
        self.api_version = api_version
        self.url = "https://{0}/wapi/v{1}/".format(self.server, self.api_version)

    def _get(self, frag):
        """
        Sends GET requests to Infoblox Server
        """
        try:
            r = requests.get(self.url + frag, verify=self.verify_ssl, auth=self.credentials)
            r_json = r.json()
            if r.status_code == 200:
                if len(r_json) > 0:
                    return r_json
                else:
                    raise Exception("No object found for: " + frag)
            else:
                if 'text' in r_json:
                    raise Exception(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def _post(self, frag, data=None):
        """
        Sends POST requests to Infoblox Server.
        Creates a new Infoblox object
        """
        try:
            r = requests.post(self.url + frag, data=data, verify=self.verify_ssl, auth=self.credentials)
            r_json = r.json()
            if r.status_code == 200 or r.status_code == 201:
                if len(r_json) > 0:
                    return r_json
                else:
                    raise Exception("No object returned for: " + frag)
            else:
                if 'text' in r_json:
                    raise Exception(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def _put(self, frag, data=None):
        """
        Sends PUT requests to Infoblox Server
        Updates an existing Infoblox object
        """
        try:
            r = requests.put(self.url + frag, data=data, verify=self.verify_ssl, auth=self.credentials)
            r_json = r.json()
            if r.status_code == 200:
                if len(r_json) > 0:
                    return r_json[0]
                else:
                    raise Exception("Error with: " + frag)
            else:
                if 'text' in r_json:
                    raise Exception(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def _delete(self, frag, data=None):
        """
        Sends DELETE requests to Infoblox Server
        """
        try:
            r = requests.delete(self.url + frag, data=data, verify=self.verify_ssl, auth=self.credentials)
            r_json = r.json()
            if r.status_code == 200:
                if len(r_json) > 0:
                    return r_json
                else:
                    raise Exception("Error with: " + frag)
            else:
                if 'text' in r_json:
                    raise Exception(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    # Get Functions

    def get_memberservers(self):
        """
        Gets all of the member Infoblox servers
        """
        frag = "member"
        return self._get(frag)

    def get_dhcp_servers(self):
        """
        Gets the DHCP Servers (that are set to Enable DHCP)
        """
        frag = "member:dhcpproperties?_return_fields=enable_dhcp,host_name,ipv4addr"
        results = self._get(frag)
        for i in xrange(len(results)):
            if results[i][u'enable_dhcp'] is False:
                results.pop(i)
        return results

    def get_network(self, network, fields=None):
        """
        Gets the Network object
        :param network: network in CIDR format (x.x.x.x/yy)
        :param fields: comma separated list of field names (optional)
        """
        if not fields:
            fields = "network,netmask"
        frag = "network?network=" + network + "&_return_fields=" + fields
        return self._get(frag)

    def get_network_by_ip(self, ip_address, fields=None):
        """
        Gets the Network object from an IP Address
        :param ip_address: IP Address
        :param fields: comma separated list of field names (optional)
        """
        if not fields:
            fields = "network,netmask"
        frag = "network?contains_address=" + ip_address + "&_return_fields=" + fields
        return self._get(frag)

    def get_next_available_network(self, network, cidr, num=1):
        """
        Get the next available network with appropriate mask from network Container
        :param network: Network Container (including CIDR mask)
        :param cidr: New network's cidr Address
        :param num: Number of networks needed
        """
        container = self._get("networkcontainer?network=" + network)
        ref = container[0]['_ref']
        find = ref.find(":")
        ref = ref[0:find]

        frag = "{0}/?_function=next_available_network&cidr={1}&num={2}".format(ref, str(cidr), str(num))

        record = self._post(frag, '')

        return record

    def get_network_container(self, network, fields=None):
        """
        Gets the Network Container object
        :param network_container: network in CIDR format (x.x.x.x/yy)
        :param fields: comma separated list of field names (optional)
        """
        frag = "networkcontainer?network=" + network
        if fields:
            frag += "&_return_fields=" + fields
        return self._get(frag)

    def get_dns_record(self, type, record, fields=None):
        """
        Gets the DNS record
        If trying to get a PTR record, you need the in-addr.arpa address
        :param type: DNS Record Type (A, PTR, CNAME, MX, etc)
        :param name: Record name
        :param fields: comma separated list of field names (optional)
        """
        frag = "record:" + type + "?name=" + record
        if fields:
            frag += "&_return_fields=" + fields
        return self._get(frag)

    def get_fixedaddress(self, address, fields=None):
        """
        Gets the Fixed Address Object
        :param address: IP Address of the object
        """
        if not fields:
            fields = "ipv4addr,mac"
        frag = "fixedaddress?ipv4addr=" + address + "&_return_fields=" + fields
        return self._get(frag)

    def get_fixedaddress_by_mac(self, mac_address):
        """
        Gets the Fixed Address Object by MAC Address
        :param mac_address:
        """
        if not fields:
            fields = "ipv4addr,mac"
        frag = "fixedaddress?mac=" + mac_address + "&_return_fields=" + fields
        return self._get(frag)

    # Create Functions

    def create_network(self, network, comment, fields):
        """
        Creates a new network
        """
        frag = ""
        data = ""
        # return _post(frag, data)
        return False

    def create_network_container(self):
        return False

    def create_dhcp_range(self):
        return False

    def create_fixedaddress(self):
        return False

    def create_dns_record(self):
        """
        Create a new DNS Record. This creates both the A and PTR records
        """
        return False

    # update Functions
    # To be defined below here

    # Delete Functions

    def delete_network(self):
        return False

    def delete_network_container(self):
        return False

    def delete_dhcp_range(self):
        return False

    def delete_fixedaddress(self):
        return False

    def delete_fixedaddress_by_mac(self):
        return False

    def delete_dns_record(self):
        return False
