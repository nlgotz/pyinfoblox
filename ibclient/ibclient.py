import requests
from jinja2 import Environment, FileSystemLoader
import os

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

    # Helper functions to create requests

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

    def _delete(self, frag):
        """
        Sends DELETE requests to Infoblox Server
        """
        try:
            r = requests.delete(self.url + frag, verify=self.verify_ssl, auth=self.credentials)
            r_json = r.json()
            if r.status_code == 200:
                if len(r_json) > 0:
                    return r_json
                else:
                    raise Exception("Error with: " + frag)
            else:
                if 'text' in r_json.json():
                    raise Exception(r_json.json()['text'])
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

    def get_dhcpfailover(self):
        """
        Gets the DHCP Failover Pair name.
        Used for creating DHCP ranges
        """
        return self._get("dhcpfailover")

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

    def get_range(self, start_addr, end_addr, fields=None):
        """
        Get DHCP range by start and end addr
        :param start_addr: First address in the DHCP range
        :param end_addr: Last address in the DHCP range
        :param fields: comma separated list of field names (optional)
        """
        frag = "range?start_addr={0}&end_addr={1}".format(start_addr, end_addr)
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

    def get_similar_dns_records(self, type, record, fields=None):
        """
        Gets similar DNS records
        If trying to get a PTR record, you need the in-addr.arpa address
        :param type: DNS Record Type (A, PTR, CNAME, MX, etc)
        :param name: Record name
        :param fields: comma separated list of field names (optional)
        """
        frag = "record:" + type + "?name~" + record
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
        :param mac_address: MAC Address in xx:xx:xx:xx:xx:xx format
        """
        if not fields:
            fields = "ipv4addr,mac"
        frag = "fixedaddress?mac=" + mac_address + "&_return_fields=" + fields
        return self._get(frag)

    # Create Functions

    def create_network(self, network, comment, template="network.j2"):
        """
        Creates a new network
        :param network: Network address with CIDR mask
        :param comment: Network name that shows up in Infoblox
        :param template: Template file to use (optional)
        """
        dhcp_members = self.get_dhcp_servers()
        var = {'network': network, 'comment': comment, 'network_view': self.network_view, 'dhcp_members': dhcp_members}

        ENV = Environment(loader=FileSystemLoader(
            os.path.join(os.path.dirname(__file__), "templates")))
        template = ENV.get_template("network.j2")

        data = template.render(var)

        return self._post('network', data)

    def create_network_container(self, network, comment):
        """
        Creates a network container
        :param network: Network address with CIDR mask
        :param comment: Network container name that shows up in infoblox
        """
        frag = "networkcontainer"
        return False

    def create_dhcp_range(self, network, start_addr, end_addr, exc_start, exc_end, options=None, template="dhcp.j2"):
        """
        Create a new DHCP range
        :param network: Network address with CIDR mask
        :param start_addr: DHCP range start address
        :param end_addr: DHCP range end address
        :param exc_start: DHCP Exclusion range start
        :param exc_end: DHCP Exclusion range end
        :param options: DHCP options in a dict array (optional)
        :param template: Template file (not implemented yet)

        Options format:
        [{'name': name, 'num': dhcp_option_num, 'use_option': True, 'value': value}, { second dict }]
        """
        failover = self.get_dhcpfailover()
        var = {
            'failover': failover,
            'network': network,
            'start_addr': start_addr,
            'end_addr': end_addr,
            'exc_start': exc_start,
            'exc_end': exc_end,
            'options': options
        }

        ENV = Environment(loader=FileSystemLoader(
            os.path.join(os.path.dirname(__file__), "templates")))
        template = ENV.get_template("dhcp.j2")

        data = template.render(var)

        return self._post('range', data)

    def create_fixedaddress(self, address, ):
        """
        Create a fixed Address
        """
        return False

    def create_ztp_fixedaddress(self, network, mac_addr, host, tftp_server, cfg_file, vendor_code=None):
        """
        """
        if not vendor_code:
            vendor_code = "00:00:00:09:12:05:10:61:75:74:6f:69:6e:73:74:61:6c:6c:5f:64:68:63:70"
        var = {
            'network': network,
            'mac_addr': mac_addr,
            'host': host,
            'tftp_server': tftp_server,
            'cfg_file': cfg_file,
            'vendor_code': vendor_code
        }

        ENV = Environment(loader=FileSystemLoader(
            os.path.join(os.path.dirname(__file__), "templates")))
        template = ENV.get_template("fixedaddress_ztp.j2")

        data = template.render(var)

        return self._post('fixedaddress', data)

    def create_a_record(self, address, fqdn):
        """
        Create a new DNS A record
        :param address: IPv4 Address (no CIDR notation)
        :param fqdn: Hostname plus domain name
        """
        data = '{"ipv4addr": "' + address + '","name": "' + fqdn + '","view": "' + self.dns_view + '"}'
        return self._post('record:a', data)

    def create_ptr_record(self, address, fqdn):
        """
        Create a new DNS PTR record
        :param address: IPv4 Address (no CIDR notation)
        :param fqdn: Hostname plus domain name
        """
        data = '{"ipv4addr": "' + address + '","ptrdname": "' + fqdn + '","view": "' + self.dns_view + '"}'
        return self._post('record:ptr', data)

    def create_dns_record(self, address, fqdn):
        """
        Create new DNS Records for a device (both A and PTR)
        :param address: IPv4 Address (no CIDR notation)
        :param fqdn: Hostname plus domain name
        """
        try:
            self.create_a_record(address, fqdn)
        except ValueError:
            raise Exception(r)
        except Exception:
            raise
        try:
            self.create_ptr_record(address, fqdn)
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    # Update Functions

    # To be defined below here

    # Delete Functions

    def delete_network(self, network):
        """
        Remove an existing network
        :param network: network in CIDR format (x.x.x.x/yy)
        """
        objref = self.get_network(network)
        network_ref = objref[0]["_ref"]
        return self._delete(network_ref)

    def delete_network_container(self, network_container):
        """
        Remove an existing network container
        :param network_container: network in CIDR format (x.x.x.x/yy)
        """
        objref = self.get_network_container(network_container)
        network_container_ref = objref[0]["_ref"]
        return self._delete(network_container_ref)

    def delete_range(self, start_addr, end_addr):
        """
        Remove an existing DHCP range
        :param start_addr: First address in the DHCP rangeFalse
        """
        objref = self.get_range(start_addr, end_addr)
        range_ref = objref[0]["_ref"]
        return self._delete(range_ref)

    def delete_fixedaddress(self, address):
        """
        Remove an existing fixedaddress
        :param address: IP Address of the object
        """
        objref = self.get_fixedaddress(address)
        fixaddress_ref = objref[0]["_ref"]
        return self._delete(fixaddress_ref)

    def delete_fixedaddress_by_mac(self, mac_address):
        """
        Remove an existing fixedaddress by MAC Address
        :param mac_address: MAC Address in xx:xx:xx:xx:xx:xx format
        """
        objref = self.get_fixedaddress_by_mac(mac_address)
        fixaddress_ref = objref[0]["_ref"]
        return self._delete(fixaddress_ref)

    def delete_dns_records(self, fqdn):
        """
        Remove DNS (A&PTR) records by name
        :param fqdn: Fully Qualified Domain Name for the host
        """
        objref = self.get_dns_record('a', fqdn)
        dns_ref = objref[0]["_ref"]
        return self._delete(dns_ref + "?remove_associated_ptr")
