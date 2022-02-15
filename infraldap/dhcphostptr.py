# -*- coding: utf-8 -*-
"""
infraldap.dhcphostptr - create DNS PTR entries for DHCP host entries found
"""

import sys
import os
import logging
import ipaddress
import pprint
from typing import Mapping

import ldap0
import ldap0.filter
from ldap0 import LDAPError
from ldap0.ldapurl import LDAPUrl
from ldap0.ldapobject import LDAPObject
from ldap0.sasl import SaslAuth
from ldap0.base import encode_list

# logging log level to use
LOG_LEVEL = os.environ.get('LOG_LEVEL', logging.INFO)

LDAP0_TIMEOUT = 10.0

# LDAP URI of DHCP-LDAP server (infra-slapd)
DHCP_LDAP_SERVER = 'ldapi://'


class DHCPLDAPConnection(LDAPObject):
    """
    Connection to infra-slapd (DHCP-LDAP) authenticated with SASL/GSSAPI
    """

    def __init__(self, ldap_uri):
        ldap_uri = LDAPUrl(ldap_uri.strip())
        LDAPObject.__init__(self, ldap_uri)
        self.set_option(ldap0.OPT_X_SASL_NOCANON, 1)
        self.network_timeout = LDAP0_TIMEOUT
        self.timeout = LDAP0_TIMEOUT
        if ldap_uri.connect_uri().lower().startswith('ldap://'):
            self.sasl_interactive_bind_s('', SaslAuth({}, 'GSSAPI'))
        else:
            self.sasl_non_interactive_bind_s('EXTERNAL')
        root_dse = self.read_s('', attrlist=['namingContexts']).entry_s
        self.search_base = ldap_uri.dn or root_dse['namingContexts'][0]

    @classmethod
    def extract_ipaddress(dn, entry):
        for val in entry['dhcpStatements']:
            if val.startswith('fixed-address '):
                return ipaddress.IPv4Address(val[14:])
        raise ValueError('No IPv4 address found in entry %r' % (dn))

    def get_dhcp_subnets(self):
        """
        Return list of DHCP subnets
        """
        return self.search_s(
            self.search_base,
            ldap0.SCOPE_SUBTREE,
            filterstr='(objectClass=dhcpSubnet)',
            attrlist=['cn', 'dhcpNetMask'],
        )

    def get_forward_dns_apex_entries(self):
        """
        Return list of DNS zone apex entries of DNS zones with A RRs
        """
        return self.search_s(
            self.search_base,
            ldap0.SCOPE_SUBTREE,
            filterstr='(&(objectClass=dNSDomain)(sOARecord=*)(!(associatedDomain=*.in-addr.arpa)))',
            attrlist=['associatedDomain', 'sOARecord'],
        )

    def get_dns_ptr_entries(self, dhcp_base_dn, dns_base_dn):
        res = {}
        for dns_rr in self.search_s(
                dns_base_dn,
                ldap0.SCOPE_ONELEVEL,
                filterstr='(&(objectClass=dNSDomain)(associatedDomain=*)(pTRRecord=*))',
                attrlist=(
                    'objectClass',
                    'dc',
                    'associatedDomain',
                    'pTRRecord',
                    'seeAlso',
                    'description',
                ),
            ):
            back_link_dn = dns_rr.entry_s.get(
                'seeAlso',
                ['cn=%s,%s' % (dns_rr.entry_s['pTRRecord'][0], dhcp_base_dn)]
            )[0]
            logging.debug('back_link_dn = %r', back_link_dn)
            res[back_link_dn] = (dns_rr.dn_s, dns_rr.entry_as)
        return res

    def get_dhcpnet_dnszone_map(self) -> Mapping[str, str]:
        """
        returns mapping from DHCP network to DNS zone apex entries
        """
        res = {}
        # loop over dhcpSubnet entries
        for sub_net in self.get_dhcp_subnets():
            if not isinstance(sub_net, ldap0.res.SearchResultEntry):
                continue
            dn, entry = sub_net.dn_s, sub_net.entry_s
            logging.debug('%r -> %r', dn, entry)
            dhcp_ip_network = ipaddress.IPv4Network(
                '%s/%s' % (
                    entry['cn'][0],
                    entry['dhcpNetMask'][0],
                )
            )
            logging.debug('dhcp_ip_network = %r', dhcp_ip_network)
            # search accompanying reverse DNS zone apex record
            try:
                dns_zone = self.find_unique_entry(
                    self.search_base,
                    ldap0.SCOPE_SUBTREE,
                    filterstr='(&(objectClass=dNSDomain)(associatedDomain=%s))' % (
                        ldap0.filter.escape_str(dhcp_ip_network.reverse_pointer.split('.', 1)[1]),
                    ),
                    attrlist=['sOARecord'],
                )
            except ldap0.err.NoUniqueEntry:
                logging.warning('No DNS apex zone entry found for DHCP network %s', dhcp_ip_network)
            else:
                logging.info('Found DNS apex zone entry %r for DHCP network %s', dns_zone.dn_s, dhcp_ip_network)
                res[dn] = dns_zone.dn_s
        return res


def sync_dhcphost_ptr():
    """
    Synchronizes PTR RR entries with dhcpHost entries
    """

    # set log level based on env var LOGLEVEL
    logging.getLogger().setLevel(os.environ.get('LOG_LEVEL', 'INFO').upper())

    logging.info('Starting %s', sys.argv[0])

    try:
        ldap_uri = sys.argv[1]
    except IndexError:
        ldap_uri = DHCP_LDAP_SERVER

    try:
        ldap_conn = DHCPLDAPConnection(ldap_uri)
    except ldap0.SERVER_DOWN as err:
        logging.error(
            'Error connecting to DHCP-LDAP server %s: %s',
            ldap_uri,
            err,
        )
        sys.exit(2)
    else:
        logging.debug(
            'Connected to DHCP-LDAP server %s as %s',
            ldap_uri,
            ldap_conn.whoami_s(),
        )

    dhcp_dns_map = ldap_conn.get_dhcpnet_dnszone_map()

    for dhcp_base_dn, dns_base_dn in dhcp_dns_map.items():

        # 1. build mapping FQDN -> (dn, entry) of existing dNSDomain entries
        dns_ptr_map = ldap_conn.get_dns_ptr_entries(dhcp_base_dn, dns_base_dn)
        logging.debug('dns_ptr_map = %s', pprint.pformat(dns_ptr_map, indent=2))

        # 2. build mapping FQDN -> ipaddress.IPv4Address instance
        #-------------------------------------------------------------------

        msg_id = ldap_conn.search(
            dhcp_base_dn,
            ldap0.SCOPE_ONELEVEL,
            filterstr='(&(objectClass=dhcpHost)(dhcpStatements=*))',
            attrlist=['cn', 'dhcpStatements', 'dhcpComments'],
        )

        dhcp_host_dn_set = set()

        for ldap_res in ldap_conn.results(msg_id):

            for dhcp_host in ldap_res.rdata:
                dhcp_host_name = dhcp_host.entry_s['cn'][0].lower()
                dhcp_host_ipaddr = ldap_conn.extract_ipaddress(dhcp_host.entry_s)
                ptr_rr = dhcp_host_ipaddr.reverse_pointer
                dc_val = ptr_rr.split('.', 1)[0]
                logging.debug('Found IPv4 address %s in %r', dhcp_host_ipaddr, dhcp_host.dn_s)
                dns_ptr_dn = 'dc=%d,%s' % (int(dc_val), dns_base_dn)
                dhcp_host_dn_set.add(dns_ptr_dn)
                dns_ptr_entry = {
                    'objectClass': ['dNSDomain', 'dNSDomain2', 'domainRelatedObject'],
                    'dc': [dc_val],
                    'associatedDomain': [ptr_rr],
                    'pTRRecord': [dhcp_host_name],
                    'seeAlso': [dhcp_host.dn_s],
                    'description': dhcp_host.entry_s.get('dhcpComments',[]),
                }
                logging.debug('dns_ptr_dn = %r', dns_ptr_dn)
                logging.debug(
                    'dns_ptr_entry = %s',
                    pprint.pformat(dns_ptr_entry, indent=2, width=60)
                )

                if dhcp_host.dn_s in dns_ptr_map:
                    # modify an existing PTR RR entry
                    old_dns_ptr_dn, old_dns_ptr_entry = dns_ptr_map[dhcp_host.dn_s]
                    if old_dns_ptr_dn != dns_ptr_dn:
                        ldap_conn.delete_s(old_dns_ptr_dn)
                        logging.info('Removed PTR RR entry %r', dns_ptr_dn)
                        ldap_conn.add_s(
                            dns_ptr_dn,
                            {
                                at: encode_list(avs)
                                for at, avs in dns_ptr_entry.items()
                            }
                        )
                        logging.info('Added new PTR RR entry %r', dns_ptr_dn)
                    else:
                        logging.debug(
                            'old_dns_ptr_entry = %s',
                            pprint.pformat(old_dns_ptr_entry, indent=2, width=60),
                        )
                        mod_list = ldap0.modlist.modify_modlist(
                            old_dns_ptr_entry,
                            {
                                at: encode_list(avl)
                                for at, avl in dns_ptr_entry.items()
                            }
                        )
                        if mod_list:
                            logging.debug(
                                'Will modify existing PTR RR entry %r : %r',
                                dns_ptr_dn,
                                mod_list,
                            )
                            ldap_conn.modify_s(dns_ptr_dn, mod_list)
                            logging.info(
                                'Modified existing PTR RR entry %r : %r',
                                dns_ptr_dn,
                                mod_list,
                            )
                else:
                    # add new PTR RR entry
                    try:
                        ldap_conn.add_s(
                            dns_ptr_dn,
                            {
                                at: encode_list(avs)
                                for at, avs in dns_ptr_entry.items()
                            }
                        )
                    except LDAPError as err:
                        logging.error(
                            'Error adding new PTR RR entry %r linked to %r: %s',
                            dns_ptr_dn,
                            dhcp_host.dn_s,
                            err,
                        )
                    else:
                        logging.info(
                            'Added new PTR RR entry %r linked to %r',
                            dns_ptr_dn,
                            dhcp_host.dn_s,
                        )
                        # add new PTR entry to map dict for possibly adding A RRs later
                        dns_ptr_map[dhcp_host.dn_s] = (dns_ptr_dn, dns_ptr_entry)

        # remove obsolete PTR RR entries
        for dn, entry in dns_ptr_map.values():
            if 'seeAlso' in entry and dn not in dhcp_host_dn_set:
                ldap_conn.delete_s(dn)
                logging.info('Removed obsolete PTR RR entry %r', dn)

        forward_dns_apex = ldap_conn.get_forward_dns_apex_entries()
        logging.debug('forward_dns_apex = %r', forward_dns_apex)

    # end of main()


if __name__ == '__main__':
    sync_dhcphost_ptr()
