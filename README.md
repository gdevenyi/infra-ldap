infra-ldap
==========

Tools for maintaining DNS and DHCP entries in LDAP.

Create DNS PTR RRs from _dhcpHost_ entries:

```
python3 -m infraldap.dhcphostptr 'ldapi:///dc=example,dc=org'
```
