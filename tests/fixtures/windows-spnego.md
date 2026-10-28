# Windows SPNEGO captures

These unmodified initial tokens are public interoperability fixtures, not usable
service credentials. No capture keys are available. Tests first extract the
original AP-REQ unchanged, then substitute a test-key AP-REQ without changing the
offer, token OID or absent MIC to verify full acceptance and both reply OIDs.

- `win2019_sspi_init.b64`: client NegTokenInit RawData from
  [pyspnego's Windows Server 2019 SSPI SMB scenario](https://github.com/jborean93/pyspnego/blob/master/docs/scenarios/sspi_kerberos_in_smb_spnego.md).
- `ldap_sspi_init.b64`: SPNEGO blob from
  [PcapPlusPlus ldap_bind_request2.dat](https://github.com/seladb/PcapPlusPlus/blob/master/Tests/Packet++Test/PacketExamples/ldap_bind_request2.dat).
