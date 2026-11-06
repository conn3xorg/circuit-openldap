# circuit-openldap

[![Conn3x grade](https://conn3x.org/circuits/openldap/grade.svg)](https://conn3x.org/circuits/openldap/grade)

A Conn3x circuit that runs [OpenLDAP](https://www.openldap.org)'s `slapd`, the LDAP server most other directories get measured against. You give it a base DN and a root password; it installs slapd from your distribution, builds its `cn=config` from scratch, loads the schemas you list, creates your OUs and adds entries from an LDIF you pass in. Then you point SSSD, Postfix, Nextcloud, Keycloak or anything else that speaks LDAP at it.

Out of the box slapd listens only on `127.0.0.1:389`, plus a local `ldapi:///` socket that root manages `cn=config` through. Anonymous binds are refused and every operation has to authenticate first, so nobody reads your directory without a password. Hand it a certificate and key, from [circuit-certbot](https://github.com/conn3xorg/circuit-certbot) or your own CA, and it serves LDAPS and StartTLS too.

The root password never reaches the plan or state. It lands on the host in a root-only file, and slapd itself keeps only an Argon2 hash of it, or a salted SHA-1 one where the build has no Argon2 module.

## OpenLDAP or LLDAP?

Both circuits give you a directory your services can sign people in against. They suit different jobs.

Pick [circuit-lldap](https://github.com/conn3xorg/circuit-lldap) when you want users and groups for a homelab or a small team, managed from a web page. LLDAP has a fixed layout, `ou=people` and `ou=groups`, and doesn't take custom schemas or arbitrary entries. In return there's nothing to learn.

Pick this one when you need LDAP itself: your own schemas, POSIX accounts for SSSD logins, a tree laid out the way an existing app expects, or LDIF you already have. There's no web interface; you manage entries with `ldapadd` and `ldapmodify`, or with an LDIF that the circuit adds for you.

If what you need is Kerberos, host enrolment and sudo rules on top, that's FreeIPA rather than either of these.

## Usage

```hcl
variable "ldap_root_password" {
  type      = string
  ephemeral = true
  sensitive = true
}

module "openldap" {
  source = "github.com/conn3xorg/circuit-openldap?ref=v0.2.1"

  hosts                = { ldap1 = "203.0.113.10" }
  ssh_private_key_file = "~/.ssh/id_ed25519"

  base_dn       = "dc=example,dc=com"
  organization  = "Example Ltd"
  root_password = var.ldap_root_password
  entries_ldif  = file("people.ldif")
}
```

Then run `conn3x init` and `conn3x apply`, with the password in `TF_VAR_ldap_root_password`. A second `conn3x plan` says `No changes.`

The administrator binds as `cn=admin,dc=example,dc=com`, the `root_dn` output. It can do anything in the directory, so give the services that only read it an account of their own: add one in your LDIF and bind as that. Any user who binds can read the tree, except passwords.

When your services run on other hosts, set `ldap_address = "0.0.0.0"` and open the port to them only, ideally with TLS on.

For hosts created in the same plan, pass host objects with the host key you generated and the distribution in `os`, such as `os = "ubuntu"`, as in [circuit-fail2ban](https://github.com/conn3xorg/circuit-fail2ban#usage). The circuit picks its packages and paths by distribution.

To try it on a throwaway container first, see [examples/local](examples/local).

### Entries from LDIF

`entries_ldif` takes plain LDIF, such as:

```ldif
dn: uid=ada,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
uid: ada
cn: Ada Lovelace
sn: Lovelace
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/ada
userPassword: {ARGON2}$argon2id$v=19$m=65536,t=2,p=1$...
```

Each entry is added if it isn't there and left alone if it is, so the LDIF is a starting point rather than the truth: change a person's mail in the directory and the next apply won't put the old one back. The circuit adds missing entries whenever the LDIF changes, the schema list changes or the directory is new. An entry you delete by hand comes back only on the next of those.

Hash `userPassword` values before they go in, with `slappasswd`, or leave them out and set passwords with `ldappasswd` afterwards. A plain password in the LDIF would sit in the plan and state.

### TLS

Point `tls_cert_file` and `tls_key_file` at a PEM certificate, with its chain, and key already on the host, and slapd serves LDAPS on `ldaps_port`, 636 by default, and StartTLS on the plain port. slapd runs as `openldap` on Debian and Ubuntu and `ldap` on Rocky Linux, and that user must be able to read both files.

```hcl
module "openldap" {
  # ...
  ldap_address  = "0.0.0.0"
  tls_cert_file = "/etc/ssl/ldap/fullchain.pem"
  tls_key_file  = "/etc/ssl/ldap/privkey.pem"
}
```

slapd reads the files when TLS is set and when it starts, so restart it after a renewal: `systemctl restart slapd`, from certbot's deploy hook for instance. The minimum protocol is TLS 1.2.

Turning TLS off again needs slapd stopped for a moment, since it won't drop its key while it runs. The apply does that for you.

## What it does

On each host, in order:

1. On Rocky Linux and AlmaLinux, installs `epel-release`, which turns on EPEL: Red Hat dropped `openldap-servers` from RHEL 8 onwards, and EPEL 9 and 10 carry it again. On RHEL, turn EPEL on yourself first. On Debian and Ubuntu, preseeds debconf with `slapd/no_configuration`, so the package doesn't build a directory of its own on install.
2. Installs `slapd` and `ldap-utils`, or `openldap-servers` and `openldap-clients`.
3. Writes a starting `cn=config` to `/etc/ldap/conn3x/bootstrap.ldif` (`/etc/openldap/conn3x` on Rocky Linux) and loads it once with `slapadd` into a fresh `slapd.d`: the core schema, a config database that root manages over `ldapi:///`, and an mdb database for `base_dn` in `/var/lib/ldap`, capped at 1 GiB. Whatever `slapd.d` the package left is replaced. If `/var/lib/ldap` already holds a database, the apply stops here rather than touch it.
4. Writes the addresses to listen on, to `/etc/default/slapd` on Debian and Ubuntu or a drop-in for `slapd.service` on Rocky Linux, restarts slapd when they change, starts it now and at boot, and waits for `ldapi:///` to answer.
5. Applies the settings with `ldapmodify`: the root DN, the access rules, refusing anonymous binds, and TLS. Settings the circuit no longer sets are removed.
6. Writes `root_password` to a root-only, write-only file, hashes it with `slappasswd` and sets the hash as `olcRootPW`. This runs again only when the password changes.
7. Loads each of `schemas` that isn't loaded yet, in list order, from the distribution's schema directory.
8. Adds the base entry, then one entry per OU in `ous`, then your `entries_ldif`, each only if it's missing. It binds as the root DN to do it.

The access rules let a user change their own password, let anyone bind to check one, and let any user who has bound read everything else. `allow_anonymous = true` lets clients search without binding as well.

### What it doesn't do

- It doesn't set up replication, overlays such as memberof or ppolicy, or a cn=config password. Add those yourself over `ldapi:///` as root: `ldapmodify -Y EXTERNAL -H ldapi:///`. The circuit leaves alone anything it doesn't set.
- Changing `base_dn` after the first apply isn't applied. Pick it before the first apply; moving a directory to a new suffix means exporting with `slapcat` and loading the result.
- Removing a schema from `schemas`, an OU from `ous` or an entry from `entries_ldif` doesn't delete it from the directory.
- It doesn't open a firewall port. Use [circuit-firewall](https://github.com/conn3xorg/circuit-firewall).
- It doesn't take backups. `slapcat -n 1` dumps the directory as LDIF while slapd runs, and `slapcat -n 0` dumps `cn=config`.
- Deleting the module leaves slapd installed and running, with its data.

## Inputs

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `hosts` | any | Required | Hosts to configure, by name. Each value is an address, such as `"203.0.113.10"`, or a host object such as `{ address = "203.0.113.10", host_key = "ssh-ed25519 AAAA..." }`. A host object can also set `user`, `port`, `private_key_file`, `jump_hosts` and `os`, the distribution's ID, such as `ubuntu` or `rocky`, which a host created in the same plan needs. The two forms can be mixed. |
| `ssh_user` | string | `"root"` | User to log in as. |
| `ssh_port` | number | `22` | SSH port. |
| `ssh_private_key_file` | string | `null` | Path to a private key. When null, Conn3x uses the SSH agent. |
| `ssh_known_hosts_file` | string | `null` | known_hosts file to check host keys against. When null, `~/.ssh/known_hosts`. Not used for a host object with `host_key`. |
| `ssh_become` | bool | `false` | Run commands as root through sudo. Set it when `ssh_user` isn't root. |
| `base_dn` | string | Required | Base DN of the directory, starting with `dc=`, such as `"dc=example,dc=com"`. You don't need to own the domain. |
| `organization` | string | `null` | `o` of the base entry. When null, the first `dc` value. |
| `root_dn` | string | `null` | DN of the administrator. When null, `cn=admin,BASE_DN`. |
| `root_password` | string | Required | Password of `root_dn`, at least 8 characters. Sensitive and ephemeral, and kept out of state. Changing it sets the new one. |
| `schemas` | list(string) | `["cosine", "inetorgperson", "nis"]` | Schemas to load in order, by file name in slapd's schema directory without `.ldif`. `core` is always loaded. |
| `ous` | list(string) | `["people", "groups"]` | Organizational units to create under `base_dn`. |
| `entries_ldif` | string | `null` | LDIF of more entries to add when they're missing, such as `file("people.ldif")`. |
| `ldap_address` | string | `"127.0.0.1"` | Address slapd listens on for LDAP, and LDAPS when TLS is on. `"0.0.0.0"` listens on every address. |
| `ldap_port` | number | `389` | Port of the LDAP listener. |
| `ldaps_port` | number | `636` | Port of the LDAPS listener, when TLS is on. |
| `tls_cert_file` | string | `null` | Path on the host of a PEM certificate. Set with `tls_key_file` to turn on LDAPS and StartTLS. |
| `tls_key_file` | string | `null` | Path on the host of the certificate's PEM private key. |
| `allow_anonymous` | bool | `false` | Let clients bind anonymously and search without a password. |

## Outputs

| Name | Description |
| --- | --- |
| `base_dn` | Base DN of the directory. |
| `root_dn` | DN the administrator binds as, such as `cn=admin,dc=example,dc=com`. |

## Requirements

Requires Conn3x v0.6.9 or later and systemd on each host, with a package mirror the host can reach. On Rocky Linux and AlmaLinux, the host also needs to reach EPEL's mirrors; on RHEL, EPEL must already be on.

### Fedora

Fedora isn't supported for now. Its `openldap-servers`, 2.6.14 on Fedora 45 and 2.6.15 on Fedora 44, can't load its own core schema: `slapadd` stops at `cn={0}core` with `olcAttributeTypes: Unexpected token before MUST c MAY ( searchGuide $ description ) )`, and that happens with the package's default config as well as this circuit's, on amd64 and arm64. This was the case on 29 October 2026, including Fedora 45's updates-testing build. Rocky Linux's 2.6.10 from EPEL and Debian's and Ubuntu's 2.6.10 load it fine.

## Tested on

Rocky Linux 10 and 9, Ubuntu 24.04, and Debian 13 and 12. CI applies [examples/local](examples/local) to each on amd64 and checks that the second plan has no changes. Then `ldapsearch` binds as the root DN and finds the base entry, `ou=people`, and the person and group from the example's LDIF; an anonymous search and a wrong password are both refused; and `cn=config` holds a hash of the root password, never the password. The container restarts, and the same checks pass again. Then, on a fresh host, v0.2.0 is applied and this version over it, the plan has no changes and the checks pass once more; Debian 12 skips that, since v0.2.0 couldn't start slapd there. The same checks passed on arm64 containers of Rocky Linux 10, Ubuntu 24.04 and Debian 13 by hand. On 6 November 2026, by hand on arm64, the apply, the clean plan and the searches passed on Rocky Linux 9 and Debian 12, and on Debian 12 they passed again after a restart. On Debian 13, a second apply with a new root password made the new one bind and the old one fail, and the plan after it had no changes.

By hand, on Debian 13 in a container, a self-signed certificate turned on LDAPS on port 636 and StartTLS on 389, `ldapwhoami` bound over both, and the plan had no changes. Taking TLS away again removed the settings and the LDAPS listener, and the plan after that had no changes either.

On an Ubuntu 24.04 droplet and a Rocky Linux 10 droplet with SELinux enforcing, both with 1 vCPU and 1 GB of memory, the same checks passed. On Ubuntu, slapd ran under its AppArmor profile in enforce mode; on Rocky Linux, it ran confined as `slapd_t`. Neither logged a denial. After a reboot both came back with their data, and the plan had no changes.

## License

MPL-2.0. See [LICENSE](LICENSE). OpenLDAP itself is under the OpenLDAP Public License.
