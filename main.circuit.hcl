# Facts give each host's distribution. Debian and Ubuntu ship slapd;
# Fedora ships openldap-servers; Rocky Linux and AlmaLinux get it from
# EPEL. The two families keep slapd's files in different places.
data "conn3x_host" "facts" {
  for_each = var.hosts

  ssh {
    host             = try(each.value.address, each.value)
    host_key         = try(each.value.host_key, null)
    user             = try(each.value.user, var.ssh_user)
    port             = try(each.value.port, var.ssh_port)
    private_key_file = try(each.value.private_key_file, var.ssh_private_key_file)
    jump_hosts       = try(each.value.jump_hosts, null)
    known_hosts_file = var.ssh_known_hosts_file
  }

  lifecycle {
    postcondition {
      condition     = try(each.value.os, self.os_id) == self.os_id
      error_message = "Host ${each.key} is ${self.os_id}, not the ${try(each.value.os, "")} its os says."
    }
  }
}

locals {
  # A host object's os stands in for the facts of a host created in the
  # same plan, which can't be read until it exists.
  os     = { for name, h in var.hosts : name => try(h.os, data.conn3x_host.facts[name].os_id) }
  debian = { for name, o in local.os : name => contains(["debian", "ubuntu"], o) }

  # Debian 13 ships a native unit for slapd; Debian 12 and Ubuntu don't.
  init_script = { for name, o in local.os : name => o == "ubuntu" || (o == "debian" && data.conn3x_host.facts[name].os_version == "12") }

  debian_hosts = { for name, h in var.hosts : name => h if local.debian[name] }

  # Rocky Linux and AlmaLinux ship epel-release in their own extras
  # repository. RHEL doesn't, so EPEL has to be on there already.
  epel_hosts = { for name, h in var.hosts : name => h if contains(["rocky", "almalinux"], local.os[name]) }

  packages = { for name, d in local.debian : name => d ? { server = "slapd", clients = "ldap-utils" } : { server = "openldap-servers", clients = "openldap-clients" } }

  # Where each family keeps slapd's config, schemas, modules and run files,
  # and the user slapd runs as.
  paths = { for name, d in local.debian : name => d ? {
    etc     = "/etc/ldap"
    modules = "/usr/lib/ldap"
    run     = "/run/slapd"
    user    = "openldap"
    } : {
    etc     = "/etc/openldap"
    modules = "/usr/lib64/openldap"
    run     = "/run/openldap"
    user    = "ldap"
  } }

  data_dir = "/var/lib/ldap"
  root_dn  = coalesce(var.root_dn, "cn=admin,${var.base_dn}")

  # EPEL's openldap-servers is built without the argon2 module, so the Red
  # Hat rebuilds hash the root password with salted SHA-1 instead.
  argon2 = { for name, o in local.os : name => !contains(["rocky", "almalinux", "rhel"], o) }

  # Debian builds the mdb backend as a module; Fedora and EPEL build it in.
  modules = { for name, d in local.debian : name => concat(d ? ["back_mdb"] : [], local.argon2[name] ? ["argon2"] : []) }

  tls = var.tls_cert_file != null

  host = lookup({ "0.0.0.0" = "", "::" = "[::]" }, var.ldap_address, strcontains(var.ldap_address, ":") ? "[${var.ldap_address}]" : var.ldap_address)
  urls = join(" ", concat(
    ["ldap://${local.host}:${var.ldap_port}/", "ldapi:///"],
    local.tls ? ["ldaps://${local.host}:${var.ldaps_port}/"] : [],
  ))

  # Debian's unit and Ubuntu's init script read the addresses from
  # /etc/default/slapd. The Red Hat unit names them on its command line.
  listen_file = { for name, d in local.debian : name => d ? <<-EOT
    # Written by Conn3x. Changes here are overwritten on the next apply.
    SLAPD_CONF=
    SLAPD_USER="openldap"
    SLAPD_GROUP="openldap"
    SLAPD_PIDFILE=
    SLAPD_SERVICES="${local.urls}"
    SLAPD_SENTINEL_FILE=/etc/ldap/noslapd
    SLAPD_OPTIONS=""
    EOT
    : <<-EOT
    # Written by Conn3x. Changes here are overwritten on the next apply.
    [Service]
    ExecStart=
    ExecStart=/usr/sbin/slapd -u ldap -h "${local.urls}"
    EOT
  }

  # The first RDN's value names the base entry's dc and, by default, its o.
  base_dc = regex("^dc=([^,]+)", var.base_dn)[0]

  # The starting cn=config, loaded once with slapadd. Root over ldapi:///
  # manages cn=config; everything the circuit changes later goes through
  # settings_ldif instead.
  bootstrap_ldif = { for name, p in local.paths : name => join("\n", compact([
    <<-EOT
    # Written by Conn3x, which loads it once into an empty slapd.d.
    dn: cn=config
    objectClass: olcGlobal
    cn: config
    olcArgsFile: ${p.run}/slapd.args
    olcPidFile: ${p.run}/slapd.pid
    EOT
    ,
    length(local.modules[name]) == 0 ? "" : <<-EOT
    dn: cn=module{0},cn=config
    objectClass: olcModuleList
    cn: module{0}
    olcModulePath: ${p.modules}
    ${join("\n", [for m in local.modules[name] : "olcModuleLoad: ${m}"])}
    EOT
    ,
    <<-EOT
    dn: cn=schema,cn=config
    objectClass: olcSchemaConfig
    cn: schema

    include: file://${p.etc}/schema/core.ldif

    dn: olcDatabase={-1}frontend,cn=config
    objectClass: olcDatabaseConfig
    objectClass: olcFrontendConfig
    olcDatabase: {-1}frontend

    dn: olcDatabase={0}config,cn=config
    objectClass: olcDatabaseConfig
    olcDatabase: {0}config
    olcAccess: {0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * none

    dn: olcDatabase={1}mdb,cn=config
    objectClass: olcDatabaseConfig
    objectClass: olcMdbConfig
    olcDatabase: {1}mdb
    olcDbDirectory: ${local.data_dir}
    olcSuffix: ${var.base_dn}
    olcRootDN: ${local.root_dn}
    olcDbMaxSize: 1073741824
    olcDbIndex: objectClass eq
    olcDbIndex: cn,uid,member eq
    EOT
  ])) }

  # Applied with ldapmodify whenever it changes. cn=config refuses to
  # replace or delete an attribute that isn't there, so the attributes to
  # clear are listed apart, and removed only when present.
  settings_ldif = <<-EOT
    # Written by Conn3x. Changes here are overwritten on the next apply.
    dn: olcDatabase={1}mdb,cn=config
    changetype: modify
    replace: olcRootDN
    olcRootDN: ${local.root_dn}
    -
    replace: olcAccess
    olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
    olcAccess: {1}to * by self read by ${var.allow_anonymous ? "*" : "users"} read
    -
    ${join("\n", local.global_set)}
  EOT

  global = merge(
    var.allow_anonymous ? {} : { olcDisallows = "bind_anon", olcRequires = "authc" },
    local.tls ? { olcTLSCertificateFile = var.tls_cert_file, olcTLSCertificateKeyFile = var.tls_key_file, olcTLSProtocolMin = "3.3" } : {},
  )
  global_clear = setsubtract(["olcDisallows", "olcRequires", "olcTLSCertificateFile", "olcTLSCertificateKeyFile", "olcTLSProtocolMin"], keys(local.global))
  global_set = length(local.global) == 0 ? [] : concat(
    ["", "dn: cn=config", "changetype: modify"],
    flatten([for k, v in local.global : ["replace: ${k}", "${k}: ${v}", "-"]]),
  )

  # The base entry, the OUs, then your entries. Each is added only if it's
  # missing, so later applies leave existing entries alone.
  entries_ldif = join("\n", concat(
    [<<-EOT
    # Written by Conn3x, which adds each entry that's missing.
    dn: ${var.base_dn}
    objectClass: dcObject
    objectClass: organization
    dc: ${local.base_dc}
    o: ${coalesce(var.organization, local.base_dc)}
    EOT
    ],
    [for ou in var.ous : <<-EOT
    dn: ou=${ou},${var.base_dn}
    objectClass: organizationalUnit
    ou: ${ou}
    EOT
    ],
    var.entries_ldif == null ? [] : ["${trimspace(var.entries_ldif)}\n"],
  ))
}

circuit "epel" {
  hosts = local.epel_hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "release" {
    package {
      name = "epel-release"
    }
  }
}

# Tells Debian's slapd package not to build a directory of its own on
# install, which the circuit would only have to take apart again.
circuit "preseed" {
  hosts = local.debian_hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "no_configuration" {
    command {
      command = "echo 'slapd slapd/no_configuration boolean true' | debconf-set-selections"
      unless  = "test -x /usr/sbin/slapd || debconf-show slapd 2>/dev/null | grep -q 'no_configuration: true'"
    }
  }
}

circuit "openldap" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "packages" {
    depends_on = [conn3x_package.epel__release, conn3x_command.preseed__no_configuration]
    for_each   = toset(["server", "clients"])
    package {
      name = local.packages[each.key][item.key]
    }
  }

  # Holds what Conn3x writes for slapd, the root password among it, so only
  # root can read it.
  step "conn3x_dir" {
    directory {
      path  = "${local.paths[each.key].etc}/conn3x"
      owner = "root"
      group = "root"
      mode  = "0700"
    }
  }

  step "bootstrap_ldif" {
    file {
      path    = "${local.paths[each.key].etc}/conn3x/bootstrap.ldif"
      content = local.bootstrap_ldif[each.key]
      mode    = "0600"
    }
  }

  # Runs once. It replaces whatever cn=config the package left, such as
  # Fedora's dc=my-domain example, but refuses to touch a slapd that
  # already holds data.
  step "bootstrap" {
    command {
      command = <<-EOT
        set -e
        if [ -e ${local.data_dir}/data.mdb ]; then
          echo "${local.data_dir}/data.mdb exists: this slapd already has a directory, and the circuit only sets up a new one. Move ${local.data_dir} aside first if you mean to replace it." >&2
          exit 1
        fi
        systemctl stop slapd 2>/dev/null || true
        rm -rf ${local.paths[each.key].etc}/slapd.d
        mkdir -m 0750 ${local.paths[each.key].etc}/slapd.d
        slapadd -q -n 0 -F ${local.paths[each.key].etc}/slapd.d -l ${local.paths[each.key].etc}/conn3x/bootstrap.ldif
        chown -R ${local.paths[each.key].user}:${local.paths[each.key].user} ${local.paths[each.key].etc}/slapd.d ${local.data_dir}
        chmod 0700 ${local.data_dir}
        if command -v restorecon >/dev/null; then restorecon -R ${local.paths[each.key].etc}/slapd.d ${local.data_dir}; fi
        touch ${local.paths[each.key].etc}/conn3x/bootstrapped
      EOT
      creates = "${local.paths[each.key].etc}/conn3x/bootstrapped"
    }
  }

  step "listen" {
    file {
      path    = local.debian[each.key] ? "/etc/default/slapd" : "/etc/systemd/system/slapd.service.d/conn3x.conf"
      content = local.listen_file[each.key]
    }
  }

  # A step rather than a handler, so the steps below talk to the slapd
  # that listens where the file says.
  step "restart" {
    command {
      command = "systemctl daemon-reload && systemctl restart slapd"
      triggers = {
        bootstrap = conn3x_command.openldap__bootstrap[each.key].revision
        listen    = conn3x_file.openldap__listen[each.key].revision
      }
    }
  }

  # Ubuntu 24.04 and Debian 12 still run slapd from an init script, which
  # the package links into the runlevels. systemd reports that unit as
  # generated rather than enabled, so Conn3x leaves its boot setting alone
  # there.
  step "running" {
    service {
      name    = "slapd"
      state   = "started"
      enabled = local.init_script[each.key] ? null : true
    }
  }

  # unless is checked at plan time, before the restart, so the restart's
  # revision makes the apply check again.
  step "ready" {
    command {
      command  = "for _ in $(seq 60); do ldapwhoami -Q -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1"
      unless   = "ldapwhoami -Q -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1"
      triggers = { restart = conn3x_command.openldap__restart[each.key].revision }
    }
  }

  step "settings_ldif" {
    file {
      path    = "${local.paths[each.key].etc}/conn3x/settings.ldif"
      content = local.settings_ldif
      mode    = "0600"
    }
  }

  step "settings" {
    command {
      command = <<-EOT
        set -e
        ldapmodify -Q -Y EXTERNAL -H ldapi:/// -f ${local.paths[each.key].etc}/conn3x/settings.ldif >/dev/null
        clear=""
        for a in ${join(" ", local.global_clear)}; do
          if ldapsearch -Q -LLL -Y EXTERNAL -H ldapi:/// -b cn=config -s base "$a" | grep -q "^$a:"; then clear="$clear $a"; fi
        done
        # slapd refuses to drop its TLS key while it runs, so whatever has
        # to go is removed with slapd stopped.
        if [ -n "$clear" ]; then
          { printf 'dn: cn=config\nchangetype: modify\n'; for a in $clear; do printf 'delete: %s\n-\n' "$a"; done; } > ${local.paths[each.key].etc}/conn3x/clear.ldif
          systemctl stop slapd
          rc=0
          slapmodify -q -n 0 -F ${local.paths[each.key].etc}/slapd.d -l ${local.paths[each.key].etc}/conn3x/clear.ldif || rc=$?
          chown -R ${local.paths[each.key].user}:${local.paths[each.key].user} ${local.paths[each.key].etc}/slapd.d
          rm -f ${local.paths[each.key].etc}/conn3x/clear.ldif
          systemctl start slapd
          for _ in $(seq 60); do ldapwhoami -Q -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 && break; sleep 1; done
          exit $rc
        fi
      EOT
      triggers = {
        bootstrap = conn3x_command.openldap__bootstrap[each.key].revision
        settings  = conn3x_file.openldap__settings_ldif[each.key].revision
      }
    }
  }

  # Write-only: the plan and state record only an HMAC of the content.
  step "root_password" {
    file {
      path       = "${local.paths[each.key].etc}/conn3x/root_password"
      content_wo = var.root_password
      owner      = "root"
      group      = "root"
      mode       = "0600"
    }
  }

  # slapd keeps only the hash. It reaches ldapmodify on stdin, so it never
  # shows in ps or in the step's output.
  step "root_password_hash" {
    command {
      command = <<-EOT
        set -e
        hash=$(slappasswd ${local.argon2[each.key] ? "-o module-path=${local.paths[each.key].modules} -o module-load=argon2 -h '{ARGON2}'" : "-h '{SSHA}'"} -T ${local.paths[each.key].etc}/conn3x/root_password)
        printf 'dn: olcDatabase={1}mdb,cn=config\nchangetype: modify\nreplace: olcRootPW\nolcRootPW: %s\n' "$hash" | ldapmodify -Q -Y EXTERNAL -H ldapi:/// >/dev/null
      EOT
      triggers = {
        bootstrap = conn3x_command.openldap__bootstrap[each.key].revision
        password  = conn3x_file.openldap__root_password[each.key].revision
      }
    }
  }

  # In list order, since inetorgperson needs cosine. cn=schema names each
  # one {N}NAME.
  step "schemas" {
    command {
      command = join("\n", concat(["set -e"], [for s in var.schemas : "ldapsearch -Q -LLL -Y EXTERNAL -H ldapi:/// -b cn=schema,cn=config -s one '(cn=*}${s})' dn | grep -q . || ldapadd -Q -Y EXTERNAL -H ldapi:/// -f ${local.paths[each.key].etc}/schema/${s}.ldif >/dev/null"]))
      unless  = join(" && ", concat(["true"], [for s in var.schemas : "ldapsearch -Q -LLL -Y EXTERNAL -H ldapi:/// -b cn=schema,cn=config -s one '(cn=*}${s})' dn 2>/dev/null | grep -q ."]))
    }
  }

  step "entries_ldif" {
    file {
      path    = "${local.paths[each.key].etc}/conn3x/entries.ldif"
      content = local.entries_ldif
      mode    = "0600"
    }
  }

  # ldapadd -c carries on past entries that already exist and writes every
  # entry it skipped to the reject file, with the reason. Anything other
  # than "Already exists" fails the step.
  step "entries" {
    command {
      command = <<-EOT
        set -e
        dir=${local.paths[each.key].etc}/conn3x
        ldapwhoami -x -H ldapi:/// -D '${local.root_dn}' -y $dir/root_password >/dev/null
        rej=$(mktemp)
        trap 'rm -f "$rej"' EXIT
        ldapadd -c -x -H ldapi:/// -D '${local.root_dn}' -y $dir/root_password -S "$rej" -f $dir/entries.ldif >/dev/null 2>&1 || true
        if grep '^# Error: ' "$rej" | grep -qv 'Already exists (68)'; then
          cat "$rej" >&2
          exit 1
        fi
      EOT
      triggers = {
        bootstrap = conn3x_command.openldap__bootstrap[each.key].revision
        entries   = conn3x_file.openldap__entries_ldif[each.key].revision
        schemas   = join(",", var.schemas)
      }
    }
  }
}
