variable "port" {
  type    = number
  default = 2311
}

# Pass it at run time, such as with TF_VAR_root_password.
variable "root_password" {
  type      = string
  ephemeral = true
  sensitive = true
}

module "openldap" {
  source = "../.."

  hosts                = { box = "127.0.0.1" }
  ssh_port             = var.port
  ssh_private_key_file = "./id_ed25519"
  ssh_known_hosts_file = "./known_hosts"

  base_dn       = "dc=example,dc=test"
  organization  = "Example"
  root_password = var.root_password

  # Added once, if missing. Your own LDIF file works the same way, with
  # entries_ldif = file("people.ldif").
  entries_ldif = <<-EOT
    dn: uid=ada,ou=people,dc=example,dc=test
    objectClass: inetOrgPerson
    objectClass: posixAccount
    uid: ada
    cn: Ada Lovelace
    sn: Lovelace
    mail: ada@example.test
    uidNumber: 10000
    gidNumber: 10000
    homeDirectory: /home/ada

    dn: cn=engineers,ou=groups,dc=example,dc=test
    objectClass: groupOfNames
    cn: engineers
    member: uid=ada,ou=people,dc=example,dc=test
  EOT
}

output "root_dn" {
  value = module.openldap.root_dn
}
