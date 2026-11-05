variable "hosts" {
  type        = any
  description = "Hosts to configure: a map of names to addresses, or to host objects with an address and optional host_key, user, port, private_key_file, jump_hosts or os."

  validation {
    condition     = alltrue([for h in var.hosts : contains(["debian", "ubuntu", "rocky", "almalinux", "rhel", "fedora"], try(h.os, "debian"))])
    error_message = "A host object's os must be one of debian, ubuntu, rocky, almalinux, rhel or fedora. CentOS Linux reached end of life on 30 June 2024: use Rocky Linux."
  }
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "User to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "known_hosts file to check host keys against. When null, ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run commands as root through sudo."
}

variable "base_dn" {
  type        = string
  description = "Base DN of the directory, such as \"dc=example,dc=com\". Its first part must be a dc=, which names the base entry. Set it before the first apply; changing it later isn't applied."

  validation {
    condition     = can(regex("^dc=[A-Za-z0-9-]+(,[A-Za-z]+=[^,=+\"\\\\<>;#\n]+)*$", var.base_dn))
    error_message = "base_dn must be a DN starting with dc=, such as \"dc=example,dc=com\"."
  }
}

variable "organization" {
  type        = string
  default     = null
  description = "o attribute of the base entry. When null, the value of base_dn's first dc."

  validation {
    condition     = var.organization == null || !strcontains(coalesce(var.organization, "-"), "\n")
    error_message = "organization must be on one line."
  }
}

variable "root_dn" {
  type        = string
  default     = null
  description = "DN of the directory's administrator, which slapd lets do anything in base_dn. When null, cn=admin,BASE_DN."

  validation {
    condition     = var.root_dn == null || can(regex("^[A-Za-z]+=[^,=+\"'\\\\<>;#\n]+(,[A-Za-z]+=[^,=+\"'\\\\<>;#\n]+)*$", coalesce(var.root_dn, "-")))
    error_message = "root_dn must be a DN such as \"cn=admin,dc=example,dc=com\", without quotes or backslashes."
  }
}

variable "root_password" {
  type        = string
  ephemeral   = true
  sensitive   = true
  description = "Password of root_dn, at least 8 characters. Pass it at run time with -var or TF_VAR_root_password; it never reaches state or the plan. Changing it sets the new one."

  validation {
    condition     = length(var.root_password) >= 8 && !strcontains(var.root_password, "\n")
    error_message = "root_password must be at least 8 characters, on one line."
  }
}

variable "schemas" {
  type        = list(string)
  default     = ["cosine", "inetorgperson", "nis"]
  description = "Schemas to load, in order, by the name of an LDIF file in slapd's schema directory, such as \"misc\" or \"dyngroup\". core is always loaded. Removing one from the list doesn't unload it."

  validation {
    condition     = alltrue([for s in var.schemas : can(regex("^[a-z0-9_-]+$", s)) && s != "core"])
    error_message = "Each schema is the name of a file in /etc/ldap/schema or /etc/openldap/schema without .ldif, such as \"cosine\". core is always loaded."
  }
}

variable "ous" {
  type        = list(string)
  default     = ["people", "groups"]
  description = "Organizational units to create directly under base_dn, such as [\"people\", \"groups\"]. Each is added if it's missing; removing one from the list doesn't delete it."

  validation {
    condition     = alltrue([for ou in var.ous : can(regex("^[A-Za-z0-9][A-Za-z0-9 _.-]*$", ou))])
    error_message = "Each OU name may use letters, digits, spaces, _, . and -."
  }
}

variable "entries_ldif" {
  type        = string
  default     = null
  description = "LDIF of more entries to add, such as file(\"people.ldif\"). Each entry is added if it's missing, and existing entries are left as they are."
}

variable "ldap_address" {
  type        = string
  default     = "127.0.0.1"
  description = "Address slapd listens on for LDAP, and LDAPS when it's on. The default keeps it to the host itself; \"0.0.0.0\" listens on every address."

  validation {
    condition     = can(cidrhost("${var.ldap_address}/${strcontains(var.ldap_address, ":") ? 128 : 32}", 0))
    error_message = "ldap_address must be an IP address, such as \"127.0.0.1\" or \"0.0.0.0\"."
  }
}

variable "ldap_port" {
  type        = number
  default     = 389
  description = "Port of the LDAP listener."

  validation {
    condition     = var.ldap_port >= 1 && var.ldap_port <= 65535 && floor(var.ldap_port) == var.ldap_port
    error_message = "ldap_port must be a port number from 1 to 65535."
  }
}

variable "ldaps_port" {
  type        = number
  default     = 636
  description = "Port of the LDAPS listener, when TLS is on."

  validation {
    condition     = var.ldaps_port >= 1 && var.ldaps_port <= 65535 && floor(var.ldaps_port) == var.ldaps_port
    error_message = "ldaps_port must be a port number from 1 to 65535."
  }
}

variable "tls_cert_file" {
  type        = string
  default     = null
  description = "Path on the host of a PEM certificate, with its chain. With tls_key_file, turns on LDAPS and StartTLS. slapd's user must be able to read it."

  validation {
    condition     = var.tls_cert_file == null || startswith(coalesce(var.tls_cert_file, "-"), "/") && !strcontains(coalesce(var.tls_cert_file, "-"), "\n")
    error_message = "tls_cert_file must be an absolute path."
  }

  validation {
    condition     = (var.tls_cert_file == null) == (var.tls_key_file == null)
    error_message = "Set tls_cert_file and tls_key_file together."
  }
}

variable "tls_key_file" {
  type        = string
  default     = null
  description = "Path on the host of the PEM private key for tls_cert_file. slapd's user must be able to read it."

  validation {
    condition     = var.tls_key_file == null || startswith(coalesce(var.tls_key_file, "-"), "/") && !strcontains(coalesce(var.tls_key_file, "-"), "\n")
    error_message = "tls_key_file must be an absolute path."
  }
}

variable "allow_anonymous" {
  type        = bool
  default     = false
  description = "Let clients search the directory without binding. Off by default: slapd refuses anonymous binds and asks every operation to authenticate first."
}
