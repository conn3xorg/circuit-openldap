output "base_dn" {
  description = "Base DN of the directory."
  value       = var.base_dn
}

output "root_dn" {
  description = "DN the administrator binds as."
  value       = coalesce(var.root_dn, "cn=admin,${var.base_dn}")
}
