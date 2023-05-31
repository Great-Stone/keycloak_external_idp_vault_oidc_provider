output "client_id" {
  value = vault_identity_oidc_client.keycloak.client_id
}

// output "client_secret" {
//   value = nonsensitive(vault_identity_oidc_client.keycloak.client_secret)
// }

output "wellknown_openid_configurationest" {
  value = local.issuer_data
}