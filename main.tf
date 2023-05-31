terraform {
  required_version = ">= 1.0"

  required_providers {
    vault = {
      source = "hashicorp/vault"
    }
    keycloak = {
      source  = "mrparkers/keycloak"
      version = ">= 2.0.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "3.3.0"
    }
  }
}

locals {
  vault_root_token  = "root"
  keycloak_user     = "admin"
  keycloak_password = "admin"
  keycloak_oidc_alias = "vault"
}

provider "vault" {
  address = var.vault_url
  token   = local.vault_root_token
}

provider "keycloak" {
  client_id = "admin-cli"
  username  = local.keycloak_user
  password  = local.keycloak_password
  url       = "http://${var.keycloak_addr}:8080"
}

// Configure Vault authentication
resource "vault_auth_backend" "userpass" {
  type = "userpass"

  tune {
    max_lease_ttl = "90000s"
  }
}

locals {
  users = [
    "user1",
    "user2"
  ]
  password = "password"
}

resource "vault_generic_endpoint" "userpass" {
  for_each             = toset(local.users)
  path                 = "auth/${vault_auth_backend.userpass.path}/users/${each.key}"
  ignore_absent_fields = true

  data_json = <<EOT
{
  "password": "${local.password}"
}
EOT
}

// Create Vault identity entity and group
resource "vault_identity_entity" "userpass" {
  depends_on = [
    vault_generic_endpoint.userpass
  ]
  for_each = toset(local.users)
  name     = each.key
  policies = ["default"]
  metadata = {
    email        = "${each.key}@vault.com"
    phone_number = "123-456-7890"
  }
  disabled = false
}

resource "vault_identity_group" "userpass" {
  name     = "internal"
  type     = "internal"
  policies = ["default"]

  metadata = {
    version = "1"
  }

  member_entity_ids = [for k, v in vault_identity_entity.userpass : v.id]
}

resource "vault_identity_entity_alias" "userpass" {
  for_each       = toset(local.users)
  name           = each.key
  canonical_id   = vault_identity_entity.userpass[each.key].id
  mount_accessor = vault_auth_backend.userpass.accessor
}

// Create a Vault OIDC client
resource "vault_identity_oidc_assignment" "keycloak" {
  name       = "my-assignment"
  entity_ids = [for k, v in vault_identity_entity.userpass : v.id]
  group_ids = [
    vault_identity_group.userpass.id,
  ]
}

resource "vault_identity_oidc_key" "keycloak" {
  name               = "my-key"
  algorithm          = "RS256"
  rotation_period    = 3600
  verification_ttl   = 7200
  allowed_client_ids = ["*"]
}

resource "vault_identity_oidc_client" "keycloak" {
  name = "keycloak"
  redirect_uris = [
    "http://localhost:8080/realms/${keycloak_realm.vault.realm}/broker/${local.keycloak_oidc_alias}/endpoint"
  ]
  assignments = [
    vault_identity_oidc_assignment.keycloak.name
  ]
  key              = vault_identity_oidc_key.keycloak.name
  id_token_ttl     = 1800
  access_token_ttl = 3600
}

// Create a Vault OIDC provider
resource "vault_identity_oidc_scope" "user" {
  name = "user"
  template    = <<-EOT
    {
      "username": {{identity.entity.name}},
      "contact" : {
        "email": {{identity.entity.metadata.email}},
        "phone": {{identity.entity.metadata.phone_number}}
      }
    }
EOT
  // template = jsonencode({
  //   username = "{{identity.entity.name}}"
  //   email    = "{{identity.entity.metadata.email}}"
  //   phone    = "{{identity.entity.metadata.phone_number}}"
  // })
  description = "The user scope provides claims using Vault identity entity metadata"
}

resource "vault_identity_oidc_scope" "groups" {
  name = "engineering"
  template = <<-EOT
    {
      "groups" : {{identity.entity.groups.names}}
    }
  EOT
  description = "The groups scope provides the groups claim using Vault group membership"
}

resource "vault_identity_oidc_provider" "keycloak" {
  name          = "my-provider"
  https_enabled = false
  issuer_host   = "127.0.0.1:8200"
  allowed_client_ids = [
    vault_identity_oidc_client.keycloak.client_id
  ]
  scopes_supported = [
    vault_identity_oidc_scope.groups.name,
    vault_identity_oidc_scope.user.name,
  ]
}

// Check a Vault well-known
data "http" "openid_configuration" {
  url = "${vault_identity_oidc_provider.keycloak.issuer}/.well-known/openid-configuration"

  request_headers = {
    Accept = "application/json"
  }
}

data "http" "keys" {
  url = "${vault_identity_oidc_provider.keycloak.issuer}/.well-known/keys"

  request_headers = {
    Accept = "application/json"
  }
}

// Keycloak Setup
resource "keycloak_realm" "vault" {
  realm   = "vault"
  enabled = true
}

locals {
  issuer_data = jsondecode(data.http.openid_configuration.response_body)
}

resource "keycloak_oidc_identity_provider" "vault" {
  add_read_token_role_on_create = false
  alias                         = local.keycloak_oidc_alias
  authenticate_by_default       = false
  authorization_url             = local.issuer_data.authorization_endpoint
  backchannel_supported         = false
  client_id                     = vault_identity_oidc_client.keycloak.client_id
  client_secret                 = vault_identity_oidc_client.keycloak.client_secret
  disable_user_info             = false
  enabled                       = true
  extra_config                  = {}
  first_broker_login_flow_alias = "first broker login"
  hide_on_login_page            = false
  issuer                        = vault_identity_oidc_provider.keycloak.issuer
  jwks_url                      = local.issuer_data.jwks_uri
  link_only                     = false
  realm                         = keycloak_realm.vault.realm
  store_token                   = false
  token_url                     = local.issuer_data.token_endpoint
  trust_email                   = false
  ui_locales                    = false
  user_info_url                 = local.issuer_data.userinfo_endpoint
  validate_signature            = true
  default_scopes                = join(" ", vault_identity_oidc_provider.keycloak.scopes_supported)
}

resource "keycloak_attribute_importer_identity_provider_mapper" "username" {
  realm                   = keycloak_realm.vault.id
  name                    = "username-attribute-importer"
  claim_name              = "username"
  identity_provider_alias = keycloak_oidc_identity_provider.vault.alias
  user_attribute          = "username"

  extra_config = {
    syncMode = "INHERIT"
  }
}

resource "keycloak_attribute_importer_identity_provider_mapper" "email" {
  realm                   = keycloak_realm.vault.id
  name                    = "email-attribute-importer"
  claim_name              = "contact.email"
  identity_provider_alias = keycloak_oidc_identity_provider.vault.alias
  user_attribute          = "email"

  extra_config = {
    syncMode = "INHERIT"
  }
}

resource "keycloak_attribute_importer_identity_provider_mapper" "phone_number" {
  realm                   = keycloak_realm.vault.id
  name                    = "phone-number-attribute-importer"
  claim_name              = "phone"
  identity_provider_alias = keycloak_oidc_identity_provider.vault.alias
  user_attribute          = "phone"

  extra_config = {
    syncMode = "INHERIT"
  }
}

resource "keycloak_attribute_importer_identity_provider_mapper" "groups" {
  realm                   = keycloak_realm.vault.id
  name                    = "groups-attribute-importer"
  claim_name              = "groups"
  identity_provider_alias = keycloak_oidc_identity_provider.vault.alias
  user_attribute          = "groups"

  extra_config = {
    syncMode = "INHERIT"
  }
}