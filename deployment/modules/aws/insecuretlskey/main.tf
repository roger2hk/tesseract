terraform {
  required_providers {
    tls = {
      source  = "hashicorp/tls"
      version = "4.0.6"
    }
  }
}

# ECDSA key with P256 elliptic curve. Do NOT use this in production environment.
#
# Security Notice
# The private key generated by this resource will be stored unencrypted in your 
# Terraform/OpenTofu state file. Use of this resource for production deployments is not 
# recommended.
#
# See https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/private_key.
# See https://search.opentofu.org/provider/hashicorp/tls/latest/docs/resources/private_key#tls_private_key-resource.
resource "tls_private_key" "ecdsa_p256" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

# Use locals to process the secret string
locals {
  # Base64 representation (stripping PEM headers/footers and whitespace)
  # regexreplace removes the BEGIN/END lines and any whitespace characters (\s+)
  public_key_base64_der = trimspace(replace(replace(replace(tls_private_key.ecdsa_p256.public_key_pem, "-----BEGIN PUBLIC KEY-----", ""), "-----END PUBLIC KEY-----", ""), "\n", ""))
}
