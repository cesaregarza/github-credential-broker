output "broker_url" {
  description = "Public broker base URL."
  value       = "https://${var.broker_hostname}"
}

output "github_oidc_audience" {
  description = "GitHub Actions OIDC audience callers must request."
  value       = local.broker_oidc_audience
}

output "droplet_ipv4" {
  description = "Droplet public IPv4 address."
  value       = digitalocean_droplet.broker.ipv4_address
}

output "droplet_ipv6" {
  description = "Droplet public IPv6 address."
  value       = digitalocean_droplet.broker.ipv6_address
}

output "broker_dns_record_managed" {
  description = "Whether this module created the exact Cloudflare A record for the broker hostname."
  value       = var.manage_broker_dns
}

output "broker_dns_a_record" {
  description = "Exact A record that must point at the isolated broker Droplet when DNS is managed elsewhere."
  value       = "${var.broker_hostname} -> ${digitalocean_droplet.broker.ipv4_address}"
}

output "runtime_env_path" {
  description = "Root-only env file that must be created manually on the Droplet before starting the broker."
  value       = "/etc/github-credential-broker/broker.env"
}

output "bootstrap_next_steps" {
  description = "Manual bootstrap commands to run from the DigitalOcean console after Terraform apply."
  value = [
    "sudo tailscale up --ssh --hostname ${var.droplet_name}",
    "sudo install -o root -g root -m 0600 /etc/github-credential-broker/broker.env.example /etc/github-credential-broker/broker.env",
    "sudo editor /etc/github-credential-broker/broker.env",
    "sudo systemctl start github-credential-broker.service",
  ]
}
