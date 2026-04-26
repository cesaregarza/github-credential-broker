variable "project_name" {
  description = "Short name used for tags and resource names."
  type        = string
  default     = "github-credential-broker"

  validation {
    condition     = length(trimspace(var.project_name)) > 0
    error_message = "project_name must not be empty."
  }
}

variable "droplet_name" {
  description = "DigitalOcean Droplet name."
  type        = string
  default     = "github-credential-broker-prod"

  validation {
    condition     = length(trimspace(var.droplet_name)) > 0
    error_message = "droplet_name must not be empty."
  }
}

variable "region" {
  description = "DigitalOcean region slug."
  type        = string
  default     = "nyc3"
}

variable "droplet_size" {
  description = "DigitalOcean Droplet size slug."
  type        = string
  default     = "s-1vcpu-1gb"
}

variable "droplet_image" {
  description = "DigitalOcean image slug."
  type        = string
  default     = "ubuntu-24-04-x64"
}

variable "enable_backups" {
  description = "Enable DigitalOcean Droplet backups. Disabled by default because backups will include the runtime secret env file after bootstrap."
  type        = bool
  default     = false
}

variable "break_glass_ssh_public_keys" {
  description = "Optional public SSH keys to install into root authorized_keys for break-glass bootstrap access. Leave empty to disable public SSH key login."
  type        = list(string)
  default     = []
}

variable "break_glass_ssh_source_addresses" {
  description = "CIDR source addresses allowed to reach TCP 22 when break-glass SSH keys are configured."
  type        = list(string)
  default     = []
}

variable "cloudflare_zone_name" {
  description = "Cloudflare DNS zone name."
  type        = string
  default     = "splat.top"
}

variable "manage_broker_dns" {
  description = "Create the exact broker hostname record in Cloudflare. Set false if the cluster DNS Terraform stack owns all Cloudflare DNS records."
  type        = bool
  default     = true
}

variable "broker_hostname" {
  description = "Public hostname for the isolated broker Droplet. This module never manages wildcard or application subdomain records."
  type        = string
  default     = "credentials.splat.top"
}

variable "cloudflare_proxied" {
  description = "Whether Cloudflare should proxy the broker DNS record. Leave false unless Cloudflare SSL mode is configured for a proxied origin."
  type        = bool
  default     = false
}

variable "container_image" {
  description = "Public broker container image to run on the Droplet, for example ghcr.io/owner/github-credential-broker:main."
  type        = string

  validation {
    condition     = length(trimspace(var.container_image)) > 0
    error_message = "container_image must not be empty."
  }
}

variable "policy_path" {
  description = "Path to the policy file to copy into the Droplet during cloud-init. Relative paths are resolved from this Terraform module."
  type        = string

  validation {
    condition     = length(trimspace(var.policy_path)) > 0
    error_message = "policy_path must not be empty."
  }
}

variable "extra_tags" {
  description = "Additional DigitalOcean tags to create and attach to the Droplet."
  type        = list(string)
  default     = ["prod"]
}
