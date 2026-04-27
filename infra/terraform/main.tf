locals {
  broker_oidc_audience = "https://${var.broker_hostname}/v1"
  common_tags          = distinct(concat([var.project_name, "credential-broker"], var.extra_tags))
  break_glass_ssh_enabled = (
    length(var.break_glass_ssh_public_keys) > 0
    && length(var.break_glass_ssh_source_addresses) > 0
  )
  policy_source_path = (
    startswith(var.policy_path, "/")
    ? var.policy_path
    : abspath("${path.module}/${var.policy_path}")
  )

  broker_env_example = <<-EOT
    BROKER_POLICY_PATH=/app/config/policy.yml
    BROKER_GITHUB_OIDC_AUDIENCE=${local.broker_oidc_audience}
    HOME=/tmp
    OP_CACHE=false
    OP_SERVICE_ACCOUNT_TOKEN=replace-me
  EOT

  journald_retention_config = <<-EOT
    [Journal]
    Storage=persistent
    SystemMaxUse=1G
    SystemKeepFree=1G
    MaxRetentionSec=30day
  EOT

  caddyfile = <<-EOT
    ${var.broker_hostname} {
      encode zstd gzip

      request_body {
        max_size 32KB
      }

      header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "no-referrer"
      }

      reverse_proxy 127.0.0.1:8080 {
        health_uri /healthz
      }
    }
  EOT

  systemd_unit = <<-EOT
    [Unit]
    Description=GitHub Credential Broker
    Documentation=https://github.com/cesaregarza/github-credential-broker
    Wants=network-online.target docker.service
    After=network-online.target docker.service
    ConditionPathExists=/etc/github-credential-broker/broker.env

    [Service]
    Restart=always
    RestartSec=5
    TimeoutStartSec=120
    TimeoutStopSec=30
    ExecStartPre=-/usr/bin/docker rm -f github-credential-broker
    ExecStart=/usr/bin/docker run --name github-credential-broker --rm --pull=always --env-file /etc/github-credential-broker/broker.env --user 10001:10001 --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m --tmpfs /home/broker:rw,noexec,nosuid,nodev,size=64m --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 512m --log-driver local --log-opt max-size=10m --log-opt max-file=5 -v /etc/github-credential-broker/policy.yml:/app/config/policy.yml:ro -p 127.0.0.1:8080:8080 ${var.container_image}
    ExecStop=/usr/bin/docker stop --time 20 github-credential-broker

    [Install]
    WantedBy=multi-user.target
  EOT
}

data "cloudflare_zone" "broker" {
  count = var.manage_broker_dns ? 1 : 0

  filter = {
    name = var.cloudflare_zone_name
  }
}

resource "digitalocean_tag" "broker" {
  for_each = toset(local.common_tags)

  name = each.value
}

resource "digitalocean_droplet" "broker" {
  name              = var.droplet_name
  region            = var.region
  size              = var.droplet_size
  image             = var.droplet_image
  ipv6              = true
  monitoring        = true
  backups           = var.enable_backups
  graceful_shutdown = true
  tags              = [for tag in digitalocean_tag.broker : tag.name]
  user_data = templatefile("${path.module}/templates/cloud-init.yaml.tftpl", {
    break_glass_ssh_public_keys = var.break_glass_ssh_public_keys
    broker_env_example_b64      = base64encode(local.broker_env_example)
    caddyfile_b64               = base64encode(local.caddyfile)
    journald_retention_b64      = base64encode(local.journald_retention_config)
    policy_yaml_b64             = filebase64(local.policy_source_path)
    systemd_unit_b64            = base64encode(local.systemd_unit)
  })
}

resource "digitalocean_firewall" "broker" {
  name        = "${var.project_name}-public"
  droplet_ids = [digitalocean_droplet.broker.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  dynamic "inbound_rule" {
    for_each = local.break_glass_ssh_enabled ? [1] : []

    content {
      protocol         = "tcp"
      port_range       = "22"
      source_addresses = var.break_glass_ssh_source_addresses
    }
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

resource "cloudflare_dns_record" "broker" {
  count = var.manage_broker_dns ? 1 : 0

  zone_id = data.cloudflare_zone.broker[0].id
  name    = var.broker_hostname
  type    = "A"
  content = digitalocean_droplet.broker.ipv4_address
  ttl     = 1
  proxied = var.cloudflare_proxied
  comment = "Managed by Terraform for ${var.project_name}"
}
