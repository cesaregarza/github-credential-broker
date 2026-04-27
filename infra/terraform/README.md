# Terraform Deployment

This module provisions the first production host for the broker:

- a DigitalOcean Droplet in `nyc3` using `ubuntu-24-04-x64`
- a DigitalOcean firewall with only public TCP `80` and `443` open
- optionally, the exact Cloudflare `A` record for `credentials.garz.ai`
- cloud-init bootstrap for Docker, Caddy, Tailscale, broker policy, and the
  broker systemd unit

It intentionally does not put the 1Password service account token, Cloudflare
token, or DigitalOcean token in Terraform variables, cloud-init, or state.

## DNS Boundary

Application subdomains stay with the cluster DNS stack. The broker is isolated
on its own Droplet for security and should have only one public DNS name:
`credentials.garz.ai`.

By default this module creates that exact `A` record. It never manages wildcard
records or application subdomains. If the cluster DNS stack owns all Cloudflare
records, set:

```hcl
manage_broker_dns = false
```

Then create the exact broker record in the cluster DNS stack instead:

```text
credentials.garz.ai A <broker droplet IPv4>
```

## Prerequisites

Set provider credentials in your shell:

```bash
export DIGITALOCEAN_TOKEN=...
export CLOUDFLARE_API_TOKEN=...
```

The DigitalOcean token needs Droplet, firewall, and tag permissions. If
`manage_broker_dns` is true, the Cloudflare token also needs zone read and DNS
edit for `garz.ai`.

The broker image must be pullable by the Droplet without authentication. The
GitHub Actions workflow publishes to GHCR; after the first package is created,
verify it is public or make it public in GitHub Packages.

## Configure

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
editor terraform.tfvars
```

Set `container_image` to the public GHCR image, for example:

```hcl
container_image = "ghcr.io/cesaregarza/github-credential-broker:main"
```

Set `policy_path` to the policy that should be copied to the Droplet at first
boot. The repository's real deployment policy lives at
`../../config/policy.yml`; the checked-in example is only a sanitized starter.

Do not put secrets in `terraform.tfvars`; local tfvars and Terraform state are
ignored by Git.

## Apply

```bash
terraform init
terraform plan
terraform apply
```

The output includes the GitHub OIDC audience:

```text
https://credentials.garz.ai/v1
```

Callers must request exactly that audience from GitHub Actions.

## Manual Bootstrap

The Droplet has no public SSH ingress. Use the DigitalOcean web console for the
initial bootstrap, then join Tailscale interactively:

```bash
sudo tailscale up --ssh --hostname github-credential-broker-prod
```

Create the root-only runtime env file from the generated example:

```bash
sudo install -o root -g root -m 0600 \
  /etc/github-credential-broker/broker.env.example \
  /etc/github-credential-broker/broker.env
sudo editor /etc/github-credential-broker/broker.env
```

Set `OP_SERVICE_ACCOUNT_TOKEN` to the dedicated read-only 1Password service
account token for the broker vault. Then start the service:

```bash
sudo systemctl start github-credential-broker.service
sudo systemctl status github-credential-broker.service
```

Caddy starts during cloud-init and obtains the public TLS certificate. The
broker service is only enabled during cloud-init; it will not start until
`/etc/github-credential-broker/broker.env` exists.

## Break-Glass SSH

The normal bootstrap path is the DigitalOcean console followed by Tailscale SSH.
If the console is unavailable, you can temporarily inject a DigitalOcean SSH key
and open TCP `22` only to your current IP:

```hcl
break_glass_ssh_public_keys = [
  "ssh-ed25519 AAAA... user@example",
]
break_glass_ssh_source_addresses = ["203.0.113.10/32"]
```

Changing the injected SSH keys replaces the Droplet because cloud-init only
runs at first boot. After Tailscale SSH is working, remove
`break_glass_ssh_source_addresses` and apply again to close public SSH without
replacing the Droplet. Remove the public key later during a planned rebuild.

When enabled, SSH as `brokeradmin`. The user has passwordless sudo and a locked
password:

```bash
ssh brokeradmin@<droplet-ip>
```

## Operations

Restarting the broker pulls the configured image tag again:

```bash
sudo systemctl restart github-credential-broker.service
```

Inspect logs without dumping secrets:

```bash
sudo journalctl -u github-credential-broker.service -n 100 --no-pager
sudo journalctl -u caddy -n 100 --no-pager
```

The policy copied at first boot comes from `policy_path`. After Tailscale is
joined, deploy policy-only changes from the repo root without rebuilding the
image:

```bash
scripts/deploy-policy.sh config/policy.yml
```

If MagicDNS is unavailable in your shell, pass the Tailscale IP explicitly:

```bash
scripts/deploy-policy.sh config/policy.yml brokeradmin@100.97.170.7
```

The script validates the policy locally, validates it again with the running
broker image on the Droplet, installs it with a timestamped backup, restarts the
service, and checks `/healthz`.
