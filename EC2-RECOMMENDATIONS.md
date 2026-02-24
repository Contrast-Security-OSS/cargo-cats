# EC2 Instance Recommendations

If running Cargo Cats on AWS, use the following as a guide.

## Recommended: `t3.xlarge`

| | vCPUs | RAM | Storage | Cost (on-demand) |
|---|---|---|---|---|
| `t3.xlarge` | 4 | 16 GiB | 30 GiB `gp3` | ~$0.17/hr |

This comfortably runs all ~16 pods with headroom for the OS and Kubernetes overhead when using **k3s**.

**Minikube** has additional virtualization overhead and requires a larger instance. Use at least a `t3.2xlarge` (8 vCPU / 32 GiB) with **50 GiB** storage when running Minikube.

## Networking

> **Warning:** This application is **purposefully vulnerable**. Do not expose it to the public internet.

Restrict your security group inbound rules to only your IP address:

| Port | Protocol | Source |
|---|---|---|
| 22 | SSH | Your IP (`x.x.x.x/32`) |
| 80 | HTTP | Your IP (`x.x.x.x/32`) |
| 443 | HTTPS | Your IP (`x.x.x.x/32`) |

You can find your public IP at [checkip.amazonaws.com](https://checkip.amazonaws.com).
