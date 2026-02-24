# Alternative Cluster Setup Guide

If you don't have access to Docker Desktop, you can set up a local Kubernetes cluster using **k3s** or **Minikube**. Once your cluster is running with the prerequisites below satisfied, return to the main [README](README.md#setup) to continue with Setup and Deployment.

| Section | Description |
|---|---|
| [k3s](#option-1-k3s) (recommended) | Lightweight K8s for Linux  |
| [Minikube](#option-2-minikube) | Single-node K8s via VM or container driver |
| [Remote Access](#remote-access-eg-ec2) | Hosts file setup for remote clusters (e.g., EC2) |

---

## Option 1: k3s

[k3s](https://k3s.io/) is a lightweight Kubernetes distribution that works well on Linux. These instructions are for Ubuntu.

### 1. Install Docker

Reference: https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository

```bash
# Add Docker's official GPG key:
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update

# Install Docker
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
```

### 2. Install k3s

> **Important:** k3s uses whatever CPU and memory are available on the host. Ensure your machine has at least 4 vCPUs and 14 GiB of RAM (e.g., a `t3.xlarge` EC2 instance). See [EC2 Recommendations](EC2-RECOMMENDATIONS.md) for guidance.

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --docker --write-kubeconfig-mode 644 --disable traefik" sh -s -
```

After installation, copy the k3s kubeconfig to the default kubectl location:

```bash
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $USER:$USER ~/.kube/config
```

### 3. Install Helm

Reference: https://helm.sh/docs/intro/install/#through-package-managers

```bash
sudo apt-get install curl gpg apt-transport-https --yes
curl -fsSL https://packages.buildkite.com/helm-linux/helm-debian/gpgkey | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/helm.gpg] https://packages.buildkite.com/helm-linux/helm-debian/any/ any main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm
```

### 4. Install Make

```bash
sudo apt install make
```

### 5. Restart your shell

Log out and back in (or restart your terminal) so that Docker group membership and environment changes take effect.

### Verify the Cluster

```bash
kubectl get nodes
# You should see your k3s node in "Ready" status
```

---

## Option 2: Minikube

[Minikube](https://minikube.sigs.k8s.io/) runs a single-node Kubernetes cluster locally using a VM or container driver.

### 1. Install Docker

Docker is required to build the application container images.

#### macOS

```bash
brew install --cask docker
```

#### Linux (Ubuntu)

Reference: https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository

```bash
# Add Docker's official GPG key:
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update

# Install Docker
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
```

### 2. Install Minikube

```bash
# macOS
brew install minikube

# Linux
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
```

### 3. Start the Cluster

> **Important:** Minikube reserves CPU for its own system components. Give it all available CPUs and at least 14 GiB of memory. On EC2, Minikube requires at least a `t3.2xlarge` (8 vCPU) — see [EC2 Recommendations](EC2-RECOMMENDATIONS.md).

```bash
minikube start --driver=docker --memory=14336 --cpus=$(nproc)
```

> **Note:** Do **not** enable the Minikube `ingress` addon. The Helm chart deploys its own nginx-ingress controller, and enabling the addon would create a conflict.

### 4. Configure Docker to Use Minikube

Minikube uses its own Docker daemon, even with `--driver=docker`. You must point your shell to it so that images built with `docker build` are available to the cluster:

```bash
eval $(minikube docker-env)
```

Run this in the same terminal before running `make deploy`. To make it persistent, add it to your shell profile (e.g., `~/.bashrc` or `~/.zshrc`).

### 5. Install kubectl

#### macOS

```bash
brew install kubectl
```

#### Linux

```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install kubectl /usr/local/bin/kubectl
```

### 6. Install Helm

Reference: https://helm.sh/docs/intro/install/#through-package-managers

#### macOS

```bash
brew install helm
```

#### Linux

```bash
sudo apt-get install curl gpg apt-transport-https --yes
curl -fsSL https://packages.buildkite.com/helm-linux/helm-debian/gpgkey | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/helm.gpg] https://packages.buildkite.com/helm-linux/helm-debian/any/ any main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm
```

### 7. Install Make

```bash
# macOS: included with Xcode Command Line Tools
# Linux:
sudo apt install make
```

### 8. Verify the Cluster

```bash
kubectl get nodes
# You should see your minikube node in "Ready" status
```

### Accessing Services with Minikube

The `*.localhost` hostnames resolve to `127.0.0.1`, so you need to forward the ingress controller to local port 80. Run this in a separate terminal:

```bash
sudo kubectl --kubeconfig ~/.kube/config port-forward svc/contrast-cargo-cats-ingress-nginx-controller 80:80
```

Leave it running.

---

## Remote Access (e.g., EC2)

If your cluster is running on a remote machine (such as an EC2 instance), the application uses `*.localhost` hostnames which always resolve to `127.0.0.1`. You cannot override this with `/etc/hosts` on macOS. The simplest solution is an SSH tunnel that forwards port 80 from the remote machine to your local machine.

### SSH Tunnel

Run the following from your **local machine** (replace `<EC2_IP>` with your server's public IP and `<KEY>` with your SSH key path):

```bash
sudo ssh -L 80:127.0.0.1:80 -N -i <KEY> ubuntu@<EC2_IP>
```

- `sudo` is required because port 80 is a privileged port on macOS
- `-L 80:127.0.0.1:80` forwards local port 80 to the remote machine's port 80
- `-N` keeps the connection open without opening a remote shell

Leave this running in a terminal. Then open your browser and access the application as usual:

- **App**: http://cargocats.localhost
- **Console**: http://console.localhost
- **OpenSearch**: http://opensearch.localhost

To stop the tunnel, press `Ctrl+C`.

---

## Next Steps

Once your cluster is running and `kubectl get nodes` shows a **Ready** node, return to the main [README](README.md#setup) to continue with environment configuration and deployment.
