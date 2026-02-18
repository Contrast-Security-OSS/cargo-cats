# Adding Contrast Security to a Running Cluster

This guide shows how to add Contrast Security agents to a cluster that was deployed without Contrast using `make deploy-no-contrast`.

## Prerequisites

- A running cluster deployed with `make deploy-no-contrast`
- Contrast Security credentials set in your `.env` file:
  - `CONTRAST__AGENT__TOKEN`
  - `CONTRAST__UNIQ__NAME`
  - `CONTRAST__API__KEY` (optional)
  - `CONTRAST__API__AUTHORIZATION` (optional)

## Steps

### 1. Label application deployments for Contrast agent injection

This command labels only the application deployment pods (those starting with `contrast-cargo-cats`) so the Contrast operator knows to inject the agent:

```bash
kubectl get deployments -o name | grep contrast-cargo-cats | xargs -I {} kubectl patch {} -p '{"spec":{"template":{"metadata":{"labels":{"contrast-agent":"flex"}}}}}'
```

### 2. Install the Contrast Agent Operator

First, ensure your environment variables with agent credentials are loaded:

```bash
source .env
```

Then deploy the Contrast operator, create the authentication secret, and apply your configuration:

```bash
kubectl apply -f https://github.com/Contrast-Security-OSS/agent-operator/releases/latest/download/install-prod.yaml && \
kubectl -n contrast-agent-operator create secret generic default-agent-connection-secret --from-literal=token="$CONTRAST__AGENT__TOKEN" && \
kubectl apply -f contrast-agent-operator-config.yaml
```

## What happens

1. The label `contrast-agent: flex` tells the operator which pods should have the agent injected
2. The operator automatically adds an init container to inject the Contrast agent
3. Labeled deployments perform a rolling restart to pick up and run the agent
4. The agent starts reporting to your Contrast Security instance

## Troubleshooting

- If pods don't restart automatically, you can force a restart: `kubectl rollout restart deployment/<deployment-name>`
- Check operator logs: `kubectl logs -n contrast-agent-operator deployment/contrast-agent-operator`
- Verify the secret was created: `kubectl get secret -n contrast-agent-operator default-agent-connection-secret`
