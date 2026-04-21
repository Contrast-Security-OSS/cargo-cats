.SILENT:

ifneq (,$(wildcard ./.env))
    include .env
    export
endif

download-helm-dependencies:
	@echo "Downloading Helm chart dependencies..."
	@cd contrast-cargo-cats && helm dependency update
	@echo "Helm chart dependencies downloaded successfully."

deploy-contrast:
	@echo "\nDeploying Contrast Agent Operator..."
	kubectl apply -f https://github.com/Contrast-Security-OSS/agent-operator/releases/latest/download/install-prod.yaml
	@echo "\nSetting Contrast Agent Operator Token..."
	kubectl -n contrast-agent-operator delete secret default-agent-connection-secret --ignore-not-found
	kubectl -n contrast-agent-operator create secret generic default-agent-connection-secret --from-literal=token=$(CONTRAST__AGENT__TOKEN)
	@echo "\nApplying Contrast Agent Operator Configuration..."
	kubectl apply -f contrast-agent-operator-config.yaml
	kubectl set env -n contrast-agent-operator deployment/contrast-agent-operator CONTRAST_INITCONTAINER_MEMORY_LIMIT="256Mi"
	echo ""

setup-opensearch:
	echo "\nSetting up OpenSearch"
	@until curl --insecure -s -o /dev/null -w "%{http_code}" http://opensearch.localhost | grep -q "302"; do \
        echo "Waiting for OpenSearch..."; \
        sleep 5; \
    done

	curl --insecure  -X POST -H "Content-Type: multipart/form-data" -H "osd-xsrf: osd-fetch" "http://opensearch.localhost/api/saved_objects/_import?overwrite=true" -u admin:Contrast@123! --form file='@contrast-cargo-cats/opesearch_savedobjects.ndjson'
	curl --insecure  -X POST -H 'Content-Type: application/json' -H 'osd-xsrf: osd-fetch' 'http://opensearch.localhost/api/opensearch-dashboards/settings' -u admin:Contrast@123! --data-raw '{"changes":{"defaultRoute":"/app/dashboards#/"}}'
	sleep 5;
	echo "OpenSearch setup complete."

check-not-kind:
	@PROVIDER_ID=$$(kubectl get nodes -o jsonpath='{.items[0].spec.providerID}' 2>/dev/null); \
	CONTEXT=$$(kubectl config current-context 2>/dev/null); \
	if echo "$$PROVIDER_ID" | grep -q "^kind://" || echo "$$CONTEXT" | grep -q "^kind-"; then \
		echo "Error: Detected a kind cluster."; \
		echo "Cargo Cats requires kubeadm (Docker Desktop's Kubernetes provider) and is not compatible with kind."; \
		echo "In Docker Desktop: Settings → Kubernetes → set provider to kubeadm, then reset the cluster."; \
		exit 1; \
	fi

validate-env-vars:
	@echo "Validating environment variables..."
	@if [ -z "$(CONTRAST__AGENT__TOKEN)" ]; then \
		echo "Error: CONTRAST__AGENT__TOKEN is not set in .env file"; \
		exit 1; \
	fi
	@if [ -z "$(CONTRAST__UNIQ__NAME)" ]; then \
		echo "Error: CONTRAST__UNIQ__NAME is not set in .env file"; \
		exit 1; \
	fi
	@if [ -z "$(CONTRAST__API__KEY)" ]; then \
		echo "Warning: CONTRAST__API__KEY is not set in .env file (optional for ADR data fetching and delete functionality)"; \
	fi
	@if [ -z "$(CONTRAST__API__AUTHORIZATION)" ]; then \
		echo "Warning: CONTRAST__API__AUTHORIZATION is not set in .env file (optional for ADR data fetching and delete functionality)"; \
	fi
	@echo "Required environment variables are set."

build-dataservice:
	@echo "Building dataservice..."
	cd services/dataservice && \
	docker build -t dataservice:latest  .

build-webhookservice:
	@echo "Building webhookservice..."
	cd services/webhookservice && \
	docker build -t webhookservice:latest  .

build-frontgateservice:
	@echo "Building frontgateservice..."
	cd services/frontgateservice && \
	docker build -t frontgateservice:latest  .

build-console-ui:
	@echo "Building console-ui..."
	cd services/console-ui && \
	docker build -t console-ui:latest  .

build-exploit-server:
	@echo "Building exploit-server..."
	cd services/exploit-server && \
	docker build -t exploit-server:latest  .

build-imageservice:
	@echo "Building imageservice..."
	cd services/imageservice && \
	docker build -t imageservice:latest  .

build-labelservice:
	@echo "Building labelservice..."
	cd services/labelservice && \
	docker build -t labelservice:latest  .

build-docservice:
	@echo "Building docservice..."
	cd services/docservice && \
	docker build -t docservice:latest  .

build-contrastdatacollector:
	@echo "Building contrastdatacollector..."
	cd services/contrastdatacollector && \
	docker build -t contrastdatacollector:latest  .

build-containers: build-dataservice build-webhookservice build-frontgateservice build-console-ui build-exploit-server build-imageservice build-labelservice build-docservice build-contrastdatacollector
	@echo "\nBuilding containers complete."

run-helm: build-containers 
	echo ""
	@echo "Deploying cluster..."
	helm upgrade --install contrast-cargo-cats  ./contrast-cargo-cats   --cleanup-on-fail \
		--set contrast.uniqName=$(CONTRAST__UNIQ__NAME)

deploy-simulation-console: build-console-ui build-contrastdatacollector
	@echo "Waiting for ingress controller to be ready..."
	@until kubectl get deployment contrast-cargo-cats-ingress-nginx-controller -o jsonpath='{.status.readyReplicas}' 2>/dev/null | grep -q "1"; do \
		echo "Waiting for ingress controller..."; \
		sleep 5; \
	done
	@echo "Getting ingress controller IP..."
	$(eval INGRESS_IP := $(shell kubectl get service contrast-cargo-cats-ingress-nginx-controller -o jsonpath='{.spec.clusterIP}' 2>/dev/null))
	@echo "Ingress controller IP: $(INGRESS_IP)"
	@echo "Deploying simulation console..."
	helm upgrade --install simulation-console ./simulation-console --cleanup-on-fail \
		--set-string aliashost.cargocats\\.localhost=$(INGRESS_IP) \
		--set contrastdatacollector.contrastUniqName=$(CONTRAST__UNIQ__NAME) \
		--set contrastdatacollector.contrastApiToken=$(CONTRAST__AGENT__TOKEN) \
		--set contrastdatacollector.contrastApiKey=$(CONTRAST__API__KEY) \
		--set contrastdatacollector.contrastApiAuthorization=$(CONTRAST__API__AUTHORIZATION) \
		--set consoleui.contrastApiToken=$(CONTRAST__AGENT__TOKEN) \
		--set consoleui.contrastUniqName=$(CONTRAST__UNIQ__NAME) \
		--set consoleui.contrastApiKey=$(CONTRAST__API__KEY) \
		--set consoleui.contrastApiAuthorization=$(CONTRAST__API__AUTHORIZATION)
	echo ""
	
deploy: check-not-kind validate-env-vars deploy-contrast download-helm-dependencies run-helm setup-opensearch deploy-simulation-console
	$(eval contrast_url := $(shell echo "$(CONTRAST__AGENT__TOKEN)" | base64 --decode | grep -o '"url"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*: *"\(.*\)"/\1/' | sed 's/-agents//g'))
	echo "\n\nDeployment complete!"
	echo "=================================================================="
	echo "Note: It may take a few minutes for the deployment to be fully ready."
	echo "==================================================================\n"
	echo ""
	echo "Simulation Console: http://console.localhost"
	echo ""
	echo "Vuln App: http://cargocats.localhost"
	echo "  Username: admin"
	echo "  Password: password123"
	echo ""
	echo "OpenSearch Dashboard: http://opensearch.localhost"
	echo "  Username: admin"
	echo "  Password: Contrast@123!"
	echo ""
	echo "Contrast UI: $(contrast_url)"
	echo "==================================================================\n"
	echo ""

deploy-no-contrast: check-not-kind validate-env-vars download-helm-dependencies run-helm setup-opensearch deploy-simulation-console
	echo "\n\nDeployment complete (without Contrast)!"
	echo "=================================================================="
	echo "Note: It may take a few minutes for the deployment to be fully ready."
	echo "==================================================================\n"
	echo ""
	echo "Simulation Console: http://console.localhost"
	echo ""
	echo "Vuln App: http://cargocats.localhost"
	echo "  Username: admin"
	echo "  Password: password123"
	echo ""
	echo "OpenSearch Dashboard: http://opensearch.localhost"
	echo "  Username: admin"
	echo "  Password: Contrast@123!"
	echo "==================================================================\n"
	echo ""

uninstall: 
	helm uninstall contrast-cargo-cats; helm uninstall simulation-console; kubectl delete namespace contrast-agent-operator;

redeploy: uninstall deploy
	@echo "Redeployment complete!"
