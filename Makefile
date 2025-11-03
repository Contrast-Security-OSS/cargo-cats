.SILENT:

.PHONY: \
	# Namespace & registry setup
	ensure-namespace registry-login create-registry-secret \
	create-secret-to-apps-sa-link create-secret-to-console-sa-link \
	\
	# Build targets - Cargo Cats core
	build-dataservice build-webhookservice build-frontgateservice build-exploit-server \
	build-imageservice build-labelservice build-docservice \
	build-cargo-cats-containers build-and-push-cargo-cats \
	push-dataservice push-webhookservice push-frontgateservice push-exploit-server \
	push-imageservice push-labelservice push-docservice push-cargo-cats \
	\
	# Build targets - Simulation
	build-contrastdatacollector build-console-ui build-simulation-containers \
	build-and-push-simulation push-contrastdatacollector push-console-ui push-simulation \
	\
	# Helm & deployment
	download-helm-dependencies deploy-contrast run-helm deploy-simulation-console deploy \
	setup-opensearch validate-env-vars \
	\
	# Uninstall/redeploy
	uninstall redeploy

ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# ======================
# Configurable Variables
# ======================
CONTAINER_PLATFORM ?= docker-desktop       # Not used to choose engine anymore, just informational
EXTERNAL_REGISTRY ?= false                 # false | true
REGISTRY ?=                                # Full registry path required if EXTERNAL_REGISTRY=true
NAMESPACE ?= default

# Optional registry auth
REG_API_KEY ?=
REG_USERNAME ?=

# ======================
# Default Container Engine
# ======================
ENGINE ?= docker

# ======================
# Registry Prefix Logic
# ======================
ifeq ($(EXTERNAL_REGISTRY),true)
ifeq ($(REGISTRY),)
$(error EXTERNAL_REGISTRY=true but REGISTRY is not set. REGISTRY must be full registry path, e.g. quay.io/myteam)
endif
IMAGE_PREFIX := $(REGISTRY)/
HELM_IMAGE_PREFIX := --set imagePrefix=$(IMAGE_PREFIX)
else
IMAGE_PREFIX :=
HELM_IMAGE_PREFIX :=
endif

# ======================
# Image Pull Logic
# ======================
ifeq ($(CONTAINER_PLATFORM),openshift)
    HELM_IMAGE_PULL_POLICY := --set imagePullPolicy=IfNotPresent
else
    HELM_IMAGE_PULL_POLICY :=
endif

# ======================
# OpenShift Route Logic
# ======================
ifeq ($(CONTAINER_PLATFORM),openshift)
    ROUTE_HOST := $(shell oc get ingresses.config/cluster -o jsonpath='{.spec.domain}')
else
    ROUTE_HOST := localhost
endif

ensure-namespace:
	@echo "Ensuring namespace $(NAMESPACE) exists..."
	kubectl get namespace $(NAMESPACE) >/dev/null 2>&1 || kubectl create namespace $(NAMESPACE)

registry-login:
ifeq ($(EXTERNAL_REGISTRY),true)
	@echo "Logging into registry $(REGISTRY)"
	echo "$(REG_API_KEY)" | $(ENGINE) login $(REGISTRY) -u "$(REG_USERNAME)" --password-stdin
endif

create-registry-secret: ensure-namespace
ifeq ($(EXTERNAL_REGISTRY),true)
	@echo "Creating external registry secret for OpenShift in namespace $(NAMESPACE)..."
	@oc create secret docker-registry my-reg-secret \
		--docker-server=$(REGISTRY) \
		--docker-username=$(REG_USERNAME) \
		--docker-password=$(REG_API_KEY) \
		--docker-email=unused \
		-n $(NAMESPACE) --dry-run=client -o yaml | oc apply -f -
endif

download-helm-dependencies:
	@echo "Downloading Helm chart dependencies..."
	@cd contrast-cargo-cats && helm dependency update
	@echo "Helm chart dependencies downloaded successfully."

deploy-contrast: ensure-namespace
	@echo "\nDeploying Contrast Agent Operator..."
	kubectl apply -f https://github.com/Contrast-Security-OSS/agent-operator/releases/latest/download/install-prod.yaml
	@echo "\nSetting Contrast Agent Operator Token..."
	kubectl -n contrast-agent-operator delete secret default-agent-connection-secret --ignore-not-found
	kubectl -n contrast-agent-operator create secret generic default-agent-connection-secret --from-literal=token=$(CONTRAST__AGENT__TOKEN)
	@echo "\nApplying Contrast Agent Operator Configuration..."
ifeq ($(NAMESPACE),default)
	kubectl apply -f contrast-agent-operator-config.yaml
else
	# Replace all 'namespace: default' with 'namespace: $(NAMESPACE)'
	sed "s/namespace: default/namespace: $(NAMESPACE)/g" contrast-agent-operator-config.yaml | kubectl apply -f -
endif
	kubectl set env -n contrast-agent-operator deployment/contrast-agent-operator CONTRAST_INITCONTAINER_MEMORY_LIMIT="256Mi"
	echo ""

setup-opensearch:
	@echo "\nSetting up OpenSearch"
	$(eval OPENSEARCH_URL := $(if $(filter openshift,$(CONTAINER_PLATFORM)),https://opensearch-$(NAMESPACE).$(ROUTE_HOST),http://opensearch.localhost))
	@echo "Using OpenSearch URL: $(OPENSEARCH_URL)"
	@until curl --insecure -s -o /dev/null -w "%{http_code}" $(OPENSEARCH_URL) | grep -q "302"; do \
        echo "Waiting for OpenSearch..."; \
        sleep 5; \
    done
	curl --insecure -X POST -H "Content-Type: multipart/form-data" -H "osd-xsrf: osd-fetch" "$(OPENSEARCH_URL)/api/saved_objects/_import?overwrite=true" -u admin:Contrast@123! --form file='@contrast-cargo-cats/opesearch_savedobjects.ndjson'
	curl --insecure -X POST -H 'Content-Type: application/json' -H 'osd-xsrf: osd-fetch' '$(OPENSEARCH_URL)/api/opensearch-dashboards/settings' -u admin:Contrast@123! --data-raw '{"changes":{"defaultRoute":"/app/dashboards#/"}}'
	sleep 5
	@echo "OpenSearch setup complete."

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
	@if [ -n "$(REG_API_KEY)" ] && [ -z "$(REG_USERNAME)" ]; then \
		echo "Error: REG_USERNAME must be supplied when REG_API_KEY is set."; \
		exit 1; \
	fi
	@echo "Required environment variables are set."

define build_service
	@echo "Building $(1)..."
	cd services/$(1) && \
	$(ENGINE) build -t $(IMAGE_PREFIX)$(1):latest .
endef

define push_service
	@echo "Pushing $(IMAGE_PREFIX)$(1):latest..."
	$(ENGINE) push $(IMAGE_PREFIX)$(1):latest
endef

# --- Cargo Cats core containers ---
build-dataservice: ; $(call build_service,dataservice)
build-webhookservice: ; $(call build_service,webhookservice)
build-frontgateservice: ; $(call build_service,frontgateservice)
build-exploit-server: ; $(call build_service,exploit-server)
build-imageservice: ; $(call build_service,imageservice)
build-labelservice: ; $(call build_service,labelservice)
build-docservice: ; $(call build_service,docservice)

push-dataservice: ; $(call push_service,dataservice)
push-webhookservice: ; $(call push_service,webhookservice)
push-frontgateservice: ; $(call push_service,frontgateservice)
push-exploit-server: ; $(call push_service,exploit-server)
push-imageservice: ; $(call push_service,imageservice)
push-labelservice: ; $(call push_service,labelservice)
push-docservice: ; $(call push_service,docservice)

# --- Build groups ---
build-cargo-cats-containers: \
	build-dataservice \
	build-webhookservice \
	build-frontgateservice \
	build-exploit-server \
	build-imageservice \
	build-labelservice \
	build-docservice
	@echo "Cargo Cats core containers built."

build-and-push-cargo-cats: build-cargo-cats-containers registry-login
ifeq ($(EXTERNAL_REGISTRY),true)
	$(MAKE) push-cargo-cats
endif

build-contrastdatacollector: ; $(call build_service,contrastdatacollector)
build-console-ui: ; $(call build_service,console-ui)

push-contrastdatacollector: ; $(call push_service,contrastdatacollector)
push-console-ui: ; $(call push_service,console-ui)

build-simulation-containers: build-console-ui build-contrastdatacollector
	@echo "Simulation containers built."

build-and-push-simulation: build-simulation-containers registry-login
ifeq ($(EXTERNAL_REGISTRY),true)
	$(MAKE) push-simulation
endif

# ======================
# Push targets
# ======================
push-cargo-cats: \
	push-dataservice \
	push-webhookservice \
	push-frontgateservice \
	push-exploit-server \
	push-imageservice \
	push-labelservice \
	push-docservice
	@echo "Pushed Cargo Cats core containers."

push-simulation: \
	push-console-ui \
	push-contrastdatacollector
	@echo "Pushed simulation containers."

create-secret-to-apps-sa-link: create-registry-secret run-helm
ifeq ($(EXTERNAL_REGISTRY),true)
	@echo "Linking external registry secret to SAs namespace $(NAMESPACE)..."
	@oc secrets link default my-reg-secret --for=pull -n $(NAMESPACE)
endif

create-secret-to-console-sa-link: create-registry-secret deploy-simulation-console
ifeq ($(EXTERNAL_REGISTRY),true)
	@echo "Linking external registry secret to SAs namespace $(NAMESPACE)..."
	@oc secrets link simulation-console-pod-monitor my-reg-secret --for=pull -n $(NAMESPACE)
endif

add-scc-permission-to-app-service-accounts: ensure-namespace
	@echo "Permissioning Service Accounts for SCC use (namespace: $(NAMESPACE))"
	oc adm policy add-scc-to-user nonroot-v2 -z contrast-cargo-cats-ingress-nginx-admission -n $(NAMESPACE)
	oc adm policy add-scc-to-user privileged -z contrast-cargo-cats-falco -n $(NAMESPACE)
	oc adm policy add-scc-to-user nonroot-v2 -z opensearch-dashboard-sa -n $(NAMESPACE)
	oc adm policy add-scc-to-user privileged -z opensearch-node-sa -n $(NAMESPACE)
	oc adm policy add-scc-to-user privileged -z contrast-cargo-cats-ingress-nginx -n $(NAMESPACE)
	oc adm policy add-scc-to-user privileged -z contrast-cargo-cats-fluent-bit -n  $(NAMESPACE)

opensearch-sysctl:
ifeq ($(CONTAINER_PLATFORM),openshift)
	@echo "Setting max_map_count for OpenSearch"
	oc adm policy add-scc-to-user privileged -z sysctl-tuner -n openshift-operators
	oc apply -f sysctl-tuner.yaml
else
	@echo "Skipping sysctl (not on OpenShift)"
endif

run-helm: ensure-namespace build-and-push-cargo-cats create-registry-secret add-scc-permission-to-app-service-accounts opensearch-sysctl
	echo ""
	@echo "Deploying contrast-cargo-cats (namespace: $(NAMESPACE))"
	helm upgrade --install contrast-cargo-cats  ./contrast-cargo-cats \
		-n $(NAMESPACE) --create-namespace --cleanup-on-fail \
		$(HELM_IMAGE_PULL_POLICY) $(HELM_IMAGE_PREFIX) \
		--set contrast.uniqName=$(CONTRAST__UNIQ__NAME) \
		--debug

deploy-simulation-console: ensure-namespace create-registry-secret build-simulation-containers
	@echo "Waiting for ingress controller to be ready..."
	@until kubectl get deployment contrast-cargo-cats-ingress-nginx-controller -o jsonpath='{.status.readyReplicas}' 2>/dev/null | grep -q "1"; do \
		echo "Waiting for ingress controller..."; \
		sleep 5; \
	done
	@echo "Getting ingress controller IP..."
	$(eval INGRESS_IP := $(shell kubectl get service contrast-cargo-cats-ingress-nginx-controller -o jsonpath='{.spec.clusterIP}' 2>/dev/null))
	$(eval VULN_APP_URL := $(if $(filter openshift,$(CONTAINER_PLATFORM)),https://cargocats-$(NAMESPACE).$(ROUTE_HOST),http://cargocats.localhost))
	$(eval OPENSEARCH_URL := $(if $(filter openshift,$(CONTAINER_PLATFORM)),https://opensearch-$(NAMESPACE).$(ROUTE_HOST),http://opensearch.localhost))
	@echo "Ingress controller IP: $(INGRESS_IP)"
	@echo "Deploying simulation console..."
	helm upgrade --install simulation-console ./simulation-console \
		-n $(NAMESPACE) --create-namespace --cleanup-on-fail \
		$(HELM_IMAGE_PULL_POLICY) $(HELM_IMAGE_PREFIX) \
		--set consoleui.vulnAppUrl=$(VULN_APP_URL) \
		--set consoleui.opensearchUrl=$(OPENSEARCH_URL) \
		--set-string aliashost.cargocats\\.localhost=$(INGRESS_IP) \
		--set contrastdatacollector.contrastUniqName=$(CONTRAST__UNIQ__NAME) \
		--set contrastdatacollector.contrastApiToken=$(CONTRAST__AGENT__TOKEN) \
		--set contrastdatacollector.contrastApiKey=$(CONTRAST__API__KEY) \
		--set contrastdatacollector.contrastApiAuthorization=$(CONTRAST__API__AUTHORIZATION) \
		--set consoleui.contrastApiToken=$(CONTRAST__AGENT__TOKEN) \
		--set consoleui.contrastUniqName=$(CONTRAST__UNIQ__NAME) \
		--set consoleui.contrastApiKey=$(CONTRAST__API__KEY) \
		--set consoleui.contrastApiAuthorization=$(CONTRAST__API__AUTHORIZATION) \
		--debug
	echo ""
	
deploy: validate-env-vars deploy-contrast download-helm-dependencies run-helm setup-opensearch deploy-simulation-console create-secret-to-apps-sa-link create-secret-to-console-sa-link
	$(eval contrast_url := $(shell echo "$(CONTRAST__AGENT__TOKEN)" | base64 --decode | grep -o '"url"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*: *"\(.*\)"/\1/' | sed 's/-agents//g'))
	$(eval CONSOLE_URL := $(if $(filter openshift,$(CONTAINER_PLATFORM)),https://console-$(NAMESPACE).$(ROUTE_HOST),http://console.localhost))
	$(eval VULN_APP_URL := $(if $(filter openshift,$(CONTAINER_PLATFORM)),https://cargocats-$(NAMESPACE).$(ROUTE_HOST),http://cargocats.localhost))
	$(eval OPENSEARCH_URL := $(if $(filter openshift,$(CONTAINER_PLATFORM)),https://opensearch-$(NAMESPACE).$(ROUTE_HOST),http://opensearch.localhost))
	@echo "\n\nDeployment complete!"
	@echo "=================================================================="
	@echo "Note: It may take a few minutes for the deployment to be fully ready."
	@echo "==================================================================\n"
	@echo ""
	@echo "Simulation Console: $(CONSOLE_URL)"
	@echo ""
	@echo "Vuln App: $(VULN_APP_URL)"
	@echo "  Username: admin"
	@echo "  Password: password123"
	@echo ""
	@echo "OpenSearch Dashboard: $(OPENSEARCH_URL)"
	@echo "  Username: admin"
	@echo "  Password: Contrast@123!"
	@echo ""
	@echo "Contrast UI: $(contrast_url)"
	@echo "==================================================================\n"
	@echo ""


uninstall: 
	helm uninstall contrast-cargo-cats; helm uninstall simulation-console; kubectl delete namespace contrast-agent-operator;

redeploy: uninstall deploy
	@echo "Redeployment complete!"
