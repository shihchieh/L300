# AKS L300 Security

> SECURITY

> **Focus:** AAD + RBAC, workload identity, authorized IP ranges, CVEs, Azure Policy, and network policy.

---

1. Explain the difference between Azure RBAC integration for AKS and Kubernetes RBAC.
2. Describe how managed AAD, Azure RBAC, and Kubernetes RBAC fit together in AKS.
3. Explain the flow behind `kubectl get nodes` for an AAD-enabled AKS cluster.
4. Explain workload identity and compare it with pod identity.
5. Troubleshoot authorized IP ranges and cluster authentication failures.
6. Handle AKS CVE reports and triage scope, exposure, and mitigation.
7. Explain how Azure Policy is integrated with AKS and how to identify non-compliant resources.
8. Troubleshoot Azure Network Policy and Calico-related behavior differences.

---

## 1. AAD + RBAC

### 1.1 Core model

AKS security often combines three layers:

- Azure Active Directory (AAD / Microsoft Entra ID): identity provider for users and service principals
- Azure RBAC: authorization for Azure resources, including AKS cluster control-plane access patterns
- Kubernetes RBAC: authorization inside the cluster itself for actions such as `get`, `list`, `create`, `delete`, and `watch` on Kubernetes objects

These are related but not the same:

- Azure RBAC answers: "Can this identity manage Azure resources?"
- Kubernetes RBAC answers: "Can this identity act inside the cluster API?"
- AAD integration answers: "How does the user or workload get an identity and token to authenticate?"

### 1.2 Azure RBAC integration for AKS vs Kubernetes RBAC

| Feature | Scope | Typical authorization question |
|---|---|---|
| Azure RBAC | Azure control plane / resource management | Can this user manage the AKS resource, node resource group, or related Azure resources? |
| Kubernetes RBAC | Kubernetes API server inside cluster | Can this user read pods, deploy workloads, or access cluster-scoped resources? |
| Managed AAD integration | User identity / token acquisition | How does the user authenticate to the API server and obtain a valid token? |

Important distinction:

- Azure RBAC does not replace Kubernetes RBAC.
- Kubernetes RBAC does not control Azure resource management.
- AAD integration is the identity plumbing used to authenticate to the Kubernetes API.

### 1.3 When managed AAD is enabled

AKS with managed AAD often uses Azure AD authentication to the Kubernetes API through token-based authentication. The cluster can be configured to use Azure RBAC for Kubernetes authorization, which maps Azure identities to Kubernetes roles and role bindings.

Typical flow:

1. A user authenticates to Azure AD.
2. The user receives a token.
3. The user runs `kubectl` with a credential plugin or Azure auth helper.
4. `kubectl` obtains a token for the Kubernetes API server.
5. The API server validates the token through the configured AAD issuer and audience.
6. Authorization is evaluated against Kubernetes RBAC or Azure RBAC mappings depending on the cluster configuration.

### 1.4 Why `kubectl get nodes` is more than a straight API call

When `kubectl get nodes` runs against an AAD-enabled AKS cluster, the request is not just a simple anonymous query.

Behind the scenes:

```text
kubectl
  -> uses kubeconfig and current context
  -> calls Azure auth plugin / kubelogin / exec plugin
  -> requests AAD token for the cluster audience
  -> calls kube-apiserver with Authorization: Bearer <token>
  -> kube-apiserver validates token via AAD issuer and audience
  -> kube-apiserver checks authorization
  -> kube-apiserver returns node list
```

If the cluster is configured for Azure RBAC integration, the API server may also map the identity into Kubernetes RBAC via the Azure RBAC integration path. If not, standard Kubernetes RBAC bindings apply.

### 1.5 AAD, kubelogin, and kubeconfig

For Azure RBAC-enabled AKS, the `kubeconfig` behavior differs depending on whether the user uses the `--admin` credential or a standard user credential.

Key points:

- `az aks get-credentials --admin` often fetches a kubeconfig that includes the cluster admin credential.
- Without `--admin`, the kubeconfig may rely on the Azure auth plugin and the user's identity.
- The user must be authorized in Azure RBAC and/or Kubernetes RBAC to perform the action.
- `kubelogin` is commonly used to acquire AAD tokens for `kubectl` in modern AKS scenarios.

### 1.6 `azure auth plugin has been removed`

When users see:

```text
error: The azure auth plugin has been removed.
```

this usually means:

- the kubeconfig still references the old `azure` auth provider
- the cluster is using a newer login flow that requires `kubelogin`
- the `kubelogin` binary is missing or outdated

Required remediation:

- install or upgrade `kubelogin`
- update kubeconfig to use `exec` mode and the correct cluster audience
- confirm the user is able to get a token through Azure CLI or the configured auth setup

### 1.7 Managed AAD and kubelogin

`kubelogin` implements Azure authentication for Kubernetes. It allows `kubectl` to exchange Azure credentials for a Kubernetes API token. In AKS, this is a common path when using AAD-enabled clusters.

Relevant login modes include:

- `azure` / Azure CLI-based login flow
- `spn` / service principal flow
- `devicecode` / interactive login mode
- `msi` / managed identity flow in supported scenarios

The exact login mode depends on the environment and identity type. The kubeconfig usually invokes an `exec` plugin that calls `kubelogin`.

### 1.8 User authentication flow with AAD

A typical user authentication path looks like this:

```text
User -> Azure CLI / kubelogin -> Microsoft Entra ID
  -> token for AKS cluster audience
  -> kubectl calls kube-apiserver
  -> kube-apiserver validates token and audience
  -> kube-apiserver checks Azure RBAC / Kubernetes RBAC
  -> kube-apiserver serves API response
```

At the protocol level, the request includes an OAuth/OIDC token. The cluster validates the token and checks the claims that correspond to the user's identity, group memberships, and authorization settings.

### 1.9 Troubleshooting AAD cluster login failures

If a user fails to log in to an AAD-enabled AKS cluster:

1. Check whether the user is a valid Azure AD identity.
2. Confirm the cluster is configured for AAD integration.
3. Confirm the token audience matches the cluster, not a different resource.
4. Confirm back-end cert or issuer settings are valid.
5. Confirm the user has Azure RBAC or Kubernetes RBAC entries for the required actions.
6. Check kubeconfig and `kubelogin` installation.
7. Check whether the user is using the correct identity, tenant, or subscription context.

Usual failure classes:

| Symptom | Likely cause |
|---|---|
| `401` | Invalid or expired token |
| `403` | Valid token, insufficient authorization |
| `The azure auth plugin has been removed` | kubeconfig / kubelogin mismatch |
| `AADSTS` errors | Azure AD tenant or consent / access problem |
| `Access denied` in cluster | Missing RBAC binding or Azure RBAC mapping |

---

## 2. Workload Identity

### 2.1 What it is

Workload Identity allows Kubernetes workloads to access Azure resources using Microsoft Entra tokens without requiring a pod identity or static secret.

The model is:

- a Kubernetes service account is bound to a federated identity
- Azure AD issues a federated credential for that service account and OIDC issuer
- the workload exchanges its token with Azure AD
- Azure AD returns a token for the target Azure resource
- the workload uses that token to call Azure APIs

### 2.2 Why it matters

Compared to pod identity, workload identity is generally preferred because it:

- uses Kubernetes-native service accounts and OIDC federation
- avoids long-lived secrets or managed identities embedded in pods
- maps more cleanly to modern cloud-native security models
- integrates with Azure resource access via federated credentials

### 2.3 How it works

Typical path:

```text
workload pod
  -> service account token projected by Kubernetes
  -> token presented to Azure AD via OIDC federation
  -> Azure AD validates issuer and audience
  -> token exchanged for Azure resource access token
  -> workload calls Azure service using managed identity semantics
```

AKS must have OIDC issuer enabled for this to work. The Azure workload identity webhook and related components may also inject environment variables and projected service-account tokens.

### 2.4 Troubleshooting workload identity

If workload identity is not working, check:

1. OIDC issuer is enabled and matches the cluster configuration.
2. Federated identity credential is correctly configured.
3. The service account annotation matches the Azure identity resource.
4. The pod has the expected projected service-account token.
5. The webhook and mutating admission components are healthy.
6. Kubernetes logs from the Azure workload identity components are valid.
7. The workload is using the correct environment variables and audience.

Useful checks:

```bash
kubectl get sa -A
kubectl get federatedidentitycredential -A
kubectl logs -n kube-system -l azure-workload-identity.io/system=true
kubectl describe pod -n <namespace> <pod>
```

Common failure signs:

- missing projected token volume
- wrong audience
- invalid federated credentials
- OIDC issuer not enabled
- workload identities not attached to the service account

### 2.5 Can OIDC issuer / workload identity be enabled after creation?

In many AKS scenarios, OIDC issuer can be enabled or configured as part of the cluster lifecycle, but the exact support depends on cluster version, networking, and Azure configuration. It is not something to assume is always changeable without validating the supported AKS workflow. Before deciding, confirm the current cluster and AKS feature support matrix.

---

## 3. Authorized IP Range

### 3.1 What it is

Authorized IP ranges restrict which public IPs can access the AKS API server endpoint.

It is not a replacement for:

- private cluster design
- AAD or RBAC controls
- firewall controls on the network path

It is a public endpoint access control mechanism.

### 3.2 How it works

When enabled, the AKS API server only accepts requests from the listed allowed IP ranges. Traffic from outside the allowed range is blocked at the API server/public endpoint layer.

This can affect:

- `az aks get-credentials`
- `kubectl` access from local workstation or VPN
- automation, CI/CD, and admin access paths

### 3.3 Troubleshooting complaints about allowed sources being blocked

If a request from an allowed IP is still denied:

1. Confirm the source IP is the actual egress IP used by the client.
2. Confirm NAT is not changing the source IP unexpectedly.
3. Confirm the public IP address range includes the real address.
4. Confirm the API server is still public or private depending on cluster design.
5. Confirm no extra network path, firewall, or proxy is altering traffic.
6. Check Azure resource configuration for the AKS API server authorization rules.

A common mistake is assuming the VPN client or corporate NAT IP matches the real source. It often does not.

---

## 4. CVE handling

### 4.1 Typical AKS CVE response

When a customer reports a CVE in AKS, treat the case as a risk, exposure, and mitigation triage, not just a package-version question.

Consider:

- whether the cluster is affected by the specific package or image
- whether the vulnerable component is in the node OS, cluster addon, or workload image
- whether the issue is in the AKS control plane, node image, or customer container
- whether the cluster is patched or whether a version update is required
- whether the issue is fixed in a supported AKS release or image
- what the practical exploit path is and whether it is reachable from the cluster environment

### 4.2 Scope of the issue

A CVE may be relevant to:

- node OS packages
- Kubernetes components
- cluster add-ons
- container images in workloads
- infrastructure components or Azure-managed dependencies

The right response depends on which layer is actually impacted.

### 4.3 Handling process

A good CVE handling workflow includes:

1. Confirm the exact affected component and version.
2. Validate whether the cluster or workload uses the vulnerable version.
3. Determine the exposure path and whether external or internal attack is possible.
4. Check if the AKS team provides a patched image or supported version.
5. Identify the customer mitigation or upgrade options.
6. Document risk and next steps clearly.

---

## 5. Azure Policy

### 5.1 What it is

Azure Policy helps enforce organizational standards and compliance for Azure resources. In AKS, it can also integrate with Kubernetes policy checks.

The AKS Azure Policy integration typically includes:

- Azure Policy add-on for AKS
- policy agent or enforcement components deployed in the cluster
- Kubernetes admission / webhook behavior for policy enforcement
- inventory and compliance evaluation for AKS resources and Kubernetes objects

### 5.2 AKS Azure Policy integration model

When enabled, Azure Policy for AKS deploys or configures components that allow policy evaluation for the cluster and workloads. The components are not just Azure-side controls; they also provide Kubernetes-side policy enforcement and a compliance path.

The main concept is:

- Azure Policy evaluates Azure resources and cluster compliance
- Policy for Kubernetes can also enforce rules on Kubernetes objects
- AKS add-ons may deploy Gatekeeper or a related policy controller depending on the feature set

### 5.3 What gets created

After Azure Policy is enabled for AKS, expect:

- policy add-on resources
- supporting Kubernetes components for admission or evaluation
- policies tied to the AKS cluster and managed resources
- policy status and compliance data

The exact resource set depends on the enabled policy capability and AKS configuration.

### 5.4 How to check compliance

To evaluate whether AKS has compliance issues:

- inspect Azure Policy compliance state
- check Azure Policy assignment results
- inspect cluster add-on health and policy controller logs
- look for noncompliant Kubernetes resources or namespaces

A typical workflow includes checking the policy assignment and the resources it targets.

### 5.5 Differences between Azure Policy and RBAC

Both can block or restrict operations, but they address different questions:

- RBAC answers whether an identity is allowed to perform an action
- Azure Policy answers whether a resource or configuration is compliant with a policy definition

A resource may be blocked by RBAC even if it is compliant, or policy may deny it despite the identity having permissions.

### 5.6 Gatekeeper

Gatekeeper is the Kubernetes admission controller model commonly used with policy enforcement. It evaluates Kubernetes objects before they are admitted and can help enforce policy standards in a cluster.

---

## 6. Network policy

### 6.1 Azure Network Policy Manager vs Calico

AKS supports different network policy implementations depending on the network plugin and configuration.

| Type | Notes |
|---|---|
| Azure Network Policy Manager | Integrated with AKS Azure CNI scenarios; policy behavior depends on the plugin and supported features |
| Calico network policy | Uses the Calico policy engine and may differ in supported features and behavior |

Key differences include:

- compatibility with network plugins
- policy enforcement model and scope
- support for features such as egress or ingress restrictions
- interaction with node networking and service behavior

### 6.2 Troubleshooting Azure network policy

When Azure network policy does not behave as expected, investigate:

1. Whether the policy selects the intended workload and namespace.
2. Whether the policy is applied in ingress, egress, or both directions.
3. Whether the source/destination pod or namespace labels match the selectors.
4. Whether the destination port or protocol is correct.
5. Whether Azure plugin/network policy manager is the active policy engine.
6. Whether a route, NSG, or firewall is also blocking traffic.

### 6.3 Rule configuration and node behavior

A policy defines which traffic is allowed. The enforcement happens at the node or dataplane layer, so the policy can affect traffic before it reaches the application. When troubleshooting, look at:

- pod labels
- namespace labels
- policy direction and selectors
- ports and protocols
- node policy engine state
- logs from the network policy manager

### 6.4 Common questions

- What is the difference between Azure Network Policy Manager and Calico?
- What is the policy enforcement mechanism and how does it interact with Azure CNI?
- How to diagnose when Azure network policy blocks a flow that should be allowed?
- How are rules translated to node-level behavior and why does a flow fail even when the pod appears healthy?

---

## 7. Core review questions

### AAD + RBAC

- What is the difference between Azure RBAC integration and Kubernetes RBAC?
- How do managed AAD, Kubernetes RBAC, and Azure RBAC relate to each other?
- What happens behind `kubectl get nodes` for an AAD-enabled cluster?
- What authentication types does Kubernetes support?
- What are the troubleshooting steps when a user cannot log in to an AAD-enabled cluster?
- What is the flow for a user authenticating as an Azure AD user and running `kubectl`?
- Why does `error: The azure auth plugin has been removed` happen?
- How does managed AAD leverage `kubelogin`?
- What are the kubelogin login modes?

### Workload Identity

- What is workload identity and how does it work?
- What are the advantages over pod identity?
- How do you troubleshoot workload identity issues?
- Is it possible to enable or disable OIDC issuer / workload identity after AKS creation?

### Authorized IP Range

- What is authorized IP range and how does it work?
- How do you troubleshoot when an allowed IP still gets denied?

### CVE handling

- What do you consider when a customer reports a CVE in AKS?

### Azure Policy

- How is Azure Policy integrated with AKS?
- What resources are installed when Azure Policy is enabled?
- How do you identify non compliant AKS resources?
- Are there built-in policies automatically applied? How do you find and modify them?
- What are the differences between Azure Policy and RBAC?

### Network Policy

- What is the difference between Azure Network Policy Manager and Calico?
- How do you troubleshoot Azure network policy not working as expected?
- How are rules converted into node-level behavior when a policy is created?

---

## 8. References

- AKS managed AAD docs
- Azure RBAC for Kubernetes authorization docs
- AAD with Kubernetes RBAC docs
- Azure RBAC for K8s Authorization troubleshooting guides
- Workload Identity docs
- OIDC issuer docs
- Authorized IP Range docs
- AKS vulnerability management docs
- Azure Policy docs
- Network policy docs
- Calico / Azure NPM docs

---

## 9. Accuracy and safety notes

- This guide is a learning aid and should be validated against the official AKS and Microsoft Learn documentation before use in a production or customer-facing design.
- Identity, policy, and network controls are often layered; a single symptom can have multiple causes.
- Do not assume Azure RBAC and Kubernetes RBAC are interchangeable.
- Network policy and Azure policy are complementary but not redundant.
- Document actual source IPs, tenant configuration, and cluster design before making changes to identity or policy controls.
