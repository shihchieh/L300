# AKS L300 Security

> SECURITY

> **Focus:** managed Microsoft Entra ID (AAD), Kubernetes and Azure RBAC, workload identity, API server authorized IP ranges, CVE handling, Azure Policy, and network policy.

---

1. Separate network access, authentication, authorization, and admission.
2. Trace `kubectl get nodes` through kubeconfig, kubelogin, token validation, and authorization.
3. Compare Kubernetes RBAC, managed Entra integration, and Azure RBAC for Kubernetes authorization.
4. Explain user versus local-admin kubeconfig and troubleshoot login failures.
5. Trace workload identity federation and validate issuer, subject, audience, and target-resource permissions.
6. Diagnose authorized IP range failures using the actual client egress path.
7. Triage CVEs by component ownership, vendor status, exposure, and deployed patch level.
8. Explain Azure Policy components, compliance reporting, and admission failures.
9. Compare Azure NPM, Calico, and Cilium and prove network-policy decisions.

---

## 1. Core concepts and security boundaries

Start with the request, not the product names:

```text
client
  -> DNS, route, firewall, API server endpoint access
  -> TLS server identity validation
  -> authentication: who is calling?
  -> authorization: may this identity perform this action?
  -> admission, for applicable write requests: is this object acceptable?
  -> persist or read the Kubernetes object
  -> response and audit evidence
```

Keep the following boundaries separate:

| Boundary | Question | Example evidence |
|---|---|---|
| Network access | Can the client reach the API endpoint? | DNS answer, TCP/TLS test, proxy and firewall logs, authorized IP ranges |
| Authentication | Which identity does the credential represent? | Exec-plugin errors, Entra sign-in logs, authenticated username |
| Kubernetes API authorization | May that identity perform the verb on this resource and scope? | `kubectl auth can-i`, role assignments, bindings, API audit logs |
| Admission | Does the proposed object satisfy applicable controls? | Webhook rejection, constraint, ReplicaSet events |
| Azure management plane | May the identity manage the AKS resource or download kubeconfig? | ARM authorization error, Azure Activity Log, role `Actions` |
| Azure resource data plane | May a pod read a Key Vault secret or blob? | Service-specific authorization result, role `DataActions`, service firewall logs |

> **Interview rule:** Downloading kubeconfig is not proof of Kubernetes access. A valid token is not a permission grant. A `403` can come from authorization or an admission policy; read the actual error.

Commands use placeholders such as `<rg>` and `<cluster>`. Replace them before use. Configuration-changing examples are deliberate changes, not diagnostic prerequisites.

---

## 2. AAD + RBAC

### 2.1 The three features and their relationship

Azure Active Directory is now Microsoft Entra ID. Existing AKS flags and resource properties still include names such as `--enable-aad` and `aadProfile`.

| Feature | Responsibility | Where permissions or identity configuration live |
|---|---|---|
| Kubernetes RBAC | Native Kubernetes API authorization | `Role`, `ClusterRole`, `RoleBinding`, and `ClusterRoleBinding` |
| Managed Entra integration | Authenticate Entra users and applications to the Kubernetes API | AKS-managed integration and the cluster's Entra tenant |
| Azure RBAC for Kubernetes authorization | Authorize Kubernetes API operations using Azure role assignments | Azure role definitions and assignments at applicable scopes |

Managed Entra integration and Kubernetes RBAC work together: Entra supplies the identity, and Kubernetes bindings can grant that identity permissions.

Enabling Azure RBAC for Kubernetes adds an authorization webhook that evaluates Azure assignments for Entra identities. It does **not** create a Kubernetes RoleBinding for each Azure assignment. Kubernetes RBAC remains relevant, including for Kubernetes service accounts and system components.

Do not confuse Azure RBAC's two uses:

| Permission type | Example | What it does not prove |
|---|---|---|
| Azure management-plane `Actions` | `listClusterUserCredential/action` | Permission to list pods or nodes |
| Kubernetes data-plane `DataActions` | AKS RBAC Reader permissions | Permission to update the AKS Azure resource |

An Azure **Contributor** assignment is not the same as **Azure Kubernetes Service RBAC Cluster Admin**. Inspect the exact role definition and scope.

### 2.2 Kubernetes RBAC versus Azure RBAC for Kubernetes

| Capability | Kubernetes RBAC | Azure RBAC for Kubernetes |
|---|---|---|
| Authorization engine | API server's native RBAC authorizer | AKS authorization webhook and Azure access evaluation |
| Grant representation | Kubernetes roles and bindings | Azure roles and assignments |
| Scope | Namespace or cluster within one cluster | Cluster, supported namespace scope, or inherited Azure scope |
| Entra identities | Bind authenticated users or group object IDs | Assign roles to Entra users, groups, or service principals |
| Kubernetes service accounts | Native model | Continue to use Kubernetes RBAC |
| Multi-cluster grants | Apply manifests to each cluster | Assign at a common supported Azure parent scope |
| Diagnostic evidence | Role rules, binding subjects, audit logs | Assignment scope, principal, role data actions, propagation |

Kubernetes RBAC example: a namespace-scoped read grant to an Entra group.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: team-view
  namespace: app
subjects:
- kind: Group
  name: "<entra-group-object-id>"
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
```

The namespace must exist. A RoleBinding referencing a ClusterRole still grants permissions only within that namespace; it does not grant access to cluster-scoped nodes.

Equivalent Azure-assignment pattern for namespace read access:

```bash
AKS_ID=$(az aks show -g <rg> -n <cluster> --query id -o tsv)
az role assignment create \
  --assignee-object-id <entra-group-object-id> \
  --assignee-principal-type Group \
  --role "Azure Kubernetes Service RBAC Reader" \
  --scope "$AKS_ID/namespaces/app"
```

These are alternative grant examples, not identical rule sets. The built-in Kubernetes `view` role and Azure AKS RBAC Reader have their own definitions.

### 2.3 Built-in role names that are easily confused

| Azure role | Purpose |
|---|---|
| Azure Kubernetes Service Cluster User Role | Retrieve user kubeconfig through ARM; does not itself grant Entra users Kubernetes API permissions |
| Azure Kubernetes Service Cluster Admin Role | Retrieve local-admin kubeconfig, when local accounts are enabled |
| Azure Kubernetes Service RBAC Reader | Read most Kubernetes objects in scope; excludes Secrets and roles/bindings |
| Azure Kubernetes Service RBAC Writer | Read/write many workload objects; can access Secrets and run pods as service accounts, creating escalation considerations |
| Azure Kubernetes Service RBAC Admin | Administrative Kubernetes access in its assigned scope, with documented limitations |
| Azure Kubernetes Service RBAC Cluster Admin | Full Kubernetes API access across the cluster when assigned at cluster scope |

The presence or absence of **RBAC** in the role name matters.

### 2.4 Authorization composition

Kubernetes authorizers return allow, deny, or no opinion, and evaluation follows the configured chain. Native Kubernetes RBAC grants are additive; a missing RBAC grant is not an explicit deny.

On AKS, Kubernetes RBAC and Azure authorization can coexist. An applicable native RBAC grant can allow a request without a later webhook decision. Azure RBAC assignments do not subtract permissions already granted through Kubernetes bindings.

However, do not summarize all access as an unconditional "either role always wins":

- Identify the authenticated principal and whether it is an Entra identity or Kubernetes service account.
- Identify which authorizers apply to that identity and request.
- Distinguish no grant from explicit denial or an evaluation error.
- A request allowed by authorization can still be rejected by admission.
- Network access and successful authentication are prerequisites.

For a Cluster User assignment plus a Kubernetes binding that permits Secret creation, the Cluster User role merely permits kubeconfig retrieval. The Kubernetes binding is the grant to investigate for the Secret operation.

### 2.5 Managed Entra integration

With managed integration, AKS manages the Entra integration applications rather than requiring customers to maintain the legacy client/server app-registration setup.

Inspect the effective configuration:

```bash
az aks show -g <rg> -n <cluster> \
  --query '{
    kubernetesRbac:enableRbac,
    managedEntra:aadProfile.managed,
    tenant:aadProfile.tenantId,
    azureRbac:aadProfile.enableAzureRbac,
    adminGroups:aadProfile.adminGroupObjectIds,
    localAccountsDisabled:disableLocalAccounts
  }'
```

For managed Entra with Kubernetes RBAC, configured Entra admin groups provide bootstrap administrative access. Verify group **object IDs**, membership, and applicable ClusterRoleBindings rather than comparing display names.

Entra integration can be enabled on an existing supported RBAC cluster; once enabled it cannot be disabled. Azure RBAC authorization is a separate setting that can be enabled or disabled on supported AKS Standard clusters. AKS Automatic has preconfigured security defaults; do not assume every Standard toggle applies to Automatic.

---

## 3. User authentication and the kubectl request flow

### 3.1 User credentials versus admin credentials

| Property | `az aks get-credentials` | `az aks get-credentials --admin` |
|---|---|---|
| ARM operation | Retrieve cluster-user credentials | Retrieve cluster-admin credentials |
| Managed Entra kubeconfig | Endpoint, CA, context, and exec credential configuration | Local-admin client certificate and private key |
| Kubernetes authentication | Entra access token acquired by kubelogin | X.509 client certificate |
| Entra sign-in for subsequent kubectl calls | Required according to login mode/cache | Bypassed |
| Kubernetes privileges | Determined by applicable grants | Highly privileged local-admin access |
| Local accounts disabled | User path remains available | Credential retrieval is blocked |
| Network reachability required | Yes | Yes; admin does not bypass authorized IP ranges or private networking |

Both downloads are ARM operations. A successful download does not mean the workstation can reach the Kubernetes endpoint.

Do not use admin credentials as the routine fix for a user's `403`. They change the identity and bypass the path being diagnosed. Store any approved break-glass kubeconfig separately, restrict file permissions, and follow the local-account/certificate lifecycle procedure.

### 3.2 End-to-end kubectl get nodes flow

```text
1. Azure CLI -> ARM:
   download user kubeconfig, subject to Azure management-plane authorization

2. kubectl -> local exec plugin:
   kubelogin get-token, using the kubeconfig's tenant, audience, and login mode

3. kubelogin / selected credential source -> Entra token endpoint:
   obtain an access token for the AKS server application

4. kubectl -> API server over HTTPS:
   validate server certificate; send Authorization: Bearer <access-token>

5. API server -> configured authentication integration:
   validate credential and produce username, UID, groups, and related claims

6. API server -> applicable authorization chain:
   list core API resource "nodes" at cluster scope

7. API server -> storage/cache:
   return a NodeList if permitted
```

The token's audience must be the AKS server application, not ARM or Microsoft Graph. Use the audience and cloud configuration generated for the cluster rather than copying arbitrary IDs.

`kubectl get nodes` normally performs a **list** operation on `/api/v1/nodes`, not a Kubernetes authorization verb named `get`. Fetching a named node uses `get`. Discovery, version negotiation, and caching can produce additional requests.

Read-only requests such as listing nodes do not pass through the object-admission path used to validate creates and updates.

### 3.3 TokenReview, SubjectAccessReview, and Guard

| Mechanism | Responsibility |
|---|---|
| `ExecCredential` | Client plugin response carrying credentials back to client-go |
| `TokenReview` | Authentication API contract: map a token to an authenticated identity |
| `SubjectAccessReview` | Authorization API contract: evaluate a subject, verb, resource, and scope |
| `SelfSubjectAccessReview` | Evaluate the current caller; used by `kubectl auth can-i` |
| Guard | Open-source webhook implementation relevant to AKS Entra authentication and Azure authorization architecture |

In the webhook authentication model, the API server submits a TokenReview to the configured authenticator. The authenticator validates the token and returns identity information. In the Azure authorization webhook model, the API server delegates an authorization review and the integration evaluates Azure permissions through a check-access service.

Do not describe TokenReview and SubjectAccessReview as two API calls that `kubectl` explicitly sends for every ordinary request. They describe server-side interfaces; caches, native authorization decisions, and managed implementation details affect the actual calls.

Guard's public code is useful for understanding token validation, group resolution, OBO, and access checks. It is not proof of the exact version or configuration deployed in a particular AKS control plane. Guard is not a customer workload pod that must be installed or restarted to make managed Entra work.

### 3.4 Protocol-level sign-in and OBO

There are two different token acquisition stages:

1. **Client sign-in:** kubelogin uses its selected OAuth flow or credential source to acquire the AKS-audience token.
2. **Server-side delegated lookup, when required:** an authenticator can exchange the user token for a downstream token to resolve identity/group information.

For browser-based user sign-in, authorization code with PKCE uses an authorization endpoint, browser authentication/Conditional Access, and code redemption at the token endpoint. Device code uses a device-authorization request followed by polling while the user signs in elsewhere. Azure CLI mode reuses Azure CLI's signed-in identity and credential cache; it does not necessarily show a new sign-in prompt.

An OBO exchange conceptually looks like:

```http
POST /<tenant-id>/oauth2/v2.0/token HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&client_id=<middle-tier-application-id>
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<middle-tier-client-assertion>
&assertion=<incoming-user-access-token>
&requested_token_use=on_behalf_of
&scope=https://graph.microsoft.com/.default
```

This is a schematic form body, not a runnable request. The middle tier authenticates itself with a supported confidential-client credential; a client secret is another supported mechanism.

Important distinctions:

- The incoming token is intended for the middle-tier API. The downstream token has a different audience.
- OBO preserves delegated **user** context. It is not the app-only client-credentials flow.
- Downstream delegated permissions must have appropriate consent.
- OBO does not grant Kubernetes permissions. Kubernetes/Azure authorization is still required.
- Guard includes an OBO implementation for Graph-related lookup. Do not claim every managed AKS request performs a fresh Graph call or OBO exchange.
- Workload identity federation uses a service-account assertion in a client-credentials exchange; it is **not** this delegated-user OBO flow.

### 3.5 Kubernetes authentication types

The upstream Kubernetes authentication reference describes mechanisms, not a list of features customers can freely enable on managed AKS.

| Mechanism | Typical purpose or characteristic |
|---|---|
| X.509 client certificates | User, node, or system identity; subject CN maps to username and O fields to groups |
| Service-account tokens | Kubernetes workload identity to the API; prefer bound, projected, time-limited tokens |
| Bootstrap tokens | Limited node bootstrap use |
| Static token file | Server-configured bearer-token list; operationally difficult to rotate |
| JWT/OIDC authentication | Validate externally issued tokens against configured trust rules |
| Webhook token authentication | Delegate token validation using TokenReview |
| Authenticating reverse proxy | Trust identity headers from a specifically authenticated proxy |
| Anonymous access, when configured | `system:anonymous`; not a successful named-user sign-in |

An exec credential plugin is a **client-side acquisition mechanism**, not a new server-side authentication type. Kubernetes RBAC, Azure RBAC, and admission webhooks are not authentication methods.

Normal users are not Kubernetes `User` objects. ServiceAccounts are Kubernetes objects. Managed AKS controls which API server authentication configurations are supported.

### 3.6 Kubelogin and the removed azure auth plugin

The error:

```text
error: The azure auth plugin has been removed.
```

usually means the client is reading a legacy kubeconfig `auth-provider: azure` entry after the in-tree Azure authentication provider was removed from newer client-go/kubectl releases. This is a client configuration problem, not evidence that the AKS Entra feature is disabled.

AKS Entra user kubeconfig for Kubernetes 1.24 and later uses exec-plugin format. Old downloaded or copied kubeconfigs can still need conversion.

For an Azure CLI sign-in workflow:

```bash
az version
kubectl version --client
kubelogin --version
az login --tenant <tenant-id>
az account set --subscription <subscription-id>
az aks get-credentials -g <rg> -n <cluster> \
  --file <dedicated-kubeconfig>
kubelogin convert-kubeconfig \
  --kubeconfig <dedicated-kubeconfig> -l azurecli
kubectl --kubeconfig <dedicated-kubeconfig> get nodes
```

If `kubelogin` is missing, install the **Azure/kubelogin** binary using its official installation instructions and make it available on the invoking process's `PATH`. Do not accidentally install a different project's similarly named binary.

Inspect the selected user entry without dumping credential values:

```bash
kubectl --kubeconfig <dedicated-kubeconfig> config view --minify \
  -o jsonpath='{.users[0].user.exec.command}{"\n"}'
```

Conversion changes how credentials are acquired; it does not grant access. Keep kubectl within the supported version skew of the server.

### 3.7 Kubelogin login modes

| Mode | Credential source / flow | Appropriate use and limitations |
|---|---|---|
| `devicecode` | OAuth device authorization | Human sign-in without a local browser; can be blocked by Conditional Access |
| `interactive` | Browser authorization code flow | Human sign-in, including supported MFA/Conditional Access scenarios |
| `azurecli` | Azure CLI signed-in account | Reuse `az login`; check tenant, cloud, account, and `AZURE_CONFIG_DIR` |
| `azd` | Azure Developer CLI account | Reuse an `azd auth login` session |
| `spn` | Service principal secret or certificate | Non-interactive automation; credential lifecycle must be managed |
| `msi` | Managed identity endpoint in a supported Azure environment | Automation using an available managed identity; not arbitrary local workstation sign-in |
| `workloadidentity` | Federated token file and application/identity configuration | Secretless automation with a trusted external assertion |
| `azurepipelines` | Azure Pipelines federated service connection | Supported Azure DevOps pipeline environments; requires pipeline/service-connection context |
| `ropc` | Username/password grant | Legacy mode; incompatible with MFA and many Conditional Access policies; avoid for new automation |

Check the installed kubelogin version and the linked mode documentation for required flags/environment variables. Mode availability and cloud support can evolve.

### 3.8 Troubleshooting Entra cluster login and access

Follow the first failing boundary:

1. **Cluster/context:** verify subscription, resource, kubeconfig path, and current context.
2. **Network/TLS:** resolve the API hostname and test TCP/TLS from the actual client network. Inspect private DNS, VPN, proxy, routes, firewall, and authorized IP ranges.
3. **Credential acquisition:** verify kubelogin execution, login mode, cloud, tenant, account, expiry, and Conditional Access. Preserve the AADSTS code, UTC timestamp, request ID, and correlation ID.
4. **Authentication:** distinguish token issuance success from API acceptance. Check audience, issuer/tenant, token lifetime, and clock skew. Inspect claims locally without sharing token contents.
5. **Authorization:** test the exact verb/resource/scope and identify the role grant used.
6. **Admission:** if a write is rejected by a webhook, inspect the named policy and request object rather than adding roles.

Useful read-only checks:

```bash
az account show --query '{tenant:tenantId,subscription:id,user:user.name}'
kubectl config current-context
kubectl auth whoami
kubectl auth can-i list nodes
kubectl auth can-i get pods -n <namespace>
kubectl auth can-i create deployments.apps -n <namespace>
kubectl get rolebindings -n <namespace> -o yaml
kubectl get clusterrolebindings -o yaml
```

Some diagnostic commands themselves require permissions. `kubectl auth whoami` availability depends on server support. For impersonation-based testing, the tester needs impersonation permissions and the actual groups must be supplied; `--as` alone does not recreate an Entra sign-in.

For Azure role diagnosis:

```bash
AKS_ID=$(az aks show -g <rg> -n <cluster> --query id -o tsv)
az role assignment list \
  --assignee <principal-object-id> \
  --scope "$AKS_ID" --include-inherited --include-groups -o table
az role assignment list \
  --scope "$AKS_ID/namespaces/<namespace>" \
  --include-inherited -o table
```

Inspect the correct principal's direct and group grants, active PIM eligibility, namespace/cluster scope, role `DataActions`, and any conditions. Group expansion can require directory read access. New AKS Azure RBAC grants can take up to five minutes to propagate; do not treat propagation as the explanation without checking the assignment.

| Symptom | First investigation |
|---|---|
| ARM `AuthorizationFailed` while downloading kubeconfig | Credential-download `Actions`, scope, and Azure identity |
| Exec binary not found / removed auth plugin | Local tool and kubeconfig |
| AADSTS error before reaching API | Entra token acquisition, tenant, consent, Conditional Access |
| API `401 Unauthorized` | Token validation or credential failure |
| API `403` naming a user and forbidden verb | Authorization for that exact identity and scope |
| `403` naming `system:anonymous` | Missing credential/anonymous path, not proof the intended user authenticated |
| Denial naming a Gatekeeper webhook or constraint | Admission policy |
| TCP timeout | Network path or endpoint access, not an RBAC conclusion |
| TLS certificate failure | CA, hostname, clock, or TLS interception |

Use enabled AKS `kube-audit`/`kube-audit-admin` diagnostics and Entra sign-in logs to correlate identity, verb, resource, response, and time. Managed control-plane component logs may require support-side investigation; do not assume a customer-visible Guard pod exists.

---

## 4. Workload Identity

### 4.1 What workload identity is

Microsoft Entra Workload ID lets a pod exchange a Kubernetes service-account token for an Entra access token without storing an application secret.

Keep the identity scenarios separate:

| Identity | Main purpose |
|---|---|
| Human/service principal used by kubectl | Call the Kubernetes API |
| AKS control-plane managed identity | Manage Azure dependencies such as networking and disks |
| Kubelet identity | Node operations such as pulling from ACR |
| Federated workload identity | Application pod access to Azure resources such as Key Vault or Storage |

A managed identity is the Azure identity. Workload identity federation is a way for a pod to authenticate **as** a configured identity. These are complementary, not competing concepts.

Workload Identity still requires namespace isolation, service-account governance, and least-privilege Azure roles.

### 4.2 Federation flow and trust configuration

```text
pod creation
  -> workload identity mutating webhook selects labeled pod
  -> inject environment variables and a projected service-account token volume
  -> kubelet obtains/rotates a token through Kubernetes TokenRequest
  -> application SDK reads the projected assertion
  -> Entra token endpoint validates federated trust and token signature
  -> Entra returns a target-resource access token
  -> application calls Key Vault / Storage / another resource
  -> target resource evaluates permissions and network controls
```

For direct federation, match the following values:

| Field | Required value |
|---|---|
| Issuer | Exact cluster `oidcIssuerProfile.issuerUrl`, including its trailing slash |
| Subject | `system:serviceaccount:<namespace>:<service-account-name>` |
| Audience | `api://AzureADTokenExchange` for the standard Azure public-cloud configuration |
| Client ID | Client/application ID of the intended managed identity or app registration |
| Tenant ID | Tenant containing that identity/application |

Entra reads the issuer's OIDC discovery document and JWKS to validate the assertion signature, along with lifetime and the configured issuer/subject/audience match. The issuer exposes **public keys**, not the Kubernetes signing private key. A private Kubernetes API endpoint does not mean the OIDC discovery endpoint should be made private.

The service-account token and the resulting Entra access token are different tokens with different audiences. A federated credential establishes trust; it does **not** grant Key Vault or Storage permissions.

### 4.3 Minimal service account and pod configuration

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: app
  annotations:
    azure.workload.identity/client-id: "<managed-identity-client-id>"
---
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: app
  labels:
    azure.workload.identity/use: "true"
spec:
  serviceAccountName: app-sa
  containers:
  - name: app
    image: "<your-workload-identity-enabled-image>"
```

The namespace must exist. For Deployments, put the label under **`spec.template.metadata.labels`**, not only on the Deployment's own metadata.

The webhook normally injects:

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_FEDERATED_TOKEN_FILE`
- `AZURE_AUTHORITY_HOST`

Use a supported Azure Identity SDK with `WorkloadIdentityCredential` or an appropriate `DefaultAzureCredential` chain. The webhook does not rewrite arbitrary application authentication code.

Read the token path from `AZURE_FEDERATED_TOKEN_FILE`; do not hard-code the mount path. The SDK must reread refreshed assertions and renew access tokens. Updating a service-account annotation or pod-template label does not retroactively mutate existing pods; recreate them through a controlled rollout.

Create the trust on an existing user-assigned managed identity:

```bash
ISSUER=$(az aks show -g <rg> -n <cluster> \
  --query oidcIssuerProfile.issuerUrl -o tsv)
az identity federated-credential create \
  --name app-federation \
  --identity-name <identity-name> \
  --resource-group <identity-rg> \
  --issuer "$ISSUER" \
  --subject system:serviceaccount:app:app-sa \
  --audiences api://AzureADTokenExchange
```

Grant the identity the target service's required data-plane role at the narrowest appropriate resource scope separately.

### 4.4 Protocol-level exchange

The SDK uses a client-credentials request with the Kubernetes token as a client assertion:

```http
POST /<tenant-id>/oauth2/v2.0/token HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=<identity-client-id>
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<projected-service-account-token>
&scope=https://vault.azure.net/.default
```

This is schematic; the SDK performs encoding and credential handling. Sovereign clouds require their corresponding authority and resource endpoints.

The application sends the returned Entra token to Key Vault. Key Vault then independently evaluates data-plane authorization and firewall/private-endpoint controls. Successful federation does not prove the subsequent service request is authorized or routable.

### 4.5 Enable and disable behavior

On supported AKS Standard clusters, enable both capabilities after creation:

```bash
az aks update -g <rg> -n <cluster> \
  --enable-oidc-issuer --enable-workload-identity
```

Important lifecycle differences:

- **OIDC issuer can be enabled after creation but cannot be disabled once enabled.**
- Enabling OIDC issuer on an existing cluster restarts the API server; plan for a brief interruption.
- **Workload Identity can be disabled** using `az aks update --disable-workload-identity` on supported Standard configurations.
- Disabling Workload Identity is not disabling OIDC or automatically deleting federated credentials/target role assignments. Do not assume it immediately revokes already issued tokens.
- Newly created Standard clusters on Kubernetes 1.34 and later enable OIDC by default; existing clusters are not automatically enabled just by reaching that version.
- AKS Automatic preconfigures OIDC and workload identity. Check its managed configuration rules rather than applying every Standard lifecycle operation.

### 4.6 Troubleshooting workload identity

Collect evidence before changing the webhook or restarting pods:

```bash
az aks show -g <rg> -n <cluster> \
  --query '{oidc:oidcIssuerProfile,workloadIdentity:securityProfile.workloadIdentity}'
kubectl get serviceaccount -n <namespace> <service-account> -o yaml
kubectl get pod -n <namespace> <pod> -o yaml
kubectl describe pod -n <namespace> <pod>
kubectl logs -n <namespace> <pod> -c <application-container> --since=15m
az identity federated-credential list \
  -g <identity-rg> --identity-name <identity-name> -o json
```

Federated credentials on a managed identity are **Azure resources**, not built-in Kubernetes `FederatedIdentityCredential` objects. `kubectl get federatedidentitycredential` is not a generic AKS diagnostic.

Check in order:

1. **Selection:** the pod template has `azure.workload.identity/use: "true"` and the pod uses the intended service account.
2. **Mutation:** expected environment variables, projected volume audience, and mounts exist in the relevant container; inspect skip-container annotations if used.
3. **Application:** SDK supports workload identity; its credential chain is not selecting a different identity or stale secret first.
4. **Trust:** issuer/subject/audience exactly match the assertion and federated credential. Check client ID versus principal/object ID confusion, tenant, token lifetime, and recent-creation propagation.
5. **OIDC:** discovery and JWKS are available. An administrator's successful local curl is useful but does not by itself prove Entra can reach them.
6. **Exchange:** preserve the Entra error code and correlation ID. A token response proves federation, not resource authorization.
7. **Resource access:** verify the actual token identity, target data-plane role, scope, role propagation, service firewall, DNS, and private endpoint.

For a managed AKS deployment where the component is exposed, the requested diagnostic pattern is:

```bash
kubectl get pods -n kube-system \
  -l azure-workload-identity.io/system=true -o wide
kubectl logs -n kube-system \
  -l azure-workload-identity.io/system=true \
  --since=15m --prefix
```

An empty result does not prove the managed webhook is absent or broken. Managed component visibility varies. Use approved support-side diagnostics when required. An upstream self-managed installation commonly uses `azure-workload-identity-system` and `app=workload-identity-webhook`; do not substitute that installation model blindly for AKS.

Check public OIDC metadata without reading token contents:

```bash
ISSUER=$(az aks show -g <rg> -n <cluster> \
  --query oidcIssuerProfile.issuerUrl -o tsv)
curl --fail --silent --show-error \
  "${ISSUER%/}/.well-known/openid-configuration"
```

Fetch the `jwks_uri` returned by discovery and verify the assertion's signing-key ID exists there. Decode token claims only locally in a trusted environment; decoding alone does not validate the signature.

| Observation | Likely boundary |
|---|---|
| No injected variables or token volume | Pod label, service account, mutation, or pod predates configuration |
| `AADSTS70021` / no matching federated record | Issuer, subject, audience, wrong identity, or propagation |
| `AADSTS90061` | Entra cannot retrieve external OIDC metadata/keys |
| Token file missing/unreadable | Injection, container mounts, permissions, hard-coded path |
| Token acquired but Key Vault returns `403` | Target permissions or service network rules; inspect service error code |
| Works initially, fails after token expiry | SDK/refresh behavior or cached assertion contents |

---

## 5. API server authorized IP ranges

### 5.1 What they protect

Authorized IP ranges limit which public source addresses can communicate with the **public Kubernetes API endpoint**.

They do not:

- grant Kubernetes permissions
- protect application Ingress or LoadBalancer frontends
- filter pod-to-pod traffic
- restrict the ARM endpoint used to download kubeconfig
- replace private API-server networking

The feature is not used with private clusters. API Server VNet Integration has its own supported configuration and limits; distinguish it from a classic private-cluster design.

### 5.2 Source address and enforcement

```text
workstation / build agent / pod
  -> VPN, proxy, NAT Gateway, firewall, or load-balancer SNAT
  -> actual public source IP
  -> API endpoint authorized-range check
  -> TLS and Kubernetes authentication/authorization
```

The allowlist must contain the IP **seen at the API endpoint**, not the workstation's private address or a VPN-assigned address.

```bash
az aks show -g <rg> -n <cluster> \
  --query '{
    fqdn:fqdn,
    privateFqdn:privateFqdn,
    apiAccess:apiServerAccessProfile,
    outboundType:networkProfile.outboundType
  }'
```

Keep administrative networks and required cluster egress addresses in the design. Rules can take up to two minutes to propagate.

`0.0.0.0/32` is an AKS special placeholder for allowing the Standard Load Balancer's outbound public IP; it is **not** "allow all." `0.0.0.0/0` is an unrestricted IPv4 range.

### 5.3 Allowed IP still cannot connect

1. Confirm the exact API hostname and whether it resolves to the intended public or private endpoint.
2. Reproduce from the same agent/container/process context that fails. A browser, terminal, and CI job can use different proxies or routes.
3. Determine the source IP along the **API-server destination path** using NAT/firewall/proxy evidence. An internet "what is my IP" endpoint can take a different route and is not conclusive.
4. Verify CIDR membership and canonical network address. Check all possible egress IPs if NAT or the corporate proxy uses a pool.
5. Inspect current `authorizedIpRanges`, operation completion, and propagation time.
6. Verify TCP 443, TLS, local proxy settings, firewall, and return routing.
7. If the API returns `401` or an authenticated `403`, investigate credentials/permissions instead of broadening the allowlist.

Example transport checks:

```bash
nslookup <api-server-fqdn>
curl -v --connect-timeout 5 "https://<api-server-fqdn>/version"
```

A Kubernetes response, including an unauthenticated rejection, is evidence of transport reachability. If TLS fails, use the expected cluster CA for diagnosis rather than disabling certificate validation as a permanent workaround.

Updating ranges **replaces** the configured list. Preserve existing required CIDRs explicitly:

```bash
az aks update -g <rg> -n <cluster> \
  --api-server-authorized-ip-ranges <existing-cidr>,<additional-cidr>
```

Do not open `0.0.0.0/0` as the first troubleshooting step. Changing outbound IPs or moving automation to a new network requires updating the allowlist before cutover.

---

## 6. CVE handling

### 6.1 Triage the report, not only the version string

When a customer reports a CVE, establish:

1. **Finding:** CVE ID, scanner/database version, scan time, package path, image digest, installed version, and claimed fixed version.
2. **Location:** managed control plane, node OS, runtime binary, managed add-on, or customer image.
3. **Applicability:** OS distribution/release, architecture, build flags, affected configuration, and vendor advisory status.
4. **Exposure:** required privileges, reachability, enabled feature, and plausible impact.
5. **Remediation:** available AKS release/image, supported rollout, temporary mitigation, and owner.
6. **Verification:** prove the running component changed, then rescan the exact deployed artifact.

Do not promise a patch date based solely on a scanner severity. AKS assessment can differ from upstream scoring because deployment and hardening affect exposure. Absence of a fix requires an explicit mitigation/escalation plan, not a claim that the finding is resolved.

### 6.2 Ownership and remediation

| Affected layer | Primary response |
|---|---|
| Managed AKS control plane | Check AKS/MSRC advisory and supported release guidance; Microsoft services the managed components |
| Node OS/kernel | Identify OS SKU and image, vendor fixed package, upgrade channel, and reboot/reimage requirement |
| Runtime or node binary | Validate the actual binary/build; use an AKS-supported node image or Kubernetes update |
| AKS-managed add-on | Identify component image/version and supported AKS/add-on remediation |
| Customer application/base image | Customer rebuilds, scans, publishes a new immutable digest, and redeploys |
| Third-party installed controller | Follow supplier advisory and supported upgrade process |

Microsoft producing a patched node image is not the same as every node already running it. Likewise, patching a node does not replace a vulnerable library inside a customer container.

### 6.3 Prove the deployed versions

```bash
az aks show -g <rg> -n <cluster> \
  --query '{version:kubernetesVersion,upgrades:autoUpgradeProfile}'
az aks nodepool list -g <rg> --cluster-name <cluster> \
  --query '[].{pool:name,os:osSKU,image:nodeImageVersion,version:orchestratorVersion}' \
  -o table
kubectl get nodes \
  -o custom-columns='NAME:.metadata.name,OS:.status.nodeInfo.osImage,KERNEL:.status.nodeInfo.kernelVersion,RUNTIME:.status.nodeInfo.containerRuntimeVersion'
kubectl get pods -A \
  -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,IMAGES:.spec.containers[*].image,IMAGEIDS:.status.containerStatuses[*].imageID'
```

Include init containers, sidecars, and ephemeral containers when determining scope. A tag is mutable; record resolved digests and the affected node pool.

For Ubuntu, compare the **distribution package revision** with the Ubuntu CVE tracker and security notices. Vendors backport fixes without necessarily changing the upstream-looking version. A scanner reporting an old upstream string is neither proof of vulnerability nor proof of a false positive.

For Go components such as `containerd`, distinguish:

- OS packages
- the Go toolchain/standard library embedded in the binary
- statically linked Go module dependencies

In an approved diagnostic environment, `go version -m <binary-path>` can expose Go build/module information. Correlate that with the vendor's build/advisory or SBOM and a binary-aware scanner. Missing build metadata is not evidence that the binary is safe. Updating an unrelated OS package does not rebuild a statically linked binary.

### 6.4 Remediate and verify

For a node-image fix on a supported Standard node pool:

```bash
az aks nodepool get-upgrades \
  -g <rg> --cluster-name <cluster> -n <pool>
az aks nodepool upgrade \
  -g <rg> --cluster-name <cluster> -n <pool> \
  --node-image-only
```

Plan surge capacity, PodDisruptionBudgets, maintenance windows, and workload availability before executing an upgrade. Use the component's documented remediation if the fix requires a Kubernetes version or add-on update rather than only a node image.

After rollout:

- verify all affected pools/nodes and running pod image digests
- confirm required reboots/restarts occurred
- rescan with current vendor-aware vulnerability data
- document residual exposure and any time-limited exception

Use the AKS vulnerability-management guidance, AKS release notes/CVE issues, and vendor advisories. For a newly discovered security vulnerability, follow the MSRC private reporting process rather than posting sensitive details publicly.

---

## 7. Azure Policy for AKS

### 7.1 Architecture and installed components

Azure Policy for Kubernetes extends OPA Gatekeeper and connects cluster evaluation to Azure assignments and compliance reporting.

```text
Azure policy definition / initiative + assignment
  -> Azure Policy add-on synchronizes applicable configuration
  -> ConstraintTemplate defines policy logic and constraint schema
  -> Constraint supplies scope, parameters, and enforcement settings
  -> Gatekeeper validates matching admission requests
  -> Gatekeeper audits existing resources
  -> add-on reports compliance to Azure Policy
```

| Component/resource | Function |
|---|---|
| `addonProfiles.azurepolicy` | Records add-on enablement and, where applicable, its Azure identity |
| `azure-policy` components in `kube-system` | Synchronize assignments/artifacts and report compliance |
| Gatekeeper controller in `gatekeeper-system` | Serves admission validation and manages policy artifacts |
| Gatekeeper audit component | Evaluates existing objects and records violations |
| Webhook configurations, Services, certificates | Allow the API server to call admission components |
| CRDs including ConstraintTemplates and constraint kinds | Represent reusable logic and instantiated policy |
| ServiceAccounts, RBAC, Deployments, configuration | Support controllers and their permissions |

Mutation templates and other artifacts depend on assigned policies and add-on capabilities. Do not claim every installation creates every possible template or policy resource.

```bash
az aks show -g <rg> -n <cluster> --query addonProfiles.azurepolicy
kubectl get pods -n kube-system
kubectl get pods,deployments,services -n gatekeeper-system
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations
kubectl get constrainttemplates
kubectl api-resources --api-group=constraints.gatekeeper.sh
```

A separate customer-installed Gatekeeper alongside the Azure Policy add-on is not a supported installation model. Follow the documented migration process rather than deploying competing controllers/webhooks.

### 7.2 Definition, initiative, assignment, and constraint

| Term | Meaning |
|---|---|
| Definition | Rule logic, parameters, mode, and effect |
| Initiative | Group of definitions for a compliance objective |
| Assignment | Applies a definition/initiative to a scope with parameter values |
| Exemption/exclusion | Changes which resources are evaluated or exempted |
| ConstraintTemplate | Gatekeeper logic/schema delivered to Kubernetes |
| Constraint | Instantiated rule, matching scope, parameters, and enforcement |

Kubernetes resource policies commonly use Azure Policy mode `Microsoft.Kubernetes.Data`. Policies that audit the ARM AKS resource itself are a different evaluation path from admission of Kubernetes Pods.

### 7.3 Are policies automatically applied?

Enabling the add-on installs the integration; it does **not**, by itself, mean every built-in definition is assigned or that a universal default deny policy exists.

Effective policies can already be inherited from management group, subscription, or resource-group assignments. Defender for Cloud onboarding and AKS Automatic/deployment safeguards can also introduce applicable assignments or managed defaults. Check the actual cluster and governance scope.

Find applicable assignments:

```bash
AKS_ID=$(az aks show -g <rg> -n <cluster> --query id -o tsv)
az policy assignment list --scope "$AKS_ID" \
  --disable-scope-strict-match -o json
az policy definition show --id <policy-definition-id>
az policy assignment show --ids <policy-assignment-id>
```

Review inheritance, `notScopes`, exemptions, parameters, effect, enforcement mode, and namespace exclusions. Do not modify Microsoft's built-in definitions. Change the assignment's supported parameters or create and assign a custom definition when the built-in cannot express the requirement.

### 7.4 Find noncompliant Kubernetes resources

1. In Azure Policy **Compliance**, select the applicable assignment and cluster.
2. Open component-level details to identify the Kubernetes kind, namespace, name, and reason.
3. Inspect the corresponding cluster constraint:

   ```bash
   kubectl get constrainttemplates
   kubectl api-resources --api-group=constraints.gatekeeper.sh
   kubectl get <constraint-kind>
   kubectl get <constraint-kind> <constraint-name> -o yaml
   ```

4. Check `status.auditTimestamp`, `status.totalViolations`, `status.violations`, and controller errors. Listed violations can be capped; do not assume a short list is the complete inventory.
5. Map the constraint back to Azure using annotations:

   ```text
   azure-policy-definition-id
   azure-policy-assignment-id
   azure-policy-definition-reference-id
   azure-policy-setdefinition-id
   ```

Definition ID identifies the rule; assignment ID identifies where and with which parameters it applies. This matters when an initiative or multiple assignments use the same definition.

### 7.5 Why noncompliant pods can keep running

Admission checks apply to matching API operations; they are not a background eviction mechanism.

- `audit` reports violations without denying creation.
- A `deny` assignment does not automatically delete pods that existed before the policy took effect.
- A replacement pod can be denied on recreation even though the old pod kept running.
- Excluded namespaces, exemptions, selectors, enforcement mode, and synchronization delays can change the result.
- Controller objects and Pods are different resources. A Deployment can be accepted while its ReplicaSet fails to create Pods.

```bash
kubectl describe deployment -n <namespace> <deployment>
kubectl describe replicaset -n <namespace> <replicaset>
kubectl get events -n <namespace> --sort-by=.lastTimestamp
```

Look for `FailedCreate` and the named admission webhook/constraint on the ReplicaSet. Adding an Azure role does not fix a compliant-configuration rejection.

### 7.6 Troubleshoot policy ingestion, enforcement, and reporting separately

| Symptom | Evidence to inspect |
|---|---|
| Assignment exists but no constraint | Effective scope, supported definition, parameters, sync status, add-on identity/egress, template conflicts |
| Constraint exists but request passes | Matching kind/namespace/operation, exclusions, effect, enforcement mode, webhook health and matching rules |
| Unexpected admission denial | Exact object/operation, constraint message, parameters, additional admission controllers |
| Existing violations not reported | Gatekeeper audit health, inventory/sync settings, assignment activity, reporting timestamps |
| Deployment succeeds but no Pods | ReplicaSet events and Pod-admission denial |
| Webhook timeout | Service/endpoints, ready controller pods, certificates, API-server-to-webhook connectivity |

Inspect logs from the discovered pods:

```bash
kubectl logs -n kube-system <azure-policy-pod> \
  --all-containers=true --since=30m
kubectl logs -n gatekeeper-system <gatekeeper-controller-pod> \
  --all-containers=true --since=30m
kubectl logs -n gatekeeper-system <gatekeeper-audit-pod> \
  --all-containers=true --since=30m
```

The add-on checks assignments and reports audit results periodically; the documented regular cycle is approximately 15 minutes. Compliance reports include historical evaluation windows, so they are not synchronous proof of the most recent request. Check the installed add-on version and observed timestamps.

Do not hand-edit Azure-managed constraints to make a denial disappear. The add-on can overwrite them; update the assignment/definition through the supported source of truth.

### 7.7 Custom policy workflow

1. Define the requirement and target Kubernetes kinds/operations precisely.
2. Reuse an appropriate Gatekeeper template or author/test policy logic.
3. Create an Azure Policy custom definition in the appropriate mode, referencing the template and constraint parameters.
4. Assign it at a scope containing the AKS resource, initially using audit or disabled enforcement as appropriate.
5. Verify synchronization, matching, violations, and admission behavior with both compliant and noncompliant examples.
6. Roll out deny only after reviewing existing workloads, exclusions, system namespaces, and recovery procedures.

Keep policy tests focused on resource behavior, not just whether the definition was accepted by ARM.

### 7.8 Azure Policy versus RBAC

| RBAC | Azure Policy / admission |
|---|---|
| May **this identity** perform this action? | Is **this resource/request** permitted by governance rules? |
| Grants verbs/data actions within a scope | Evaluates properties such as image source, privilege, labels, or security context |
| Evaluated during authorization | Kubernetes policy admission is evaluated after authentication/authorization |
| Does not make an unsafe spec compliant | Does not grant an identity the right to create the object |

A user can pass RBAC and fail policy. A compliant object can still be rejected because the caller lacks authorization. Cluster-admin authorization is not a general exemption from admission policy.

---

## 8. Network policy

### 8.1 Kubernetes NetworkPolicy semantics

NetworkPolicy is enforced by a compatible network-policy engine, not merely by storing YAML in the API.

- A pod starts non-isolated for a direction until selected by a policy covering that direction.
- Applicable standard NetworkPolicies are **additive allowlists**, not an ordered first-match deny list.
- Selected ingress and egress directions are independent.
- A new pod-to-pod connection must satisfy source egress and destination ingress isolation, if present.
- Reply traffic for an allowed connection is implicitly allowed.
- A policy's `podSelector` selects destination/source workload pods in the policy's own namespace.
- A peer `podSelector` alone selects peers in the policy namespace.
- A `namespaceSelector` and `podSelector` in the **same peer item** are ANDed.
- Separate peer items are ORed.
- NetworkPolicy does not grant Kubernetes API permissions or validate pod security settings.

### 8.2 Azure NPM versus Calico versus Cilium

| Aspect | Azure NPM | AKS-managed Calico | Azure CNI powered by Cilium |
|---|---|---|---|
| Supported networking | Azure CNI | Azure CNI; legacy Kubenet on Linux | Azure CNI supported IPAM modes |
| Linux mechanism | iptables/ipsets | Felix programs Linux policy rules, typically iptables in this managed model | eBPF policy/data plane |
| Windows | NPM support ended 30 September 2026 | Supported configurations use Windows policy/HNS machinery | Linux data plane; do not assume Windows parity |
| Kubernetes NetworkPolicy | Supported within documented limits | Supported | Supported |
| Additional policy APIs | No general Calico/Cilium APIs | AKS support is for `networking.k8s.io` policies, not arbitrary Calico enterprise/global features | Supported extensions vary by AKS feature/version; verify availability |
| Observability | NPM logs, metrics, iptables/ipset state | Calico/Felix logs and node rules | Cilium endpoint/policy state and supported Hubble/drop tooling |

As of this guide's October 2026 review, Azure NPM on Linux is scheduled to retire on **30 September 2028**. Its documented limits include 250 nodes/20,000 pods and no IPv6 support. Prefer the supported Cilium path for new Linux deployments and plan migrations using the current AKS matrix.

Kubenet retires on **31 March 2028**. Do not infer that choosing Calico makes an unsupported networking/OS combination supported.

### 8.3 How a policy becomes node rules

For Azure NPM on Linux:

```text
NetworkPolicy / Namespace / Pod API changes
  -> NPM watches and reconciles selected endpoints
  -> selectors become IP-set membership
  -> ingress/egress peer and port rules become iptables chains/rules
  -> node packet path evaluates those rules
  -> counters/logs and packet evidence show the decision
```

Each node's policy agent maintains local enforcement state based on API watch/reconciliation. Label changes and pod-IP changes require updates even when the policy YAML itself is unchanged.

Azure NPM does not translate each NetworkPolicy into an Azure NSG rule. Calico and Cilium also reconcile policy to node enforcement, but their APIs, state, and packet-processing mechanisms differ.

Rule installation is not instantaneous. Check controller health and convergence before concluding a new policy is ineffective. Established connections can survive rule changes due to connection tracking; test a **new connection**.

### 8.4 Example: allow only a specific client group

This policy selects `app=api` pods in namespace `app` and allows ingress on TCP 8080 only from `app=frontend` pods in namespaces labeled `team=web`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-from-web
  namespace: app
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          team: web
      podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

The two selectors are in the same peer item, so both must match. Another applicable ingress policy can grant additional access; this policy does not override broader grants. Source egress isolation can still block the connection.

An egress-isolated application also needs DNS permission to the actual DNS path, typically UDP **and** TCP 53. CoreDNS, LocalDNS, and NodeLocal DNS designs can expose different destination addresses; inspect the cluster instead of copying a universal DNS rule.

### 8.5 Troubleshoot policy not working as expected

Define one expected flow:

```text
source pod/namespace/node/labels
  -> destination pod or Service address
  -> translated destination endpoint
  -> protocol and port
  -> new connection at a known UTC time
```

Collect desired state:

```bash
az aks show -g <rg> -n <cluster> \
  --query '{
    plugin:networkProfile.networkPlugin,
    mode:networkProfile.networkPluginMode,
    policy:networkProfile.networkPolicy,
    dataplane:networkProfile.networkDataplane
  }'
kubectl get pods -A -o wide --show-labels
kubectl get namespaces --show-labels
kubectl get networkpolicy -A
kubectl describe networkpolicy -n <namespace> <policy>
kubectl get service,endpointslice -n <namespace>
kubectl get daemonsets,pods -n kube-system -o wide
```

Then:

1. Verify the destination listens on the target port and has ready endpoints.
2. Check all policies selecting either endpoint; include unexpected broad allows.
3. Verify ingress/egress `policyTypes`, labels, namespace scope, AND/OR structure, IP blocks, numeric/named ports, and protocol.
4. Compare direct pod IP and Service access; then same-node and cross-node access.
5. Test a new connection and separate DNS failure from TCP failure.
6. Identify the actual policy agent on the affected node. Check restarts, OOM, watch/reconciliation errors, and timing.
7. Compare installed node state with desired rules and observe the matching flow.
8. If no policy drop is proven, continue through Service translation, route, NSG, firewall, and return path.

For discovered Azure NPM pods:

```bash
kubectl logs -n kube-system <azure-npm-pod-on-affected-node> \
  --since=15m --all-containers=true
```

Through an approved node diagnostic session, read-only Linux checks can include:

```bash
iptables-save -c
ipset list
```

Use the backend/tooling appropriate to the node. Inspect source/destination set membership, chain placement, matching counters, and conntrack rather than editing AKS-managed rules by hand.

### 8.6 LoadBalancer traffic, NAT, and PlaceAzureChainFirst

Service processing can DNAT the destination and SNAT the source. Policy may therefore see a pod address, node address, or original client address depending on the data plane and traffic path.

For external traffic that unexpectedly stopped after an NPM/AKS update:

- Record the NPM image, Kubernetes version, and actual feature/configuration state.
- If the build exposes `PlaceAzureChainFirst` or a related chain-order change, inspect where the Azure policy chain sits relative to Service translation and established-flow handling.
- Compare `externalTrafficPolicy: Cluster` and `Local`, node/endpoint placement, observed source address, and policy `ipBlock`/selector matches.
- Capture before and after the suspected NAT/policy boundary and correlate rule counters.
- Check the version-specific advisory before applying a workaround. Do not universally disable a flag or broaden policy based on the flag name alone.

For source restrictions on a LoadBalancer frontend, use the supported Service `loadBalancerSourceRanges` configuration where appropriate. This addresses frontend source filtering; it is not a universal substitute for pod-level policy.

### 8.7 Cilium drop evidence

On a Cilium cluster, discover the relevant agent and inspect it:

```bash
kubectl get pods -n kube-system -l k8s-app=cilium -o wide
kubectl logs -n kube-system <cilium-pod-on-affected-node> \
  -c cilium-agent --since=15m
```

Where supported, use the agent's available CLI (`cilium-dbg` on current builds, `cilium` on some older builds) for status, endpoint/policy inspection, and drop monitoring:

```text
cilium-dbg status --verbose
cilium-dbg monitor --type drop
hubble observe --verdict DROPPED
```

Run agent diagnostics in the appropriate agent environment. Hubble requires supported deployment/access; these binaries are not assumed to be installed on a workstation.

Match source/destination identities, five-tuple, node, time, and drop reason. A matching policy-denied event proves a policy decision; a generic timeout does not. No observed drop is not proof of allow if the observer is on the wrong node or did not capture the flow.

---

## 9. Troubleshooting method

Use one failing request and one controlled comparison:

| First failing boundary | Next useful evidence | Avoid |
|---|---|---|
| Cannot retrieve kubeconfig | ARM error, management role/scope | Assigning Kubernetes roles without reading the ARM failure |
| Cannot execute credential plugin | Current kubeconfig entry, binary/version/PATH | Rotating cluster certificates |
| Cannot acquire Entra token | AADSTS code, tenant, login mode, sign-in log | Treating all sign-in failures as Kubernetes RBAC |
| Cannot reach API endpoint | DNS/TCP/TLS, actual egress IP, private path | Broadening RBAC |
| API rejects credential | Token audience/issuer/lifetime, authentication logs | Using admin kubeconfig and declaring user login repaired |
| API forbids resource action | Actual identity, exact verb/resource/scope, applicable grants | Confusing Cluster User with RBAC Cluster Admin |
| Write rejected by policy | Constraint, object, webhook, controller events | Assuming cluster-admin bypasses policy |
| Pod cannot obtain resource token | Mutation, projected assertion, federated trust | Assuming Azure resource role assignment creates federation |
| Token works, resource rejects access | Resource data role and network controls | Recreating the workload identity blindly |
| Pod connection fails | Selectors, active engine, translated packet, flow evidence | Assuming every timeout is NetworkPolicy |

Record UTC time, request/correlation IDs, cluster/pool/component versions, the expected behavior, and the smallest reproducer. Capture evidence before restarting controllers or changing grants.

---

## 10. Interview question index

The detailed sections above are the canonical answers. This index maps the sample questions covered in this guide to their complete answers.

| Topic / sample question | Complete answer |
|---|---|
| Difference between Azure RBAC integration and Kubernetes RBAC? | [RBAC comparison](#22-kubernetes-rbac-versus-azure-rbac-for-kubernetes) |
| How do Kubernetes RBAC, Entra integration, and Azure RBAC relate? | [Three features](#21-the-three-features-and-their-relationship) and [composition](#24-authorization-composition) |
| Azure RBAC cluster: get-credentials with versus without admin? | [User versus admin credentials](#31-user-credentials-versus-admin-credentials) |
| What happens behind `kubectl get nodes`? | [End-to-end flow](#32-end-to-end-kubectl-get-nodes-flow) |
| What Kubernetes authentication types exist? | [Authentication types](#35-kubernetes-authentication-types) |
| Troubleshooting steps when a user cannot log in to an Entra cluster? | [Login and access troubleshooting](#38-troubleshooting-entra-cluster-login-and-access) |
| Explain user authentication, access grants, and authorization at protocol level. | [Request flow](#32-end-to-end-kubectl-get-nodes-flow), [OBO](#34-protocol-level-sign-in-and-obo), and [grant examples](#22-kubernetes-rbac-versus-azure-rbac-for-kubernetes) |
| How to resolve the removed Azure auth plugin error / 1.24 requirements? | [Kubelogin remediation](#36-kubelogin-and-the-removed-azure-auth-plugin) |
| How does managed Entra leverage kubelogin? | [Managed integration](#25-managed-entra-integration) and [client/server contracts](#33-tokenreview-subjectaccessreview-and-guard) |
| Describe kubelogin login modes. | [Login modes](#37-kubelogin-login-modes) |
| What is Workload Identity and how does it work? | [Identity scenarios](#41-what-workload-identity-is), [federation flow](#42-federation-flow-and-trust-configuration), and [exchange](#44-protocol-level-exchange) |
| How to troubleshoot environment variables, mutation, and federation? | [Workload identity troubleshooting](#46-troubleshooting-workload-identity) |
| Can OIDC issuer / workload identity be enabled or disabled after creation? | [Lifecycle behavior](#45-enable-and-disable-behavior) |
| What are authorized IP ranges and how do they work? | [Scope](#51-what-they-protect) and [source-address flow](#52-source-address-and-enforcement) |
| Why can an allowed IP still be blocked? | [Allowed IP troubleshooting](#53-allowed-ip-still-cannot-connect) |
| What should be considered when a customer reports an AKS CVE? | [Triage](#61-triage-the-report-not-only-the-version-string), [ownership](#62-ownership-and-remediation), and [verification](#64-remediate-and-verify) |
| How is Azure Policy integrated; which components are installed and why? | [Architecture and resources](#71-architecture-and-installed-components) |
| Which Kubernetes resources are noncompliant? | [Compliance investigation](#74-find-noncompliant-kubernetes-resources) |
| Are predefined policies automatically applied, and how are they modified? | [Effective assignments](#73-are-policies-automatically-applied) |
| How to create a custom Kubernetes Azure Policy? | [Custom policy workflow](#77-custom-policy-workflow) |
| Difference between Azure Policy and RBAC? | [Policy versus RBAC](#78-azure-policy-versus-rbac) |
| Azure NPM versus Calico: compatibility, mechanism, and support scope? | [Engine comparison](#82-azure-npm-versus-calico-versus-cilium) |
| How to troubleshoot Azure network policy not working as expected? | [Troubleshooting](#85-troubleshoot-policy-not-working-as-expected) and [NAT/chain order](#86-loadbalancer-traffic-nat-and-placeazurechainfirst) |
| How does a policy become rules on nodes? | [Node programming](#83-how-a-policy-becomes-node-rules) |

### 10.1 Entra-enabled cluster: get pods returns an unexpected result

**Feedback focus:** Locate the failing boundary before changing authentication or authorization settings.

1. A customer enabled Microsoft Entra integration, but `kubectl get pods` does not return the expected pods. What information do you collect before deciding this is an authentication failure?
2. How do you verify the active kubeconfig context, namespace, signed-in identity, and cluster configuration? Which fields in `aadProfile`, `enableRbac`, and `apiServerAccessProfile` distinguish the relevant access paths?
3. How would `kubectl get pods -n <namespace> --v=8` help locate the failure? Which request URL, response status, error body, and timestamps matter, and what must be sanitized before sharing the output?
4. How do you distinguish a credential-plugin failure, Entra sign-in failure, TCP timeout, TLS error, `401`, authorization `403`, and a successful empty PodList?
5. Why does successfully downloading kubeconfig or signing in through a browser not prove permission to list pods?

**Answer checkpoints:** `kubectl get pods` requires `list` on pods in the selected namespace; retrieving a named pod uses `get`. Confirm context, namespace, and any selectors before interpreting an empty result as an access failure. Verbose output is diagnostic evidence, not a reason to expose tokens or raw credentials.

**Complete answers:** [Security boundaries](#1-core-concepts-and-security-boundaries), [request flow](#32-end-to-end-kubectl-get-nodes-flow), and [login/access troubleshooting](#38-troubleshooting-entra-cluster-login-and-access).

### 10.2 Managed Entra authentication and the OBO flow

**Feedback focus:** Explain the protocol interactions, not only "the webhook checks with Entra."

1. Trace an Entra user's `kubectl get pods` from the kubeconfig exec entry through kubelogin, token acquisition, HTTPS, authentication, authorization, and the API response.
2. What audience should the token sent to the Kubernetes API have? Why is an ARM or Microsoft Graph access token not interchangeable with that token?
3. What is the distinction between kubelogin's `ExecCredential` response, a server-side TokenReview, and an authorization SubjectAccessReview?
4. In a delegated OBO exchange, who is the client, middle tier, identity provider, and downstream API? What are the audiences of the incoming and outgoing tokens?
5. Explain `assertion`, the middle tier's client credential, `requested_token_use=on_behalf_of`, requested scopes, and consent. Why does this exchange not itself grant permission to list pods?
6. When can Guard use OBO for a downstream identity/group lookup? Why is it inaccurate to assume every kubectl request triggers a new OBO exchange or Graph request?
7. How do device code, browser-based authorization code, and Azure CLI login modes differ? How can MFA or Conditional Access change the expected user interaction?

**Answer checkpoints:** Separate client sign-in from server-side validation and optional delegated lookups. OBO preserves user context; workload identity federation uses a different, app-only client-credentials exchange. Managed implementation and caching details must be supported by evidence rather than inferred from a conceptual diagram.

**Complete answers:** [Client/server contracts and Guard](#33-tokenreview-subjectaccessreview-and-guard), [protocol-level sign-in and OBO](#34-protocol-level-sign-in-and-obo), and [kubelogin modes](#37-kubelogin-login-modes).

### 10.3 Precise RBAC diagnosis when Cluster Admin is present

**Feedback focus:** Identify the actual identity, exact role, scope, and denied operation.

1. A customer says, "I have Cluster Admin, but `kubectl get pods -n app` returns `403`." Which exact Azure role names do you ask them to distinguish, and why?
2. What is the difference between **Azure Kubernetes Service Cluster Admin Role**, **Azure Kubernetes Service RBAC Cluster Admin**, and a Kubernetes `cluster-admin` ClusterRoleBinding?
3. The customer's role assignment looks correct. How do you prove that kubectl is using the intended Entra identity rather than another exec login, a service account, or an admin certificate?
4. Which checks distinguish a wrong principal/object ID, inactive PIM assignment, group-membership problem, namespace-only scope, insufficient `DataActions`, and assignment propagation?
5. How do you use `kubectl auth can-i list pods -n app` and the actual API error together? What additional evidence is needed if the forbidden username is `system:anonymous`?
6. Does assigning Azure **Contributor** fix every Kubernetes `403`? How do management-plane `Actions` differ from Kubernetes API `DataActions`?
7. How do Kubernetes RBAC and Azure RBAC coexist? Why can inspecting Azure assignments alone miss a native Kubernetes grant?
8. A privileged user can list pods but cannot create a particular pod. How do you distinguish an authorization failure from an admission-policy denial? Would `--admin` bypass authorized IP ranges or admission checks?

**Answer checkpoints:** A role that permits downloading admin kubeconfig does not turn an existing Entra user kubeconfig into admin credentials. A valid AKS RBAC Cluster Admin assignment at cluster scope should grant Kubernetes authorization to its intended principal, but the wrong identity, credential failure, network boundary, or admission policy is a different problem. Do not prescribe Contributor or a broader allowlist without identifying the failing boundary.

**Complete answers:** [Role-name distinctions](#23-built-in-role-names-that-are-easily-confused), [authorization composition](#24-authorization-composition), [user/admin credentials](#31-user-credentials-versus-admin-credentials), and [403 diagnosis](#38-troubleshooting-entra-cluster-login-and-access).

### 10.4 Workload Identity and federated credential validation

**Feedback focus:** Explain Issuer, Subject, Audience, and how the assertion is validated.

1. A pod must read an Azure Key Vault secret. Which Azure identity, service account, pod configuration, federated credential, target-resource role, and application SDK behavior are required?
2. What does **Issuer** identify, and where do you obtain its exact value? Why can omitting the trailing slash break federation?
3. What does **Subject** identify? Construct the subject for service account `app-sa` in namespace `app`, and explain why moving the workload to another namespace changes the trust match.
4. What is the projected assertion's **Audience**, and how does it differ from the audience/scope of the Entra token used to call Key Vault?
5. How do OIDC discovery, JWKS, signing-key ID, signature, issuer, subject, audience, and token lifetime participate in validation? Why is merely decoding a JWT insufficient?
6. Which pod label, service-account annotation, environment variables, and projected volume prove mutation occurred? Why does changing a Deployment label outside its pod template not configure new pods correctly?
7. Explain why a federated credential does not grant access to Key Vault. If token acquisition succeeds but Key Vault returns `403`, which permission and network controls do you inspect?
8. How do you distinguish a missing token file, `AADSTS70021`, `AADSTS90061`, an unsupported SDK, a credential chain choosing another identity, and failed token renewal?

**Answer checkpoints:** For the example, the subject is `system:serviceaccount:app:app-sa`; the standard exchange audience is `api://AzureADTokenExchange`. The application exchanges a Kubernetes assertion for an Entra token and then calls Key Vault. Validate mutation, federation, resource authorization, and network access as separate stages; the AKS cluster does not automatically gain access on behalf of every pod.

**Complete answers:** [Federated trust](#42-federation-flow-and-trust-configuration), [pod configuration](#43-minimal-service-account-and-pod-configuration), [token exchange](#44-protocol-level-exchange), and [troubleshooting](#46-troubleshooting-workload-identity).

### 10.5 Authorized IP ranges and misleading access symptoms

**Feedback focus:** Explain the supported behavior without assuming an undocumented NSG topology.

1. What does an API-server authorized IP range protect, and which observed source IP must be included when the client uses a VPN, proxy, firewall, or NAT Gateway?
2. The customer's workstation IP appears allowed, but kubectl times out. How do you verify the actual egress path, endpoint/DNS selection, all possible NAT addresses, CIDR membership, and propagation?
3. Why is "the control plane has two NSGs, one allow and one deny" not a sufficient explanation of the feature or a basis for editing AKS-managed infrastructure?
4. If the intended API endpoint returns a `403` naming the authenticated user and forbidden verb, why should you investigate authorization rather than assume the source IP was rejected?
5. Does `az aks get-credentials --admin` bypass the authorized IP check? Does successful kubeconfig retrieval prove the API endpoint is reachable?

**Answer checkpoints:** Describe the public API endpoint's source-address restriction and prove the observed traffic path. Internal implementation assumptions are not a customer configuration contract. Keep ARM credential retrieval, network access, and Kubernetes authorization separate.

**Complete answers:** [Authorized-range scope](#51-what-they-protect), [source-address flow](#52-source-address-and-enforcement), and [allowed-source troubleshooting](#53-allowed-ip-still-cannot-connect).

### 10.6 CVE validation and patch verification

**Feedback focus:** Establish applicability and prove remediation rather than relying on image age.

1. A scanner reports a CVE in AKS. How do you identify whether it belongs to a managed component, node OS, runtime binary, managed add-on, or customer image?
2. The node image is less than 30 days old. Does that prove the CVE is fixed? What does the AKS guidance about vendor-fixed CVEs and updated images actually require you to verify?
3. How do you use a scanner such as Trivy alongside vendor advisories, package revisions, image digests, node image versions, and the scanner database date?
4. Why can an old-looking Ubuntu package version already contain a backported fix? Conversely, why does an updated OS package not prove that a statically linked Go binary such as `containerd` was rebuilt?
5. Which evidence proves the fix is running on every affected node or pod after an upgrade? What changes if the vendor has not released a fix?

**Answer checkpoints:** Neither "latest image" nor an age threshold is a universal guarantee. Confirm the affected artifact, vendor fix, deployed build, rollout completion, and rescan result. Distinguish Microsoft patch availability from customer deployment of that patch.

**Complete answers:** [CVE triage](#61-triage-the-report-not-only-the-version-string), [ownership](#62-ownership-and-remediation), [deployed-version evidence](#63-prove-the-deployed-versions), and [remediation verification](#64-remediate-and-verify).

### 10.7 Azure Policy components and assignment synchronization

**Feedback focus:** Identify each component's responsibility and the source of truth.

1. After enabling the Azure Policy add-on, which Azure-side settings and Kubernetes components do you expect, and what does each do?
2. Explain the relationship between an Azure Policy definition, initiative, assignment, Gatekeeper ConstraintTemplate, and constraint.
3. A customer installed Gatekeeper independently and now wants to enable the add-on. Is running both installations supported, and what documented migration checks are needed?
4. A policy assignment exists in Azure but no corresponding constraint appears. How do you investigate scope, inheritance, synchronization, definition/template errors, identity, and required egress?
5. Which constraint annotations identify the Azure definition and the actual assignment? Why is the definition ID alone insufficient when multiple assignments use the same definition?

**Answer checkpoints:** Azure Policy synchronizes and reports; Gatekeeper performs matching admission evaluation and audit. Enabling the add-on is not equivalent to assigning every built-in policy. Inspect synchronization evidence and update Azure-managed artifacts at their supported source of truth.

**Complete answers:** [Architecture](#71-architecture-and-installed-components), [policy objects](#72-definition-initiative-assignment-and-constraint), [effective assignments](#73-are-policies-automatically-applied), and [policy diagnostics](#76-troubleshoot-policy-ingestion-enforcement-and-reporting-separately).

### 10.8 Azure Policy enforcement, running pods, and exemptions

**Feedback focus:** Explain admission-time enforcement separately from audit and compliance reporting.

1. A deny policy is assigned, but existing noncompliant pods are still running. Why is this expected, and what can happen when a replacement pod is created?
2. A Deployment is accepted, but no pods start. Which ReplicaSet events and webhook/constraint messages distinguish admission denial from scheduling or image-pull failure?
3. Is `audit` a policy effect? How does it differ from `deny`, `disabled`, and an assignment with enforcement disabled? Why is "only effect makes a policy work" an incorrect distinction?
4. A new noncompliant pod is accepted. How do you check the effective assignment, policy parameters, namespace exclusions, match selectors, exemptions, enforcement settings, webhook configuration, and synchronization time?
5. How do Azure scope exclusions (`notScopes`), policy exemptions, and Kubernetes namespace exclusions differ? At which layer do you inspect each rather than assuming a single exemption switch in the definition?
6. The portal still shows noncompliance after a fix. How do you correlate the audit timestamp, current constraint violations, add-on reporting cycle, and the resource's actual current state?
7. Can a user with cluster-admin authorization still be blocked by Gatekeeper? Why does passing `kubectl auth can-i` not prove that a proposed object will pass admission?

**Answer checkpoints:** Audit reports; deny rejects matching requests when enforcement applies. Neither automatically evicts preexisting pods. Exclusions and exemptions change evaluation scope or treatment, while reporting is asynchronous. Separate admission evidence from an older compliance result.

**Complete answers:** [Compliance mappings](#74-find-noncompliant-kubernetes-resources), [existing pods and admission](#75-why-noncompliant-pods-can-keep-running), [enforcement troubleshooting](#76-troubleshoot-policy-ingestion-enforcement-and-reporting-separately), and [Policy versus RBAC](#78-azure-policy-versus-rbac).

---

## 11. Command reference

### Cluster security configuration

```bash
az aks show -g <rg> -n <cluster> \
  --query '{
    kubernetesRbac:enableRbac,
    entra:aadProfile,
    localAccountsDisabled:disableLocalAccounts,
    apiAccess:apiServerAccessProfile,
    oidc:oidcIssuerProfile,
    workloadIdentity:securityProfile.workloadIdentity,
    azurePolicy:addonProfiles.azurepolicy,
    networking:networkProfile
  }'
```

### Identity and authorization

```bash
kubectl config current-context
kubectl auth whoami
kubectl auth can-i list nodes
kubectl auth can-i get pods -n <namespace>
kubectl get role,rolebinding -n <namespace>
kubectl get clusterrole,clusterrolebinding
```

### Workload identity and policy

```bash
kubectl get serviceaccount -n <namespace> <service-account> -o yaml
kubectl describe pod -n <namespace> <pod>
az identity federated-credential list \
  -g <identity-rg> --identity-name <identity-name>
kubectl get constrainttemplates
kubectl api-resources --api-group=constraints.gatekeeper.sh
kubectl get networkpolicy -A
kubectl get events -n <namespace> --sort-by=.lastTimestamp
```

Do not publish bearer tokens, private keys, client secrets, projected assertions, or raw kubeconfig in tickets or public examples. Sanitize identity/resource metadata according to the sharing context.

---

## 12. References and material map

### AAD + RBAC: public material

- [Managed Entra control-plane authentication - AKS](https://learn.microsoft.com/azure/aks/entra-id-control-plane-authentication)
- [Cluster authentication concepts - AKS](https://learn.microsoft.com/azure/aks/concepts-cluster-authentication)
- [Cluster authorization concepts - AKS](https://learn.microsoft.com/azure/aks/concepts-cluster-authorization)
- [Azure RBAC for Kubernetes / Entra authorization - AKS](https://learn.microsoft.com/azure/aks/entra-id-authorization)
- [Entra integration with Kubernetes RBAC - AKS](https://learn.microsoft.com/azure/aks/kubernetes-rbac-entra-id)
- [Control access to kubeconfig - AKS](https://learn.microsoft.com/azure/aks/control-kubeconfig-access)
- [Manage local accounts - AKS](https://learn.microsoft.com/azure/aks/local-accounts)
- [Kubelogin authentication - AKS](https://learn.microsoft.com/azure/aks/kubelogin-authentication)
- [Azure kubelogin - official repository](https://github.com/Azure/kubelogin)
- [Kubelogin login modes - official documentation](https://azure.github.io/kubelogin/concepts/login-modes.html)
- [Guard - Azure repository](https://github.com/Azure/guard)
- [Guard OBO token-provider implementation](https://github.com/Azure/guard/blob/master/auth/providers/azure/graph/obo_tokenprovider.go)
- [OAuth 2.0 On-Behalf-Of flow - Microsoft identity platform](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-on-behalf-of-flow)
- [Kubernetes authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
- [Kubernetes authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

### Workload Identity: public material

- [Workload Identity overview - AKS](https://learn.microsoft.com/azure/aks/workload-identity-overview)
- [Deploy/configure Workload Identity - AKS](https://learn.microsoft.com/azure/aks/workload-identity-deploy-cluster)
- [OIDC issuer - AKS](https://learn.microsoft.com/azure/aks/use-oidc-issuer)
- [Azure Workload Identity - official documentation](https://azure.github.io/azure-workload-identity/docs/)
- [Workload Identity troubleshooting](https://azure.github.io/azure-workload-identity/docs/troubleshooting.html)
- [Workload Identity issues - official repository](https://github.com/Azure/azure-workload-identity/issues)

### Authorized IP ranges and CVEs: public material

- [API server authorized IP ranges - AKS](https://learn.microsoft.com/azure/aks/api-server-authorized-ip-ranges)
- [Vulnerability management - AKS](https://learn.microsoft.com/azure/aks/concepts-vulnerability-management)
- [Node image upgrades - AKS](https://learn.microsoft.com/azure/aks/node-image-upgrade)
- [AKS release notes](https://github.com/Azure/AKS/releases)
- [AKS CVE issue search](https://github.com/Azure/AKS/issues?q=is%3Aissue%20CVE)
- [Ubuntu CVE tracker](https://ubuntu.com/security/cves)
- [Ubuntu Security Notices](https://ubuntu.com/security/notices)

### Azure Policy: public material

- [Use Azure Policy to secure AKS](https://learn.microsoft.com/azure/aks/use-azure-policy)
- [Built-in Azure Policy definitions for AKS](https://learn.microsoft.com/azure/aks/policy-reference)
- [Azure Policy for Kubernetes, custom definitions, logging, and artifacts](https://learn.microsoft.com/azure/governance/policy/concepts/policy-for-kubernetes)
- [Azure Policy definition structure](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-basics)
- [Determine noncompliance and component details](https://learn.microsoft.com/azure/governance/policy/how-to/determine-non-compliance)
- [Gatekeeper - official repository/documentation](https://github.com/open-policy-agent/gatekeeper)

### Network policy: public material

- [Secure pod traffic with network policies - AKS](https://learn.microsoft.com/azure/aks/use-network-policies)
- [Azure NPM - official source and documentation directory](https://github.com/Azure/azure-container-networking/tree/master/npm)
- [Azure CNI powered by Cilium - AKS](https://learn.microsoft.com/azure/aks/azure-cni-powered-by-cilium)
- [Kubernetes NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

### Internal reading list supplied for this module

The following titles are retained as a study checklist. They require authorized PG Wiki, CSS Wiki, Engineer Hub, or sharing access. No URLs were supplied; their contents were not accessed or represented as verified public guidance.

| Topic | Internal material |
|---|---|
| AAD + RBAC | Azure RBAC for K8s Authorization TSG; Managed AAD engineering design; Managed AAD TSG; Kubelogin CSS Wiki |
| Workload Identity | Azure AD Workload Identity overview; Workload Identity TSG; OIDC Issuer Engineer Hub; deep-dive sharing |
| Authorized IP ranges | Authorized IP Range design; PG TSG; Engineer Hub TSG |
| CVEs | CVE Common Vulnerabilities and Exposures on AKS - CSS Wiki |
| Azure Policy | Azure Policy CSS Wiki/overview; gathering logs; policy blocks cluster operations; V2 add-on TSG; policy add-on; PG/CSS TSGs; policy integration |
| Network policy | AKS Network Policy; Azure NPM TSG; `PlaceAzureChainFirst=True` change on 1.27+; AKS NPM learning session |

Public documentation was reviewed on **27 October 2026**. Recheck feature/version/OS support and retirement dates before applying the guide to a live cluster.
