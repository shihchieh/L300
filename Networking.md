# AKS L300 Networking

> NETWORKING

> **Focus:** ingress, egress, container networking, DNS, private clusters, network policy, and evidence-driven troubleshooting.

---

1. Trace inbound traffic from an Azure frontend through the node data plane to a ready pod.
2. Compare managed NGINX, application routing Gateway API, Istio, AGIC, and Application Gateway for Containers.
3. Explain Azure Load Balancer rules, Floating IP, health probes, NodePort, and client source-IP preservation.
4. Compare Load Balancer, NAT Gateway, UDR, Azure Firewall, and explicit AKS outbound types.
5. Compare Kubenet, Azure CNI Node Subnet, Pod Subnet, Overlay, and Cilium data planes.
6. Troubleshoot subnet exhaustion and dynamic pod IP allocation through CNS, IPAM, and NNC evidence.
7. Trace internal and external DNS resolution and private control-plane connectivity.
8. Diagnose NetworkPolicy and Cilium drops with concrete flow evidence.

---

## 1. Core concepts and packet path

Do not start a networking answer with a list of products. Start with the packet and identify every decision point:

```text
source
  -> DNS
  -> route selection
  -> NSG / firewall
  -> Azure load-balancing or NAT component
  -> node network
  -> Kubernetes Service implementation
  -> network policy
  -> pod
  -> return path
```

For each hop, answer five questions:

1. What source and destination IP addresses exist at this hop?
2. Which route is selected?
3. Which component performs DNAT or SNAT?
4. Which policy can permit or deny the packet?
5. What command, log, metric, or packet capture proves the conclusion?

Keep these scopes separate:

| Scope | Examples |
|---|---|
| Azure network | VNet, subnet, UDR, NSG, NAT Gateway, Azure Load Balancer, Azure Firewall |
| Kubernetes network | Service, EndpointSlice, NodePort, Ingress, Gateway, NetworkPolicy |
| Node data plane | `kube-proxy`, eBPF, routes, conntrack, interfaces |
| Application | Process listening port, TLS, HTTP host/path, readiness |
| Control plane | Cloud-provider reconciliation, API aggregation, Konnectivity |

> **Interview rule:** A timeout does not prove that a firewall dropped traffic. A `502` does not prove that the ingress controller is broken. Identify the failing layer with evidence.

---

## 2. Ingress and service traffic

### 2.1 Kubernetes Service types

| Type | Purpose |
|---|---|
| `ClusterIP` | Stable virtual IP reachable inside the cluster |
| `NodePort` | Allocates a port in the node-port range and installs forwarding behavior on nodes |
| `LoadBalancer` | Requests an external or internal load balancer and normally builds on `NodePort` behavior |
| `ExternalName` | Returns a DNS CNAME; it doesn't proxy traffic |

### 2.2 Azure Load Balancer packet flow

For a typical AKS `LoadBalancer` Service:

```text
client
  -> Azure Load Balancer frontend IP:servicePort
  -> load-balancing rule and healthy backend node
  -> node:nodePort
  -> kube-proxy or eBPF Service translation
  -> ready pod IP:targetPort
```

The AKS cloud provider reconciles the Kubernetes Service into Azure resources:

- frontend IP configuration
- load-balancing rule
- backend-pool membership
- health probe
- optional outbound configuration, depending on the cluster outbound type

The Service object remains the source of truth. Direct edits to AKS-managed load-balancer rules can be overwritten during reconciliation.

### 2.3 Why NodePort works without a listening process

`ss -lntp` might show no process listening on the NodePort. That is expected.

A NodePort is implemented by packet-processing rules, not necessarily a userspace socket:

- `kube-proxy` can program iptables or IPVS rules.
- Azure CNI powered by Cilium can implement Kubernetes Service handling with eBPF.
- The data plane rewrites and forwards packets to a selected endpoint.

Use the following evidence instead of relying only on `ss`:

```bash
kubectl get service <service> -o yaml
kubectl get endpointslice -l kubernetes.io/service-name=<service> -o wide
kubectl get pods -o wide
```

First identify the active data plane. Depending on the cluster, useful node evidence includes iptables/IPVS state, Cilium service state, conntrack entries, interfaces, routes, and a packet capture. Co[...]

### 2.4 `externalTrafficPolicy`

#### `Cluster`

- Any healthy backend node can receive external traffic.
- The node can forward traffic to an endpoint on another node.
- This gives broad traffic distribution.
- The extra hop and Service SNAT behavior can hide the original client source IP from the pod.

#### `Local`

- A node should receive client traffic only when it has a local ready endpoint for the Service.
- Traffic isn't forwarded to a pod on another node.
- The client source IP is preserved for the backend pod.
- Traffic capacity follows endpoint placement. Uneven pod distribution can create uneven load.

AKS configures health-probe behavior to represent local endpoint availability. Azure platform health probes originate from the virtual IP `168.63.129.16`. An NSG must permit the `AzureLoadBalancer` se[...] 

Check:

```bash
kubectl get service <service> \
  -o jsonpath='{.spec.externalTrafficPolicy}{"\n"}'
kubectl get pods -l <selector> -o wide
kubectl get endpointslice \
  -l kubernetes.io/service-name=<service> -o yaml
```

### 2.5 Health probes

Do not confuse these health signals:

| Signal | What it controls |
|---|---|
| Pod readiness probe | Whether a pod appears as a ready Service endpoint |
| Azure Load Balancer health probe | Whether a backend node receives new load-balanced flows |
| Ingress/backend health probe | Whether an L7 proxy routes requests to a backend |
| Liveness probe | Whether kubelet restarts the container |

Troubleshoot the exact configured probe protocol, port, path, expected status code, and source. A pod can be ready while an Azure load-balancer probe is blocked, and a node can pass an Azure probe whi[...] 

### 2.6 Azure Load Balancer Floating IP

Floating IP is an Azure Load Balancer rule setting, also associated with Direct Server Return patterns. It changes the address mapping seen by the backend so the frontend IP is retained instead of bei[...] 

Its primary Azure use cases include:

- reusing the same backend port across multiple load-balancing rules
- high-availability clustering and listener scenarios
- network virtual appliances
- applications that must receive traffic addressed to the frontend IP

Important characteristics:

- It is configured per load-balancing rule.
- It is not a public IP that moves between AKS nodes.
- It is not the same feature as `externalTrafficPolicy: Local`.
- Generic VM scenarios require guest-OS configuration for the frontend IP and weak-host/loopback behavior.
- AKS-managed load-balancer rules are owned by the cloud provider and shouldn't be edited directly.

For node-backend Kubernetes Services, the Azure cloud provider creates load-balancing rules with Floating IP enabled and uses the Service's NodePort as the backend port. This lets the node's Kubernete[...] 

Inspect the full Service rule, frontend, NodePort, and cloud-provider configuration before changing it. Direct changes can be reverted by reconciliation.

### 2.7 `LoadBalancer` Service remains pending

`<pending>` means cloud-provider reconciliation hasn't assigned the requested frontend. Start with the Service event because it often contains the Azure API error:

```bash
kubectl describe service -n <namespace> <service>
kubectl get events -n <namespace> --sort-by=.lastTimestamp
```

Check these failure classes:

| Failure | Evidence |
|---|---|
| Cluster identity lacks access | Azure `AuthorizationFailed`; verify Network Contributor or the required custom permissions on the BYO subnet/public IP |
| Internal frontend has no free address | Requested IP unavailable or subnet exhausted |
| Public IP or load-balancer quota | Azure quota error in Service events |
| Invalid annotation or resource reference | Referenced subnet, public IP, resource group, or IP doesn't exist or is incompatible |
| Frontend IP conflict | Requested static IP is already allocated |
| Reconciliation/API failure | Repeated `SyncLoadBalancerFailed` event |

In managed AKS, control-plane Cloud Controller Manager logs aren't normally exposed as a customer pod. Use Service events, AKS control-plane diagnostic logs when enabled, and an AKS support bundle or [...] 

For a BYO VNet, confirm the cluster identity's scope and permissions:

```bash
az aks show -g <rg> -n <cluster> \
  --query '{principalId:identity.principalId,kubelet:kubeletIdentity.objectId}'
az role assignment list --assignee <cluster-principal-id> --all -o table
```

For an internal frontend, inspect subnet address space and current IP configurations. Pod-subnet exhaustion and load-balancer frontend exhaustion are different problems; identify which subnet the fron[...] 

### 2.8 Internal load balancer

An internal `LoadBalancer` Service receives a private frontend IP from the configured subnet. It is not automatically reachable from every network.

Validate:

- private IP allocation and subnet capacity
- routes from the client network to the AKS VNet
- peering or hub-spoke forwarding settings
- NSGs on source, destination, and intermediate subnets
- firewall policy and return route
- DNS resolving the application name to the intended private IP

### 2.9 Ingress API versus Gateway API

| Ingress API | Gateway API |
|---|---|
| Primarily HTTP/HTTPS routing | Extensible role-oriented traffic API |
| Most advanced behavior is controller-specific annotations | More behavior is expressed with typed resources |
| One `Ingress` combines listener and route concerns | Separates infrastructure and application ownership |
| Uses `IngressClass` | Uses `GatewayClass`, `Gateway`, and route objects such as `HTTPRoute` |

Gateway API ownership model:

```text
infrastructure provider -> GatewayClass
platform team           -> Gateway and listeners
application team        -> HTTPRoute / GRPCRoute
```

Route status is part of the API. Always inspect `status.parents[].conditions` rather than assuming a successfully created object is attached and programmed.

---

## 3. Application routing and Gateway API

### 3.1 Managed NGINX application routing add-on

The managed application routing add-on historically provided managed NGINX ingress integration, including Azure DNS and Key Vault certificate scenarios.

The upstream ingress-nginx project ended maintenance in March 2026. Microsoft support for critical security patches for application-routing NGINX resources continues through November 2026. Existing us[...] 

### 3.2 Application routing Gateway API implementation

The AKS application routing Gateway API implementation:

- uses `Gateway`, `HTTPRoute`, and related Gateway API resources
- uses the `approuting-istio` `GatewayClass`
- deploys an Istio control plane to manage Gateway API infrastructure
- does **not** provide service-mesh sidecar injection or general Istio CRD support
- is different from the AKS Istio service mesh add-on

| Application routing Gateway API | Istio service mesh add-on |
|---|---|
| Managed ingress-focused implementation | Service mesh plus ingress capability |
| `GatewayClass` is `approuting-istio` | `GatewayClass` is `istio` |
| No sidecar injection | Supports sidecar injection |
| No Istio `VirtualService`/`DestinationRule` use | Supports Istio APIs |
| In-place managed upgrades | Revision-based minor upgrades |

The two add-ons can't be enabled at the same time. Do not describe the application routing Gateway API implementation as a complete Istio service mesh.

### 3.3 Minimal Gateway API example

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: web-gateway
  namespace: platform
spec:
  gatewayClassName: approuting-istio
  listeners:
  - name: http
    protocol: HTTP
    port: 80
    allowedRoutes:
      namespaces:
        from: All
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: web
  namespace: app
spec:
  parentRefs:
  - name: web-gateway
    namespace: platform
  hostnames:
  - app.example.com
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /
    backendRefs:
    - name: web
      port: 80
```

Troubleshoot:

```bash
kubectl get gatewayclass
kubectl get gateway -A
kubectl describe gateway -n platform web-gateway
kubectl get httproute -A
kubectl describe httproute -n app web
kubectl get events -A --sort-by=.lastTimestamp
```

Look for `Accepted`, `Programmed`, and `ResolvedRefs` conditions. Common failures include:

- wrong `gatewayClassName`
- route not allowed by `allowedRoutes`
- cross-namespace reference without the required permission
- nonexistent backend Service or port
- invalid TLS certificate reference
- gateway pods pending because of capacity, taints, or quotas
- DNS still pointing to an old frontend

### 3.4 Application routing NGINX versus Istio

| Managed NGINX application routing | Application routing Gateway API |
|---|---|
| Uses the Kubernetes Ingress API | Uses Gateway API |
| NGINX data plane | Istio-based gateway proxy and managed control plane |
| Advanced behavior commonly uses NGINX annotations | Behavior uses typed Gateway API fields where supported |
| `IngressClass` selects the controller | `GatewayClass` is `approuting-istio` |
| Upstream ingress-nginx maintenance ended in March 2026 | Strategic managed path for AKS ingress |
| Microsoft critical security support ends November 2026 | Recommended migration target for supported use cases |

Microsoft recommends migration because upstream ingress-nginx is retired and Gateway API is the long-term Kubernetes standard. This is not a claim that Istio is universally better than NGINX. Validate[...] 

### 3.5 NGINX ingress returns HTTP 404

A `404` proves that an HTTP component responded. Identify **which component** generated it.

1. Reproduce with the exact Host header and path:

   ```bash
   curl -sv -H 'Host: app.example.com' \
     http://<ingress-ip>/expected/path
   ```

2. Inspect the Ingress:

   ```bash
   kubectl get ingress -n <namespace> <ingress> -o yaml
   kubectl describe ingress -n <namespace> <ingress>
   kubectl get ingressclass
   ```

3. Verify host, `path`, `pathType`, controller class, rewrite annotation, backend Service name, and port.
4. Verify the Service and endpoints:

   ```bash
   kubectl get service,endpointslice -n <namespace>
   kubectl get pods -n <namespace> -o wide --show-labels
   ```

5. Compare the same request at each layer:

   ```bash
   # Ingress route
   curl -sv -H 'Host: app.example.com' \
     http://<ingress-ip>/expected/path

   # Service path, before ingress rewrite
   kubectl run curl --rm -it --restart=Never \
     --image=curlimages/curl -- \
     curl -sv http://<service>.<namespace>.svc:<port>/<backend-path>

   # Direct pod path
   kubectl run curl --rm -it --restart=Never \
     --image=curlimages/curl -- \
     curl -sv http://<pod-ip>:<target-port>/<backend-path>
   ```

Interpretation:

| Result | Likely cause |
|---|---|
| Pod IP and Service return 404 | Backend application/path |
| Pod IP works, Service fails | Service selector, port, or target port |
| Service works, ingress returns default-backend 404 | Host/path/class didn't match an Ingress rule |
| Service backend path works, ingress path fails | Rewrite or route configuration |

Check NGINX access logs for:

- request Host and URI
- response status
- selected upstream name
- upstream address
- upstream status
- request time and upstream response time
- request ID, if enabled

The exact log format can vary, but upstream fields distinguish an NGINX-generated 404 from a backend-generated 404. If no matching request appears, verify DNS/frontend routing and that the expected co[...] 

```bash
kubectl get pods -A | grep -E 'nginx|app-routing'
kubectl logs -n <controller-namespace> <controller-pod> \
  --since=10m
```

---

## 4. Application Gateway for Containers

Application Gateway for Containers is an Azure-managed Layer 7 ingress and load-balancing service designed for Kubernetes. Its data plane runs outside the AKS cluster.

### 4.1 Main components

- **Application Gateway for Containers resource**: parent Azure resource
- **Frontend**: client-facing entry point
- **Association**: connection to the delegated subnet
- **Security policy**: TLS or mutual-TLS policy
- **ALB Controller**: in-cluster controller that watches Kubernetes resources and programs Azure
- **User-assigned managed identity**: used by the controller

The controller supports Kubernetes Ingress and Gateway API resources. It can use either:

- **bring-your-own Azure resources**, or
- **ALB Controller-managed resources** through an `ApplicationLoadBalancer` custom resource

### 4.2 Kubernetes objects

For Gateway API, expect:

- `GatewayClass`: identifies the ALB Controller implementation
- `Gateway`: defines listeners and references the frontend
- `HTTPRoute` or another supported route: matches traffic and selects backends
- `Service`: exposes the backend pods
- `ApplicationLoadBalancer`: used when ALB Controller manages the Azure resource lifecycle

The exact objects differ between bring-your-own and controller-managed deployment. Do not say that every deployment creates every object automatically.

### 4.3 Control path and data path

Keep them separate:

```text
Control path:
Kubernetes resources -> ALB Controller -> Azure resource configuration

Data path:
client -> Application Gateway for Containers frontend
       -> Azure-managed L7 data plane
       -> selected AKS backend pod
```

If the Kubernetes resource exists but Azure configuration isn't created, investigate the control path. If Azure configuration is healthy but requests fail, investigate the data path, backend health, r[...] 

### 4.4 Application Gateway for Containers versus AGIC

| Application Gateway for Containers | AGIC |
|---|---|
| Purpose-built Kubernetes offering | Controller for classic Application Gateway |
| Dedicated control and data plane | Programs an Application Gateway resource |
| Supports Ingress and Gateway API | Primarily Ingress based |
| ALB Controller | Application Gateway Ingress Controller |

Do not use the names interchangeably.

### 4.5 AGIC reconciliation and troubleshooting

AGIC watches selected Kubernetes resources, builds the desired classic Application Gateway configuration, and applies it through Azure Resource Manager.

```text
Ingress / Service / Endpoint change
  -> AGIC event handler and reconcile
  -> desired listeners, rules, probes, HTTP settings, and backend pools
  -> ARM update to Application Gateway
  -> cache updated with applied configuration
```

When Application Gateway doesn't update:

1. Verify AGIC is healthy and watches the application's namespace:

   ```bash
   kubectl get pods -A -l app=ingress-azure
   kubectl logs -n <agic-namespace> <agic-pod> --since=30m
   kubectl logs -n <agic-namespace> <agic-pod> --previous
   ```

2. Verify the Ingress class/annotation is `azure/application-gateway`, the Service selector has ready endpoints, and the backend pod IP is reachable from Application Gateway.
3. Check Kubernetes events for rejected annotations, invalid ports, or missing resources.
4. Increase AGIC verbosity when necessary. Verbosity level 5 includes sanitized desired ARM configuration; use it temporarily because it is noisy.
5. Check Azure Activity Log for `Microsoft.Network/applicationGateways/write` and determine whether the write was sent, succeeded, or failed.
6. Compare Application Gateway listeners, routing rules, backend pools, HTTP settings, probes, and backend health with the desired Kubernetes objects.

Official successful synchronization lines include:

```text
Applied Application Gateway config in ...
cache: Updated with latest applied config.
END AppGateway deployment
```

These prove AGIC completed an Application Gateway deployment. If AGIC detects no desired-state difference, it might correctly avoid an ARM update.

Common causes:

- AGIC isn't observing the namespace
- wrong ingress class
- workload has no ready endpoints
- cluster identity lacks Application Gateway permissions
- AGIC can't reach ARM or Microsoft Entra endpoints
- another tool edits the same Application Gateway
- invalid or conflicting annotations
- Application Gateway provisioning state or Azure API operation failed

### 4.6 Application Gateway for Containers troubleshooting checklist

1. Inspect `Ingress`, `Gateway`, and `HTTPRoute` status and events.
2. Verify the ALB Controller pods and logs.
3. Verify managed-identity permissions and federated identity configuration.
4. Verify subnet delegation and available IP space.
5. Confirm the frontend address and DNS record.
6. Confirm listener, hostname, path, and TLS configuration.
7. Verify backend references, EndpointSlices, pod readiness, and target port.
8. Check backend health and distinguish controller programming failures from application failures.

---

## 5. Egress and SNAT

### 5.1 AKS outbound types

Current AKS outbound types include:

| Outbound type | AKS behavior | Typical use |
|---|---|---|
| `loadBalancer` | AKS creates Standard Load Balancer outbound configuration and public IP | Standard managed internet egress |
| `managedNATGateway` | AKS creates and attaches a NAT Gateway | Higher-scale managed SNAT |
| `managedNATGatewayV2` | AKS uses StandardV2 NAT Gateway; preview as of this review | Zone-resilient, higher-throughput managed egress |
| `userAssignedNATGateway` | Customer attaches NAT Gateway to a BYO VNet subnet | Controlled public IP and SNAT scale |
| `userDefinedRouting` | AKS doesn't create the egress path; customer supplies a `0.0.0.0/0` route | Azure Firewall or another NVA |
| `none` | AKS doesn't create egress infrastructure and doesn't require a default route during validation | Network-isolated or custom egress design |
| `block` | AKS configures rules to block public egress; preview and limited scenarios | Managed-VNet network isolation |

Default outbound access for Azure VMs is no longer a supported AKS egress design. Starting 31 March 2026, new AKS-managed VNets use private subnets by default. Production clusters need an explicit sup[...] 

### 5.2 Route selection before SNAT

Avoid memorizing the oversimplified statement "UDR > NAT Gateway > Load Balancer" without explaining the packet.

1. Azure selects the effective route using longest-prefix match and route-source precedence.
2. If a UDR sends `0.0.0.0/0` to an NVA, that next hop owns the egress path.
3. If the selected next hop is Internet and a NAT Gateway is attached to the subnet, NAT Gateway provides outbound SNAT.
4. Without NAT Gateway, the configured AKS load-balancer outbound rule can provide SNAT.

Therefore, a default UDR to Azure Firewall prevents NAT Gateway from becoming the internet egress path even if both are associated with the subnet.

For the common AKS interview shorthand, state the order and then add the routing qualification:

```text
UDR to an NVA/firewall
  > NAT Gateway for an Internet next hop
  > explicit Load Balancer outbound rule
  > implicit/default outbound access
```

NAT Gateway takes precedence over Load Balancer SNAT and instance-level public IP for flows that use the subnet's Internet next hop. A more-specific UDR or a default UDR to a virtual appliance changes[...] 

Prove the path with:

```bash
az network nic show-effective-route-table \
  --resource-group <node-resource-group> \
  --name <node-nic>
```

Also inspect the subnet's route table and NAT Gateway association. Do not infer the active path from the existence of an Azure resource.

### 5.3 Azure Load Balancer versus NAT Gateway SNAT

| Azure Load Balancer outbound rule | NAT Gateway |
|---|---|
| SNAT ports are allocated to backend instances according to outbound-rule configuration | Ports are allocated dynamically across the subnet's active flows |
| Scaling nodes can reduce per-node port availability when using automatic allocation | New nodes use the shared NAT Gateway inventory |
| Multiple outbound IPs or a public IP prefix increase inventory | Multiple public IPs or a prefix increase inventory |
| Inbound and outbound can share the same Standard Load Balancer resource | Dedicated outbound service |
| Requires careful `allocatedOutboundPorts` and node-count planning | Usually preferred for high or unpredictable connection fan-out |

Each public IPv4 address contributes about 64,000 TCP and 64,000 UDP SNAT ports, but architecture must leave operational headroom and account for destination reuse, connection duration, and scale.

AKS sets `AllocatedOutboundPorts=0` by default, which enables automatic allocation based on backend-pool size. Current documented examples are:

- 50 or fewer nodes: 1,024 ports per node
- scaling from 50 to 51 nodes: allocation drops to 512 ports per node
- scaling across an automatic-allocation boundary can reset existing connectivity

For an explicit design:

```text
maximum supported nodes
  = 64,000 ports per frontend IP
    / allocated ports per node
    * number of outbound frontend IPs
```

The configured port count must be a multiple of eight. Include Cluster Autoscaler maximums and upgrade surge nodes. Adding public IPs increases total node capacity; it doesn't increase an explicitly f[...] 

### 5.4 SNAT exhaustion symptoms

- intermittent outbound timeouts
- failures increase under concurrency
- some destinations work while high-fan-out destinations fail
- retries temporarily succeed
- DNS succeeds but TCP connect fails
- application logs show connection timeout or socket errors

SNAT exhaustion is not the only cause of timeout. Also validate:

- route and next hop
- NSG and firewall decision
- DNS answer
- remote endpoint health
- connection tracking
- application connection pooling and keepalive

### 5.5 Mitigations

- use connection pooling and reuse
- avoid aggressive retry storms
- use private endpoints or service endpoints where appropriate
- increase outbound public IP inventory
- set an explicit load-balancer outbound-port design
- use NAT Gateway for dynamic SNAT allocation
- scale the firewall/NVA and its SNAT inventory in UDR designs

Changing outbound type or public IP changes the observed source IP and disrupts existing connections. Update allowlists and API-server authorized IP ranges before migration.

### 5.6 UDR with Azure Firewall

Typical path:

```text
pod
  -> node or pod network
  -> node subnet UDR 0.0.0.0/0
  -> Azure Firewall private IP
  -> firewall network/application rule
  -> firewall public IP SNAT
  -> internet
```

Validate both directions. A forward route through the firewall with an asymmetric return path can fail even when every individual component appears healthy.

---

## 6. Container networking models

### 6.1 Model comparison

| Model | Network model | Pod IP source | External pod-IP reachability | IP efficiency | Status |
|---|---|---|---|---|---|
| Azure CNI Overlay | Overlay | Separate pod CIDR | Initiated from pod; inbound normally through a Service | High | Recommended for most scenarios |
| Azure CNI Pod Subnet | Flat | Delegated pod subnet | Bidirectional over connected networks | Efficient or high-scale modes | Recommended flat model |
| Azure CNI Node Subnet | Flat | Node subnet | Bidirectional with scope-dependent SNAT behavior | Lower | Legacy |
| Kubenet | Overlay-like routed pod CIDRs | Per-node pod CIDR | Initiated from pod; inbound through a Service | High | Retires 31 March 2028 |

Azure CNI powered by Cilium is a **data-plane choice**, not a separate IPAM model. It can be used with Azure CNI Overlay, Pod Subnet, or Node Subnet.

### 6.2 Flat versus overlay

#### Flat

- Pods receive VNet IP addresses.
- Connected networks can route directly to pod IPs, subject to the selected IPAM model and policy.
- Address planning must include pods, nodes, upgrades, and growth.
- Best when direct pod reachability is required.

#### Overlay

- Pods receive addresses from a CIDR separate from the VNet.
- Only node interfaces consume VNet addresses for the pod data plane.
- Pod traffic leaving the cluster is SNATed to the node IP.
- External systems don't route directly to overlay pod IPs.

### 6.3 Azure CNI Overlay cross-node flow

```text
pod A
  -> source node data plane looks up pod B
  -> packet crosses the VNet between node IPs through the overlay data plane
  -> destination node decapsulates/processes the packet
  -> pod B
```

For traffic outside the cluster:

```text
pod A source IP
  -> SNAT to source node IP
  -> subnet route selection
  -> configured outbound path
  -> destination
```

AKS assigns a pod-CIDR block to each node and the managed overlay data plane maintains the mapping between pod CIDRs and node ownership. The node data plane uses that mapping to send the packet across[...] 

SNAT is **not** required merely because two overlay pods are on different nodes; both addresses belong to the cluster overlay. SNAT to the node IP occurs when traffic leaves the cluster overlay for a [...] 

Troubleshoot cross-node traffic by comparing same-node and cross-node tests:

1. Confirm pod IPs and node placement.
2. Confirm the destination pod listens on the expected port.
3. Confirm NetworkPolicy allows the flow.
4. Confirm node-to-node reachability and effective routes.
5. Check NSGs and firewall rules for node-subnet traffic.
6. Observe both nodes with Cilium/Hubble or packet capture.
7. Verify the return path.

### 6.4 Kubenet cross-node flow

Kubenet assigns a pod CIDR to each node. Azure route-table entries direct each node's pod CIDR to that node's primary IP.

```text
pod A
  -> source node
  -> Azure UDR for pod B's node CIDR
  -> destination node primary IP
  -> pod B
```

Failures commonly involve:

- missing or stale route-table entries
- route-table limits
- node-subnet NSG denial
- overlapping address ranges
- node or CNI initialization problems

Kubenet retires on 31 March 2028. Plan migration to Azure CNI Overlay rather than designing new long-lived deployments around Kubenet.

### 6.5 Traditional Azure CNI cross-node flow

Traditional Azure CNI Node Subnet is a flat network, not the Kubenet per-node-pod-CIDR design:

- every pod receives a secondary VNet IP from the node subnet
- Azure networking knows those IP configurations through the node NIC/network configuration
- cross-node pod traffic is routed as VNet traffic to the destination pod IP
- customer UDRs containing one pod CIDR per node are a Kubenet concept, not traditional Azure CNI behavior

Troubleshoot with pod IP/node placement, effective routes, NIC IP configurations, NSGs, NetworkPolicy, and packet capture. Correct the model before interpreting the route table.

### 6.6 Traditional Azure CNI IP exhaustion and migration

Traditional Node Subnet reserves pod capacity per node. Exhaustion can block node scale-out, upgrades, or pod creation.

Immediate checks:

```bash
az aks show -g <rg> -n <cluster> \
  --query 'agentPoolProfiles[].{pool:name,count:count,maxPods:maxPods,vnetSubnetID:vnetSubnetID}'
az network vnet subnet show --ids <node-subnet-id> \
  --query '{prefixes:addressPrefixes,ipConfigurations:length(ipConfigurations)}'
```

Possible remediations:

- reclaim unused addresses/resources
- add a node pool on a larger subnet and move workloads
- migrate to Azure CNI Pod Subnet to separate node and pod addresses
- migrate to Azure CNI Overlay when direct routable pod IPs aren't required

A safe workload migration is:

1. Create and permission the new subnet.
2. Add a new node pool using the target subnet/network model where supported.
3. Validate routes, NSGs, DNS, policy, egress, and dependencies.
4. Cordon and drain old nodes while respecting PDBs.
5. Remove the old pool after workloads and system dependencies move.

Changing the cluster network model can require a supported network-plugin update path or a new cluster. Verify the current AKS migration matrix before committing to an in-place design.

### 6.7 Azure CNI Pod Subnet dynamic IP allocation

Dynamic IP allocation separates the node subnet from a delegated pod subnet:

- nodes receive IPs from the node subnet
- pods receive VNet IPs from the pod subnet
- each node initially receives a batch of 16 pod IPs
- another batch of 16 is requested when fewer than eight remain available
- `NodeNetworkConfiguration` (`NNC`) resources show node allocation state
- Container Networking Service (`CNS`) on the node serves pod IP allocations to the CNI/IPAM path

If a pod can't obtain an IP:

1. Inspect the pod event for `FailedCreatePodSandBox` and CNI/IPAM errors.
2. Check pod-subnet free capacity and cluster identity permissions.
3. Inspect NNC allocation state:

   ```bash
   kubectl get nodenetworkconfigs -n kube-system -o wide
   kubectl describe nodenetworkconfig -n kube-system <name>
   ```

4. Determine whether only one node fails. If so, inspect that node's CNS and Azure CNI state.
5. Through the approved node-log collection method, inspect:
   - `/var/log/azure/cns.log`
   - `/var/log/azure/azure-vnet.log`
   - kubelet/container-runtime messages around sandbox creation
6. Check for stale NNC state, failed batch allocation, subnet exhaustion, Azure API throttling, identity authorization failure, or a node networking daemon problem.

Do not restart networking components as the first action. Capture NNC state, pod events, and node logs before changing state.

### 6.8 Azure CNI Pod Subnet and Node Subnet

**Pod Subnet**

- Pods receive IPs from a delegated subnet separate from nodes.
- It is the recommended flat-network IPAM option.
- It separates node and pod address planning.
- Pod IPs can be reached from connected networks when routing and policy allow.

**Node Subnet**

- Nodes and pods consume addresses from the node subnet.
- Preallocation and upgrade surge can require substantial unused space.
- It is a legacy flat-network model.
- Destinations outside the cluster VNet can see the node IP rather than the pod IP.

### 6.9 IP address planning

Plan for:

- maximum nodes in every pool
- `maxPods` for each pool
- upgrade surge nodes
- cluster autoscaler headroom
- internal load-balancer frontends
- private endpoints
- future node pools and clusters
- non-overlap with peered VNets, on-premises networks, pod CIDRs, and service CIDRs

For legacy Azure CNI Node Subnet, a conservative starting calculation is:

```text
required addresses
  >= nodes * (1 + maxPods)
   + surge nodes * (1 + maxPods)
   + Azure-reserved subnet addresses
   + operational growth
```

Do not use this formula for every model. Overlay pods do not consume VNet IPs, and Pod Subnet allocation has different behavior.

### 6.10 Service CIDR

The Service CIDR supplies virtual ClusterIPs. It:

- must not overlap the VNet, pod CIDR, peered networks, or on-premises ranges
- isn't directly routed like a normal subnet
- is implemented by Service translation in the node data plane

An overlap might remain hidden until the cluster needs to reach a real network that uses the same address range.

### 6.11 IP masquerading

IP masquerading decides when pod source addresses are preserved and when they are SNATed.

The `ip-masq-agent` configuration identifies non-masquerade CIDRs. Traffic to other destinations is masqueraded to the node IP. Incorrect exclusions can cause:

- return traffic to target a nonroutable pod IP
- unexpected source IP at a firewall
- policy mismatch
- asymmetric routing

Always inspect the effective configuration before changing it. The correct CIDRs depend on the cluster networking model and connected networks.

---

## 7. DNS

### 7.1 Pod lookup flow

Typical lookup:

```text
application
  -> pod /etc/resolv.conf
  -> CoreDNS Service IP
  -> CoreDNS
     -> Kubernetes plugin for cluster names
     -> upstream resolver for external names
```

Service records commonly include:

```text
<service>.<namespace>.svc.cluster.local
```

### 7.2 Search domains and `ndots`

A normal pod often has:

```text
search <namespace>.svc.cluster.local svc.cluster.local cluster.local
options ndots:5
```

With `ndots:5`, a name containing fewer than five dots is tried with search suffixes before or alongside the absolute form. An application repeatedly resolving `api.example.com` can therefore generate[...]

Use a trailing dot for an explicitly absolute test:

```bash
nslookup api.example.com.
```

High DNS query volume or latency can come from search expansion, not only from CoreDNS CPU.

### 7.3 Custom DNS

When the VNet uses custom DNS servers, those servers must resolve or forward the Azure and private DNS zones required by the cluster. Common designs forward appropriate Azure zones to Azure DNS at `16[...] 

Do not configure a pod to bypass CoreDNS as a first troubleshooting step. That can make external names work while breaking Kubernetes service discovery.

If only some custom DNS servers are healthy, failures can look intermittent because queries are distributed or retried across upstreams. Test every configured upstream independently.

CoreDNS `forward` supports `random`, `round_robin`, and `sequential` upstream-selection policies; the default is `random`. A three-upstream configuration with two unreachable servers can therefore pro[...] 

When a network error occurs, the forward plugin health-checks the upstream. A healthy proxy that fails an exchange causes another upstream to be tried. If all upstreams are considered down, CoreDNS tr[...] 

Prove the upstream problem:

```bash
# Run from a network location that follows the same route as CoreDNS.
dig @<dns-server-1> www.bing.com
dig @<dns-server-2> www.bing.com
dig @<dns-server-3> www.bing.com

# Test UDP and TCP because large/truncated replies retry over TCP.
dig @<dns-server> www.bing.com
dig +tcp @<dns-server> www.bing.com
```

Inspect CoreDNS logs and metrics for timeouts, unhealthy upstreams, request duration, and which upstream handled a query. Validate routes, NSGs, firewall rules, and return paths from every CoreDNS nod[...] 

### 7.4 CoreDNS customization

AKS supports CoreDNS customization through supported ConfigMaps. Use a custom server block or rewrite only when the behavior is understood and tested.

Troubleshoot:

```bash
kubectl get pods -n kube-system -l k8s-app=kube-dns -o wide
kubectl get service -n kube-system kube-dns -o wide
kubectl logs -n kube-system -l k8s-app=kube-dns --tail=200
kubectl get configmap -n kube-system coredns -o yaml
kubectl get configmap -n kube-system coredns-custom -o yaml
```

From a test pod:

```bash
cat /etc/resolv.conf
nslookup kubernetes.default.svc.cluster.local
nslookup <internal-name>
nslookup example.com.
```

Interpret the pattern:

| Result | Likely layer |
|---|---|
| Cluster name fails, external works | CoreDNS Kubernetes plugin, Service path, or cluster-domain issue |
| Cluster name works, external fails | Upstream resolver, custom DNS, firewall, or forwarding |
| DNS Service IP unreachable | Service data plane, network policy, node networking |
| Only one node's pods fail | Node-local data plane or node DNS path |
| Intermittent external failure | unhealthy upstream, timeout, packet loss, or saturation |

### 7.5 LocalDNS

LocalDNS places a DNS caching/forwarding path closer to workloads, reducing repeated cross-node queries and pressure on central CoreDNS. It doesn't fix:

- incorrect private-zone links
- broken custom DNS forwarding
- an overlapping CIDR
- an application using the wrong name

Use metrics and query tests to prove whether the failure is before or after the local cache.

---

## 8. Private clusters and control-plane connectivity

### 8.1 Private API server access

In a private AKS cluster, the API server uses private connectivity and private DNS. Clients need:

- network reachability through the VNet, peering, VPN, or ExpressRoute
- DNS resolution for the private API-server name
- NSG, firewall, and route permission
- valid authentication and authorization

Separate these failure classes:

| Symptom | First checks |
|---|---|
| Name doesn't resolve | Private DNS zone, VNet link, custom DNS forwarder |
| TCP timeout | Route, NSG, firewall, VPN/ExpressRoute |
| TLS error | Wrong endpoint, interception, CA or certificate issue |
| `401` | Authentication/token |
| `403` | Authorization |

API-server authorized IP ranges restrict public endpoint access. They don't replace private-cluster networking and don't authorize Kubernetes actions.

### 8.2 API Server VNet Integration

API Server VNet Integration projects API-server connectivity into a delegated subnet. It is distinct from a classic private-cluster private endpoint design. State the exact cluster configuration befor[...] 

### 8.3 Konnectivity

AKS uses Konnectivity for secure control-plane-to-node communication without requiring the control plane to initiate arbitrary direct connections to every node.

This path matters for operations such as:

- `kubectl exec`
- `kubectl logs`
- `kubectl port-forward`
- API-server access to node-hosted components

If normal API requests work but `exec`, logs, or port-forward fail, investigate the control-plane-to-node tunnel, Konnectivity agents, node health, and required egress instead of treating it as a gene[...] 

### 8.4 Metrics Server path

Do not describe Metrics Server as a direct dependency of Cluster Autoscaler.

```text
kubelet exposes resource metrics
  -> Metrics Server scrapes kubelet
  -> Metrics Server serves metrics.k8s.io
  -> API aggregation exposes the API through kube-apiserver
  -> kubectl top and HPA consume it
```

Important distinctions:

- HPA can use Metrics Server resource metrics.
- `kubectl top` uses the same resource metrics API.
- Cluster Autoscaler responds to unschedulable pods and scheduler state, not `kubectl top`.

Troubleshoot:

```bash
kubectl get apiservice v1beta1.metrics.k8s.io
kubectl describe apiservice v1beta1.metrics.k8s.io
kubectl get --raw /apis/metrics.k8s.io/v1beta1/nodes
kubectl get pods -n kube-system -l k8s-app=metrics-server -o wide
kubectl logs -n kube-system -l k8s-app=metrics-server --tail=200
```

Check both paths:

1. Metrics Server to kubelet, normally HTTPS on port `10250`.
2. API aggregation/control plane to the Metrics Server API.

---

## 9. Network policy and Cilium

### 9.1 Policy behavior

Kubernetes NetworkPolicy is allow-list based:

- A pod is non-isolated for a direction until a policy selects it for that direction.
- After selection, allowed traffic is the union of all applicable policies.
- An ingress allow doesn't automatically allow egress.
- Both source egress and destination ingress policy can affect a connection.
- Policy uses pod/namespace selectors and IP blocks, not Service names.

Always check selectors against actual labels:

```bash
kubectl get networkpolicy -A
kubectl describe networkpolicy -n <namespace> <policy>
kubectl get pods -n <namespace> --show-labels
kubectl get namespace --show-labels
```

### 9.2 Azure CNI powered by Cilium

Cilium uses eBPF for the network data plane and policy enforcement. It can provide:

- Kubernetes Service load balancing
- Kubernetes NetworkPolicy enforcement
- CiliumNetworkPolicy capabilities where supported
- flow visibility through Hubble
- drop reasons closer to the enforcement point

Cilium doesn't remove the need to inspect Azure routing, NSGs, or firewalls. A packet can pass Cilium policy and still be dropped later.

### 9.3 Drop investigation

Start with:

```bash
kubectl get pods -A -o wide
kubectl get networkpolicy -A
kubectl get ciliumnetworkpolicy -A
kubectl get ciliumclusterwidenetworkpolicy
kubectl get pods -n kube-system -l k8s-app=cilium -o wide
kubectl logs -n kube-system -l k8s-app=cilium \
  -c cilium-agent --since=10m --prefix
```

Then reproduce one flow and observe the node hosting the source or destination endpoint:

```bash
cilium status --verbose
cilium monitor --type drop
hubble observe --verdict DROPPED
```

Use `cilium connectivity test` for a broader controlled validation after checking whether its test resources and policies are acceptable in the cluster.

Correlate:

- source and destination identity
- source and destination labels
- destination port and protocol
- drop reason
- node on which the drop occurred
- policy that selected the endpoint

Interpret the evidence:

| Observation | Meaning |
|---|---|
| Matching policy-denied drop | Selector/direction/port rule rejected the flow |
| No Cilium drop, packet leaves node | Continue with Azure route, NSG, firewall, and destination |
| DNS flow denied | Add the required egress to the actual DNS endpoint/port |
| Policy selects no pods | Label or namespace-selector mismatch |
| Only one direction allowed | Check both source egress and destination ingress isolation |

A timeout by itself doesn't prove NetworkPolicy. A policy drop event with the matching five-tuple is evidence.

---

## 10. Troubleshooting method

### 10.1 Establish scope

Ask:

- one pod, one node, one namespace, or the entire cluster?
- same-node only or cross-node only?
- ClusterIP, internal frontend, public frontend, or direct endpoint?
- TCP connection, TLS handshake, or HTTP request?
- new deployment or previously working?
- one destination or all destinations?

### 10.2 Resolve desired state

```bash
kubectl get service <service> -o yaml
kubectl get endpointslice \
  -l kubernetes.io/service-name=<service> -o yaml
kubectl get pods -l <selector> -o wide
kubectl get events -A --sort-by=.lastTimestamp
```

Verify:

- selector matches pod labels
- endpoint addresses exist
- endpoint port matches the container listener
- pods are ready
- `targetPort` resolves to the intended numeric or named port

### 10.3 Test progressively

```text
inside source pod -> destination pod IP
inside source pod -> Service ClusterIP
inside cluster    -> ingress/gateway frontend
inside VNet       -> private frontend
external client   -> public frontend
```

The first failed boundary usually identifies the responsible layer.

### 10.4 Inspect Azure state

Validate:

- frontend IP
- load-balancing rule
- health probe
- backend-pool membership
- effective NSG
- effective routes
- NAT Gateway association
- firewall logs
- subnet free addresses

Useful Azure CLI patterns:

```bash
az aks show -g <rg> -n <cluster> \
  --query 'networkProfile'

az network nic list-effective-nsg \
  --resource-group <node-resource-group> \
  --name <node-nic>

az network nic show-effective-route-table \
  --resource-group <node-resource-group> \
  --name <node-nic>
```

### 10.5 Observe the packet

Use packet capture only after defining the expected packet:

- source IP and port
- destination IP and port
- interface
- expected NAT at that hop

Example:

```bash
tcpdump -ni any \
  'host <source-or-destination-ip> and port <port>'
```

Capture on both sides of a suspected boundary. A packet visible on the source node but absent on the destination node points to a different layer than a packet arriving and receiving a reset.

### 10.6 Common scenarios

#### Public Service times out

1. Confirm frontend IP and DNS.
2. Inspect Azure health probe.
3. Confirm NSG permits `AzureLoadBalancer`.
4. Confirm backend nodes and Service endpoints.
5. Test NodePort/Service path from inside the VNet.
6. Inspect `externalTrafficPolicy` and endpoint placement.
7. Capture traffic on the selected node.

#### Service works by pod IP but not ClusterIP

Investigate Service translation:

- wrong Service selector or port
- stale/missing EndpointSlice
- kube-proxy or Cilium service-programming issue
- NetworkPolicy matching Service-translated traffic

#### Same-node works, cross-node fails

Investigate:

- node-to-node route and NSG
- overlay or Kubenet route state
- Cilium tunnel/native-routing health
- MTU mismatch
- asymmetric return path

#### DNS is intermittent

1. Compare short name and FQDN with trailing dot.
2. Inspect `/etc/resolv.conf` and `ndots`.
3. Test the CoreDNS Service IP.
4. Test each upstream DNS server independently.
5. Inspect CoreDNS errors, latency, throttling, and restarts.
6. Check UDP and TCP port 53 paths.

#### Egress works at low load but fails under concurrency

1. Confirm DNS remains successful.
2. Compare connection errors with flow count.
3. Inspect NAT Gateway, load-balancer, or firewall SNAT metrics.
4. Check connection reuse and retry behavior.
5. Add SNAT capacity or change architecture only after proving exhaustion.

---

## 11. Interview question index

The detailed sections above are the canonical answers. This index avoids repeating shortened versions that can omit an important condition or troubleshooting step.

| Interview question | Complete answer |
|---|---|
| Explain a public `LoadBalancer` Service end to end | [Azure Load Balancer packet flow](#22-azure-load-balancer-packet-flow) |
| Why does NodePort work without a listening process? | [Why NodePort works without a listening process](#23-why-nodeport-works-without-a-listening-process) |
| Compare `externalTrafficPolicy: Local` and `Cluster` | [`externalTrafficPolicy`](#24-externaltrafficpolicy) |
| Explain health probes and `168.63.129.16` | [Health probes](#25-health-probes) |
| What is Floating IP and why does AKS use it? | [Azure Load Balancer Floating IP](#26-azure-load-balancer-floating-ip) |
| Why is a `LoadBalancer` Service pending? | [`LoadBalancer` Service remains pending](#27-loadbalancer-service-remains-pending) |
| Compare NGINX and Istio application routing | [Application routing NGINX versus Istio](#34-application-routing-nginx-versus-istio) |
| How do you isolate an NGINX ingress 404? | [NGINX ingress returns HTTP 404](#35-nginx-ingress-returns-http-404) |
| How do you prove AGIC synchronized Application Gateway? | [AGIC reconciliation and troubleshooting](#45-agic-reconciliation-and-troubleshooting) |
| What objects does Application Gateway for Containers use? | [Application Gateway for Containers](#4-application-gateway-for-containers) |
| Compare Load Balancer and NAT Gateway SNAT | [Azure Load Balancer versus NAT Gateway SNAT](#53-azure-load-balancer-versus-nat-gateway-snat) |
| What is the AKS outbound precedence order? | [Route selection before SNAT](#52-route-selection-before-snat) |
| Explain traditional Azure CNI cross-node traffic | [Traditional Azure CNI cross-node flow](#65-traditional-azure-cni-cross-node-flow) |
| How do you recover from traditional Azure CNI IP exhaustion? | [IP exhaustion and migration](#66-traditional-azure-cni-ip-exhaustion-and-migration) |
| Explain CNS, IPAM, and NNC | [Dynamic IP allocation](#67-azure-cni-pod-subnet-dynamic-ip-allocation) |
| Explain Azure CNI Overlay cross-node routing and SNAT | [Azure CNI Overlay cross-node flow](#63-azure-cni-overlay-cross-node-flow) |
| How do you prove a Cilium policy drop? | [Drop investigation](#93-drop-investigation) |
| Explain internal versus external DNS resolution | [DNS](#7-dns) |
| Why can two of three unhealthy upstream DNS servers cause intermittent failure? | [Custom DNS](#73-custom-dns) |
| Explain the Metrics Server network path | [Metrics Server path](#84-metrics-server-path) |

### Interview feedback questions

The following questions are attached from the networking interview discussion and resulting feedback.

#### 1. Application Routing add-on

**Feedback:** Insufficient familiarity with the architecture and troubleshooting differences between NGINX-based and Istio-based Application Routing.

1. What is the difference between NGINX-based Application Routing and Istio-based Application Routing?
   - Compare the APIs, controller/data-plane architecture, supported features, upgrade model, and use cases.
   - [Application routing NGINX versus Istio](#34-application-routing-nginx-versus-istio)
2. Have you used the Istio-based Application Routing implementation?
   - Be prepared to describe a hands-on deployment using `GatewayClass`, `Gateway`, `HTTPRoute`, a backend `Service`, and the resource status conditions.
   - [Minimal Gateway API example](#33-minimal-gateway-api-example)
3. An Ingress is created successfully, but external access returns HTTP `404`. How do you troubleshoot it?
   - How do you determine whether the request matched the Ingress host and path?
   - How do you verify the backend path rewrite?
   - Which NGINX access-log fields show the selected upstream and upstream response?
   - How do you compare the ingress IP and path with the Service or pod IP and backend path?
   - [NGINX ingress returns HTTP 404](#35-nginx-ingress-returns-http-404)

#### 2. Outbound traffic priority

**Feedback:** Did not identify the expected AKS outbound precedence when UDR, NAT Gateway, Load Balancer outbound, and default outbound mechanisms coexist.

1. A subnet has a UDR, NAT Gateway, Load Balancer outbound rule, and default outbound access. What is the outbound traffic priority?
2. Why can the observed outbound public IP be an Azure Firewall IP instead of the NAT Gateway IP?
3. How do the effective route and selected next hop affect which component performs SNAT?

[Route selection before SNAT](#52-route-selection-before-snat)

#### 3. Azure Load Balancer health probe

**Feedback:** Did not know that Azure Load Balancer health probes originate from `168.63.129.16`.

1. With `externalTrafficPolicy: Local`, how does Azure Load Balancer determine which node is healthy?
2. What source IP does the Azure Load Balancer health probe use?
3. Why must the NSG allow `168.63.129.16`, normally through the `AzureLoadBalancer` service tag?
4. What happens to new client flows when the probe is blocked?

[Health probes](#25-health-probes) and [`externalTrafficPolicy`](#24-externaltrafficpolicy)

#### 4. Cross-node pod networking

**Feedback:** Could not explain Kubenet cross-node routing or Azure CNI Overlay cross-node traffic flow.

##### Kubenet

1. How does pod-to-pod traffic route across nodes with Kubenet?
2. How does the source node know which node owns the destination pod CIDR?
3. Where are the route entries stored, and how are Azure route tables programmed?
4. How are pod CIDRs allocated to nodes?

[Kubenet cross-node flow](#64-kubenet-cross-node-flow)

##### Azure CNI Overlay

1. How does cross-node pod-to-pod traffic flow with Azure CNI Overlay?
2. Is pod-to-pod traffic SNATed?
3. How does the data plane determine which node owns the destination pod CIDR?
4. Which managed routing information maintains the node-to-pod-CIDR mapping?
5. What is the role of `kube-proxy` or Cilium, and what is not their role in selecting the destination node?

[Azure CNI Overlay cross-node flow](#63-azure-cni-overlay-cross-node-flow)

#### 5. Cilium and NetworkPolicy troubleshooting

**Feedback:** Was not familiar with Cilium flow and drop analysis for NetworkPolicy troubleshooting.

1. A Kubernetes or Cilium network policy isn't allowing or blocking traffic as expected. How do you troubleshoot it?
2. Which pods, labels, selectors, policy directions, ports, and namespaces do you validate?
3. Which Cilium agent logs do you inspect?
4. How do you determine whether Cilium dropped the packet?
5. What does the following command show?

   ```bash
   cilium monitor --type drop
   ```

6. How do you distinguish a Cilium policy drop from an Azure route, NSG, firewall, DNS, or application failure?

[Drop investigation](#93-drop-investigation)

#### 6. CoreDNS and custom DNS behavior

**Feedback:** Could not fully explain CoreDNS forwarding or why partial custom-DNS failure affected only external resolution.

1. Explain the complete resolution path for an internal name such as:

   ```text
   service.default.svc.cluster.local
   ```

2. Explain the complete resolution path for an external name such as:

   ```text
   www.bing.com
   ```

3. Internal service resolution works, but external DNS resolution fails approximately two-thirds of the time. What do you investigate?
4. Why can internal DNS continue to work while external DNS fails?
5. How does the CoreDNS `forward` plugin select among multiple custom DNS servers?
6. If three custom DNS servers are configured, two are unreachable, and one is healthy, why can roughly two-thirds of requests fail?
7. How do you test every upstream over UDP and TCP and prove which path is failing?

[Pod lookup flow](#71-pod-lookup-flow), [Custom DNS](#73-custom-dns), and [CoreDNS customization](#74-coredns-customization)

---

## 12. Command reference

### Kubernetes objects

```bash
kubectl get nodes -o wide
kubectl get pods -A -o wide
kubectl get service -A -o wide
kubectl get endpointslice -A
kubectl get ingress -A
kubectl get gateway,httproute -A
kubectl get networkpolicy -A
kubectl get events -A --sort-by=.lastTimestamp
```

### Workload and Service validation

```bash
kubectl describe pod -n <namespace> <pod>
kubectl describe service -n <namespace> <service>
kubectl get endpointslice -n <namespace> \
  -l kubernetes.io/service-name=<service> -o yaml
kubectl exec -n <namespace> <pod> -- \
  curl -sv --connect-timeout 5 http://<service>:<port>/
```

### DNS

```bash
kubectl exec -n <namespace> <pod> -- cat /etc/resolv.conf
kubectl exec -n <namespace> <pod> -- \
  nslookup kubernetes.default.svc.cluster.local
kubectl exec -n <namespace> <pod> -- nslookup example.com.
kubectl logs -n kube-system -l k8s-app=kube-dns --tail=200
```

### Cluster network configuration

```bash
az aks show -g <resource-group> -n <cluster> \
  --query '{
    networkPlugin:networkProfile.networkPlugin,
    networkPluginMode:networkProfile.networkPluginMode,
    networkDataplane:networkProfile.networkDataplane,
    podCidrs:networkProfile.podCidrs,
    serviceCidrs:networkProfile.serviceCidrs,
    dnsServiceIP:networkProfile.dnsServiceIP,
    outboundType:networkProfile.outboundType,
    loadBalancerProfile:networkProfile.loadBalancerProfile,
    natGatewayProfile:networkProfile.natGatewayProfile
  }'
```

### Azure routes and NSGs

```bash
az network nic show-effective-route-table \
  --resource-group <node-resource-group> \
  --name <node-nic>

az network nic list-effective-nsg \
  --resource-group <node-resource-group> \
  --name <node-nic>
```

---

## 13. References

### Public Microsoft and Kubernetes documentation

- [CNI networking in AKS](https://learn.microsoft.com/azure/aks/concepts-network-cni-overview)
- [Plan pod networking for AKS](https://learn.microsoft.com/azure/aks/plan-pod-networking)
- [Azure CNI Overlay](https://learn.microsoft.com/azure/aks/concepts-network-azure-cni-overlay)
- [Azure CNI Pod Subnet](https://learn.microsoft.com/azure/aks/concepts-network-azure-cni-pod-subnet)
- [Customize cluster egress with outbound types](https://learn.microsoft.com/azure/aks/egress-outboundtype)
- [Configure a public Standard Load Balancer in AKS](https://learn.microsoft.com/azure/aks/configure-load-balancer-standard)
- [Azure Load Balancer outbound connections and SNAT](https://learn.microsoft.com/azure/load-balancer/load-balancer-outbound-connections)
- [Use NAT Gateway with AKS](https://learn.microsoft.com/azure/aks/nat-gateway)
- [Control egress with UDR](https://learn.microsoft.com/azure/aks/egress-udr)
- [Application routing with Gateway API](https://learn.microsoft.com/azure/aks/app-routing-gateway-api)
- [Application Gateway for Containers overview](https://learn.microsoft.com/azure/application-gateway/for-containers/overview)
- [Private AKS clusters](https://learn.microsoft.com/azure/aks/private-clusters)
- [Customize CoreDNS in AKS](https://learn.microsoft.com/azure/aks/coredns-custom)
- [Network policies in AKS](https://learn.microsoft.com/azure/aks/use-network-policies)
- [Azure CNI powered by Cilium](https://learn.microsoft.com/azure/aks/azure-cni-powered-by-cilium)
- [Configure Azure CNI dynamic IP allocation](https://learn.microsoft.com/azure/aks/configure-azure-cni-dynamic-ip-allocation)
- [Troubleshoot AGIC](https://learn.microsoft.com/troubleshoot/azure/application-gateway/ingress-controller-troubleshoot)
- [Azure Load Balancer Floating IP](https://learn.microsoft.com/azure/load-balancer/load-balancer-floating-ip)
- [Service](https://kubernetes.io/docs/concepts/services-networking/service/)
- [Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/)
- [Gateway API](https://gateway-api.sigs.k8s.io/)
- [DNS for Services and Pods](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/)
- [Debugging DNS resolution](https://kubernetes.io/docs/tasks/administer-cluster/dns-debugging-resolution/)
- [Resource metrics pipeline](https://kubernetes.io/docs/tasks/debug/debug-cluster/resource-metrics-pipeline/)
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [CoreDNS forward plugin](https://coredns.io/plugins/forward/)

---

## 14. Accuracy and safety notes

- This guide was reviewed against Microsoft Learn and upstream Kubernetes documentation on **6 October 2026**.
- Preview features, limits, defaults, supported versions, and retirement dates can change. Verify them before a production design or customer-facing recommendation.
- A timeout doesn't prove firewall or NetworkPolicy denial. Correlate the flow with routes, policy state, logs, metrics, or packet capture.
- Don't edit AKS-managed load-balancer, route, VMSS, or network resources directly unless the documented AKS workflow explicitly requires it; reconciliation can overwrite manual changes.
- Changing outbound type, public IPs, routes, or NAT configuration can terminate existing connections and change source IPs. Update allowlists before migration.
- Never add subscription IDs, tenant IDs, customer addresses, credentials, tokens, kubeconfig, private keys, or unredacted production logs to this repository.
