# talos-kms-vault

Proxy between a Talos node and a Hashicorp Vault instance to enable KMS disk encryption.
This project is a proof of concept.

## Usage

The KMS server supports multiple Vault authentication methods and automatically detects the best method based on your environment.

### Basic Configuration

Set the following environment variables:

```bash
VAULT_ADDR=https://vault.example.com
```

The server will automatically detect and use the appropriate authentication method based on available credentials and environment.

## Vault Authentication Methods

### 1. Token Authentication

Direct token authentication (simplest for development):

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_TOKEN=your-vault-token
```

### 2. Kubernetes Authentication (Recommended for Production)

When running in Kubernetes, the server can authenticate using the pod's ServiceAccount:

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_K8S_ROLE=talos-kms-role
# Optional: customize mount path (default: kubernetes)
export VAULT_K8S_MOUNT_PATH=kubernetes
```

**Vault Setup Required:**
```bash
# Enable Kubernetes auth
vault auth enable kubernetes

# Configure Kubernetes auth
vault write auth/kubernetes/config \
    token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
    kubernetes_host="https://kubernetes.default.svc.cluster.local" \
    kubernetes_ca_cert="$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)"

# Create role for Talos KMS
vault write auth/kubernetes/role/talos-kms-role \
    bound_service_account_names=talos-kms \
    bound_service_account_namespaces=default \
    policies=talos-kms-policy \
    ttl=1h
```

### 3. AppRole Authentication

For service-to-service authentication:

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_ROLE_ID=your-role-id
export VAULT_SECRET_ID=your-secret-id  # Optional for some configurations
# Optional: customize mount path (default: approle)
export VAULT_APPROLE_MOUNT_PATH=approle
```

**Vault Setup Required:**
```bash
# Enable AppRole auth
vault auth enable approle

# Create role
vault write auth/approle/role/talos-kms \
    token_policies=talos-kms-policy \
    token_ttl=1h \
    token_max_ttl=4h

# Get role ID
vault read auth/approle/role/talos-kms/role-id

# Generate secret ID
vault write -f auth/approle/role/talos-kms/secret-id
```

### Advanced Configuration

**Force Specific Auth Method:**
```bash
export VAULT_AUTH_METHOD=kubernetes  # kubernetes|approle|token
```

**Disable Auto-Renewal:**
```bash
export VAULT_AUTO_RENEW=false
```

**Custom Transit Mount Path:**
```bash
./kms-server -mount-path=custom-transit
```

## Multi-Instance Deployment & Leader Election

### High Availability Setup

The KMS server supports running multiple instances in a Kubernetes cluster using leader election. Only one instance will be active at a time, ensuring consistency while providing high availability through automatic failover.

**Enable Leader Election:**
```bash
./kms-server \
  --enable-leader-election=true \
  --leader-election-namespace=default \
  --leader-election-name=talos-kms-leader \
  --leader-election-lease-duration=15s
```

**Environment Variables:**
```bash
export POD_NAME=talos-kms-pod-123              # Kubernetes pod name (auto-detected)
export POD_NAMESPACE=talos-system              # Pod namespace (auto-detected)
export LEADER_ELECTION_IDENTITY=custom-id      # Override identity (optional)
export LEADER_ELECTION_NAMESPACE=talos-system  # Lease namespace (optional)
export LEADER_ELECTION_NAME=talos-kms-leader   # Lease name (optional)
```

**Leader Election Configuration:**
- **Lease Duration**: Time before lease expires (default: 15s)
- **Renew Deadline**: Deadline for leader to renew lease (default: 10s)
- **Retry Period**: How often non-leaders try to acquire lease (default: 2s)

### Kubernetes RBAC Requirements

For leader election to work, the service account needs permissions to manage leases:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: talos-kms-leader-election
rules:
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: talos-kms-leader-election
subjects:
- kind: ServiceAccount
  name: talos-kms
roleRef:
  kind: Role
  name: talos-kms-leader-election
  apiGroup: rbac.authorization.k8s.io
```

### Deployment Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: talos-kms
spec:
  replicas: 3  # Run multiple instances
  selector:
    matchLabels:
      app: talos-kms
  template:
    metadata:
      labels:
        app: talos-kms
    spec:
      serviceAccountName: talos-kms
      containers:
      - name: kms-server
        image: talos-kms:latest
        args:
        - --enable-leader-election=true
        - --leader-election-namespace=$(POD_NAMESPACE)
        - --kms-api-endpoint=:8080
        - --enable-tls=true
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: VAULT_ADDR
          value: "https://vault.example.com"
        - name: VAULT_K8S_ROLE
          value: "talos-kms-role"
        ports:
        - containerPort: 8080
        livenessProbe:
          exec:
            command: ["/bin/sh", "-c", "test -f /tmp/leader"]
          initialDelaySeconds: 30
          periodSeconds: 10
```

### Behavior

- **Leader**: Processes all seal/unseal requests
- **Followers**: Return `UNAVAILABLE` error with current leader identity
- **Failover**: Automatic when leader becomes unhealthy
- **Split-brain Prevention**: Kubernetes lease coordination prevents multiple leaders

**Client Error Handling:**
When connecting to a non-leader instance, clients receive:
```
rpc error: code = Unavailable desc = Not the leader - current leader is talos-kms-pod-123
```

Clients should retry with backoff or implement service discovery to find the leader.

## Security & Validation

### UUID Validation

The server includes comprehensive UUID validation to ensure security and prevent injection attacks. By default, it enforces:

- **UUID v4 format** for maximum entropy and security
- **RFC 4122 compliance** with proper version and variant bits
- **Entropy checking** to prevent predictable or weak UUIDs
- **Input sanitization** for safe logging

**Validation Configuration:**
```bash
# Command line options
./kms-server \
  -disable-validation=false \
  -allow-uuid-versions=v4 \
  -disable-entropy-check=false

# Environment variables
export KMS_DISABLE_VALIDATION=false          # Enable/disable validation
export KMS_ALLOW_UUID_VERSIONS=v4            # v4, v1-v5, or any
export KMS_DISABLE_ENTROPY_CHECK=false       # Enable entropy checking
```

**⚠️ Security Note:** Disabling validation is NOT recommended for production environments as it removes important security protections against:
- Vault key injection attacks
- Log poisoning
- Resource exhaustion
- Audit trail corruption

### Request Security

- **Size limits**: Requests are limited to 4MB by default
- **Proper error handling**: Internal errors are sanitized before being returned to clients
- **Audit logging**: All operations are logged with sanitized UUIDs for security

## Vault Policy Requirements

All authentication methods require a policy that allows transit operations:

```hcl
# talos-kms-policy
path "transit/encrypt/+" {
  capabilities = ["update"]
}

path "transit/decrypt/+" {
  capabilities = ["update"]
}

# Optional: for key management
path "transit/keys/+" {
  capabilities = ["create", "read", "update"]
}
```

Apply the policy:
```bash
vault policy write talos-kms-policy policy.hcl
```

## TODOs

* ~~Talos Node's ID seems to be a UUID, if that's always the case implement a validation on the `Seal`/`Unseal` methods.~~ ✅ **COMPLETED** - Comprehensive UUID validation with RFC 4122 compliance and security checks
* ~~Dynamic vault authentication (don't use a static token and try to use the right method for the current context)~~ ✅ **COMPLETED** - Multiple auth methods now supported
* Maybe transform this into a Vault plugin.

## References

* KMS client and server example - https://github.com/siderolabs/kms-client