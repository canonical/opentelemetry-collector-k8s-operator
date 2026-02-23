# **juju-overview.md**

## **What Juju Is**
Juju is an orchestration system that manages the lifecycle of applications (workloads) through *charms*. A charm encodes operational knowledge about how to install, configure, integrate, and maintain a workload. Juju handles the model, relations, units, and events, while the charm implements the logic that responds to those events.

## **How Juju Models Applications**
Juju organizes workloads into models containing:
- **Applications** — logical deployments of a workload.
- **Units** — individual instances of an application.
- **Machines** — hosts where units run (for machine charms).
- **Relations** — connections between applications that exchange data.
- **Integrations** — the modern name for relations, representing declared interfaces between applications.

Each charm instance runs inside a unit and receives events from Juju that reflect changes in the model.

---

## **How Charms Work**
A charm is a Python program that reacts to Juju events. These events represent lifecycle changes such as installation, configuration updates, relation changes, or leadership changes. The charm’s job is to translate these events into actions that bring the workload into the correct state.

### **Key Responsibilities of a Charm**
- Install and configure the workload. In case of a Kubernetes charm, the workload is provided through an OCI-compliant artifact called a ROCK. In a machine charm, oftentimes, the workload is provided through a snap.
- Maintain idempotent, predictable behavior.
- React to relation data and update configuration accordingly.
- Manage services, files, and runtime state.
- Report status back to Juju.

Charms should avoid embedding business logic in event handlers. Instead, they should delegate to a reconciler or similar pattern that computes and applies desired state.

---

## **Juju Events**
Juju emits events to signal changes in the environment. Common events include:
- **install** — initial setup of the workload.
- **config-changed** — configuration updates. The `config-changed` hook is guaranteed to run after the `install` or `update-status` hooks.
- **relation-created / joined / changed / departed / broken** — integration lifecycle.
- **leader-elected / leader-settings-changed** — leadership changes.
- **update-status** — periodic health reporting. Some charms use the `update-status` hook to perform polling of the workload's status.

Event handlers should remain thin and delegate to a central reconciliation loop.

---

## **Observed vs. Desired State**
Juju charms operate by comparing:
- **Observed state** — what the system currently looks like (files, services, relation data, configuration).
- **Desired state** — what the system *should* look like based on charm logic and relation data.

The charm’s job is to converge the system toward desired state in an idempotent way.

---

## **Relations and Integrations**
Relations allow applications to exchange structured data. Each relation has:
- A **role** (provider or requirer).
- A **schema** or **databag** (what data is exchanged). Databags are supposed to be strings. They are often constructed as dictionaries in Python, but are then dumped in using `json.dumps()`. You can use Pydantic models to create schemas for what the data in a relation databag should look like.
[//]: # Maybe we should mention more rules regarding assumptions about databags here?
- A **lifecycle** (created → joined → changed → departed → broken).

Charms must handle partial or missing relation data gracefully and avoid assuming ordering between events.

---

## **Machine Charms**
In machine charms:
- Units run directly on machines (not containers).
- The charm manages system-level resources such as packages, services, and files.
- Systemd, apt, and filesystem operations are common.
- Idempotency is critical because operations run directly on the host.

Machine charms must be careful to avoid destructive or non-repeatable operations.

---

## **Status Reporting**
Charms communicate health and readiness through Juju status:
- **active** — workload is healthy.
- **waiting** — waiting for data or resources. This is usual in scenarios where, for example, the charm is attempting to set resource restrictions using `lightkube` and is waiting for the process to complete.
- **blocked** — is meant to represent a scenario where the workload needs manual intervention by an admin. For example, the charm may need a specific config to be set by the user before it can successfully start the workload.
- **maintenance** — performing operations.
- **error** — this most commonly happens when the charm Python code encounters an uncaught error. 

Status should reflect the workload’s actual condition, not just charm execution flow.

---

## **Why This Matters for Copilot**
Copilot should use this overview to:
- Understand the Juju model and event-driven architecture.
- Generate charm code that respects Juju’s lifecycle.
- Follow correct patterns for relations, events, and workload management.
- Avoid embedding business logic in event handlers.
- Produce idempotent, predictable operations.
