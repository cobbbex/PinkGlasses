package mcpserver

import (
	"context"
	"fmt"
)

// workerTools set up and remove remote workers, the two ways the app has:
//
//   - a VPS that can reach this install: add_remote_worker mints a single-use
//     enrollment token and the command to run on the VPS; the worker then
//     enrols as pending and approve_worker lets it take work.
//   - a VPS when nothing on the internet can reach this install: add_ssh_exit
//     records the VPS and generates a key for its authorized_keys, and
//     install_ssh_exit installs a worker over that session, already approved.
//
// A private key never passes through these tools: add_ssh_exit always has
// the server generate one, and only its public half is returned.
func workerTools() []toolDef {
	return []toolDef{
		{
			Name: "add_remote_worker",
			Description: "Start enrolling a VPS as a remote worker. Returns a single-use enrollment token (valid ttl_mins, default 60) " +
				"and the install command to run as root on the VPS; the VPS must be able to reach this install's gateway. " +
				"The worker then appears in list_workers as pending and takes no work until approve_worker. " +
				"If the install is not reachable from the internet, use add_ssh_exit instead. Operator role.",
			Schema: obj(map[string]any{
				"name":     str("The worker's name, e.g. vps-fra-1"),
				"pool_id":  str("Pool to join (list_workers → pools); default: the remote pool"),
				"ttl_mins": integer("Minutes the token stays valid; default 60"),
			}, "name"),
			Routes: []string{"POST /workers/enrollment-tokens"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				body := map[string]any{"kind": "vps", "name": a.str("name"), "ttl_mins": a.integer("ttl_mins", 60), "max_uses": 1}
				if p := a.str("pool_id"); p != "" {
					body["pool_id"] = p
				}
				var out map[string]any
				return out, c.post(ctx, "/workers/enrollment-tokens", body, &out)
			},
		},
		{
			Name: "approve_worker",
			Description: "Change a worker's state: approve (a pending worker starts taking tasks), drain (finish what it has, take nothing new), " +
				"resume (after drain), quarantine (stop it at once), revoke (its credential stops working). " +
				"Approving trusts the machine with every company's tasks in its pool: approve only a worker the user just set up. " +
				"quarantine and revoke need confirm: true. Operator role.",
			Schema: obj(map[string]any{
				"worker_id": str("Worker id from list_workers"),
				"action":    str("What to do", "approve", "drain", "resume", "quarantine", "revoke"),
				"confirm":   boolean("Must be true for quarantine and revoke"),
			}, "worker_id", "action"),
			Routes: []string{"POST /workers/{workerID}/{action}"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				action := a.str("action")
				switch action {
				case "approve", "drain", "resume":
				case "quarantine", "revoke":
					if !a.boolean("confirm") {
						return nil, errConfirm
					}
				default:
					return nil, fmt.Errorf("action must be approve, drain, resume, quarantine or revoke")
				}
				var out map[string]any
				return out, c.post(ctx, "/workers/"+a.str("worker_id")+"/"+action, nil, &out)
			},
		},
		{
			Name: "remove_worker", Destructive: true,
			Description: "Remove a remote (VPS) worker from the fleet. Its tasks in flight are retried elsewhere; the software on the VPS " +
				"is not uninstalled (for an SSH exit, use remove_ssh_exit, which does both). The standing local workers are refused: " +
				"they are part of this install. Requires confirm: true and the worker's exact name. Operator role.",
			Schema: obj(map[string]any{
				"worker_id": str("Worker id from list_workers"),
				"name":      str("The worker's exact name, typed back"),
				"confirm":   boolean("Must be true"),
			}, "worker_id", "name"),
			Routes: []string{"DELETE /workers/{workerID}"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				if !a.boolean("confirm") {
					return nil, errConfirm
				}
				var workers []map[string]any
				if err := c.get(ctx, "/workers", &workers); err != nil {
					return nil, err
				}
				id := a.str("worker_id")
				for _, w := range workers {
					if fmt.Sprint(w["id"]) != id {
						continue
					}
					if fmt.Sprint(w["name"]) != a.str("name") {
						return nil, fmt.Errorf("name does not match: the worker is %q", w["name"])
					}
					if fmt.Sprint(w["kind"]) == "local" {
						return nil, fmt.Errorf("%q is a local worker, part of this install: remove it from the Workers page if you mean to", w["name"])
					}
					var out map[string]any
					return out, c.del(ctx, "/workers/"+id, &out)
				}
				return nil, fmt.Errorf("no worker %s", id)
			},
		},
		{
			Name: "set_pool_discovery",
			Description: "Whether one of the token owner's pools runs that account's discovery (passive sources, DNS resolution, DNS bruteforce), " +
				"moving that load off this host onto its own workers; other accounts' scans are unaffected. If the pool has no active " +
				"worker the local workers take it back. Operator role.",
			Schema: obj(map[string]any{
				"pool_id":         str("Pool id from list_workers → pools"),
				"takes_discovery": boolean("true to move discovery onto this pool, false to stop"),
			}, "pool_id", "takes_discovery"),
			Routes: []string{"PATCH /pools/{poolID}"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out map[string]any
				return out, c.patch(ctx, "/pools/"+a.str("pool_id"), map[string]any{"takes_discovery": a.boolean("takes_discovery")}, &out)
			},
		},
		{
			Name: "list_ssh_exits", ReadOnly: true,
			Description: "SSH exits: VPSes this install reaches over SSH to run a worker when nothing on the internet can reach the install. " +
				"Each with host, user, the public key for the VPS's authorized_keys, session state and install status and log.",
			Schema: obj(map[string]any{}),
			Routes: []string{"GET /ssh-exits"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out map[string]any
				return out, c.get(ctx, "/ssh-exits", &out)
			},
		},
		{
			Name: "add_ssh_exit",
			Description: "Record a VPS as an SSH exit. The server generates an Ed25519 key and returns its public_key: it must be added to " +
				"~/.ssh/authorized_keys of `username` on the VPS (by the user, or by you if you have a shell there) before install_ssh_exit. " +
				"Scans then leave from the VPS's address. Operator role.",
			Schema: obj(map[string]any{
				"name":        str("Name of the exit, also the worker's name"),
				"host":        str("VPS address or name"),
				"port":        integer("SSH port; default 22"),
				"username":    str("SSH user; default root"),
				"remote_port": integer("Port the VPS listens on, on its own loopback, for the tunnel back; default 47090"),
				"pool_id":     str("Pool the worker joins; default the remote pool"),
			}, "name", "host"),
			Routes: []string{"POST /ssh-exits"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				body := map[string]any{"name": a.str("name"), "host": a.str("host"),
					"port": a.integer("port", 22), "username": a.str("username"), "remote_port": a.integer("remote_port", 47090)}
				if p := a.str("pool_id"); p != "" {
					body["pool_id"] = p
				}
				var out map[string]any
				return out, c.post(ctx, "/ssh-exits", body, &out)
			},
		},
		{
			Name: "install_ssh_exit",
			Description: "Install the worker on an SSH exit's VPS over its session: pulls the worker image and starts it, already approved. " +
				"Runs a script as root on the VPS. Returns at once; follow install_status and install_log with list_ssh_exits. Operator role.",
			Schema: obj(map[string]any{"exit_id": str("Exit id from list_ssh_exits")}, "exit_id"),
			Routes: []string{"POST /ssh-exits/{exitID}/install"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out map[string]any
				return out, c.post(ctx, "/ssh-exits/"+a.str("exit_id")+"/install", nil, &out)
			},
		},
		{
			Name: "remove_ssh_exit", Destructive: true,
			Description: "Remove an SSH exit: uninstalls the worker from the VPS if it can still reach it, closes the session, and deletes " +
				"the exit and its key. Requires confirm: true. Operator role.",
			Schema: obj(map[string]any{"exit_id": str("Exit id from list_ssh_exits"), "confirm": boolean("Must be true")}, "exit_id"),
			Routes: []string{"DELETE /ssh-exits/{exitID}"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				if !a.boolean("confirm") {
					return nil, errConfirm
				}
				var out map[string]any
				return out, c.del(ctx, "/ssh-exits/"+a.str("exit_id"), &out)
			},
		},
	}
}
