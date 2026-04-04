# AGENTS.md - vdexcli Development Rules

## tmux Session Rules

- Use the existing tmux session `vdexcli` for all build, test, run, and debug operations.
- **Never close** the session. Do not add windows or panes.
- If the session is accidentally closed, recreate it with `tmux new-session -d -s vdexcli`.
- **After sending C-c** (cancel), always wait **0.5 seconds** before sending the next key.
  Without this delay, the first character of the next input will be swallowed.
  Example: `tmux send-keys -t vdexcli C-c` → sleep 0.5 → then send next command.

## Build & Run

- Build: `go build -o vdexcli .` (run inside tmux session)
- The project uses Go 1.22+ with a single dependency (cobra).
