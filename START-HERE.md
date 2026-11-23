# START HERE — set up your machine and repo (Windows)

Time needed: about 45 minutes the first time.

## What's in this kit

| File | What it does |
|---|---|
| `CLAUDE.md` | Project rules Claude Code reads automatically at the start of every session |
| `docs/PRODUCT_BRIEF.md` | The product spec: vision, architecture, connectors, roadmap |
| `prompts/00-KICKOFF.md` | The first prompt to paste into Claude Code |
| `prompts/01-PHASE-PROMPTS.md` | One prompt per later phase (AWS, M365, Google Workspace, deploy…) |
| `.claude/settings.json` | Permission guardrails: what Claude may run freely, what it must ask, what it can never touch |
| `.claude/agents/security-reviewer.md` | A security-review subagent you can call after each feature |
| `.gitignore` | Keeps secrets, state files and build junk out of Git |

---

## 1. Pick your environment: WSL2 (recommended) or native Windows

For this project use **WSL2 (Ubuntu)**. The stack (Python, Docker, Helm, Terraform) is Linux-first,
Docker Desktop runs on WSL2 anyway, and Claude Code's command sandboxing works in WSL2 but not
on native Windows.

### 1a. Install WSL2 + Ubuntu
PowerShell **as Administrator**:
```powershell
wsl --install -d Ubuntu-24.04
```
Reboot, open "Ubuntu" from the Start menu, create your Linux user.

### 1b. Docker Desktop
Install Docker Desktop → Settings → General: "Use the WSL 2 based engine" →
Resources → WSL integration: enable for Ubuntu-24.04.

### 1c. VS Code
Install the **WSL** extension. From Ubuntu you can then run `code .` to open a folder.

## 2. Install the toolchain inside Ubuntu
```bash
sudo apt update && sudo apt install -y git build-essential curl unzip ca-certificates

# Python tooling (uv manages Python versions too)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Node.js LTS + pnpm (via fnm)
curl -fsSL https://fnm.vercel.app/install | bash
source ~/.bashrc
fnm install --lts
npm install -g pnpm
```
GitHub CLI: follow the Ubuntu/Debian steps at https://cli.github.com (official apt repo).
Later phases also want Terraform, Helm, kubectl and the AWS/Azure/Google CLIs — install them when
you reach those phases.

## 3. Install Claude Code (inside Ubuntu)
```bash
curl -fsSL https://claude.ai/install.sh | bash
claude doctor
```
Native-Windows alternative (PowerShell, no admin needed): `irm https://claude.ai/install.ps1 | iex`.
Install Git for Windows as well so Claude Code gets a Bash shell.

## 4. Git identity and GitHub login
```bash
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
git config --global init.defaultBranch main
gh auth login          # GitHub.com → HTTPS → login with browser
```
Claude Code is good at using `gh` for repos, issues and PRs, so you don't need a GitHub MCP server
to start.

## 5. Create the project and repo
Keep code on the Linux filesystem (`~/code/...`), not under `/mnt/c/...` — it's much faster.
```bash
mkdir -p ~/code && cd ~/code
# copy or unzip this kit here so you get ~/code/skyline/ containing CLAUDE.md etc.
# (Windows Explorer can reach it at \\wsl$\Ubuntu-24.04\home\<you>\code)
cd skyline
git init
git add -A
git commit -m "chore: project brief and Claude Code setup"
gh repo create skyline --private --source=. --remote=origin --push
```
Then on GitHub, under the repo's Settings:
- Branches: protect `main` (require PR + passing checks once CI exists).
- Code security: turn on Dependabot alerts, plus secret scanning / push protection if your plan includes them.

## 6. Your first Claude Code session
```bash
cd ~/code/skyline
claude
```
1. Log in when prompted (Pro/Max/Team/Enterprise or Console account).
2. Run `/model` and pick the strongest model available for planning-heavy work.
3. Press **Shift+Tab** until the mode shows **plan mode**. It reads and plans but won't edit yet.
4. Paste the whole of `prompts/00-KICKOFF.md` (everything below the `---` line).
5. Answer its questions, review the plan files, then switch out of plan mode and let it build.

## 7. Working rhythm that keeps this on track
- **One phase per session.** `/clear` between phases; each phase prompt tells Claude what to read.
- **Plan → approve → build → review → commit.** Read the diffs, especially connectors and auth.
- After each feature: *"Use the security-reviewer agent to review changes since main."*
- Tag the start of each phase (`git tag phase-1-start`) so reviews and rollbacks are easy.
- `/permissions` shows the active rules. If you click "always allow" for something risky,
  remove it there.
- Ask Claude to keep `CLAUDE.md` short and current. It's loaded into every session.

## 8. Before Phase 1: build a safe test lab
Never point an early build at a production tenant.
- **AWS:** a separate sandbox account (AWS Organizations), with some deliberately misconfigured
  resources to detect (open SG, public bucket, IAM user without MFA). Use budgets/alerts.
- **Microsoft 365:** a test tenant (developer sandbox if you qualify, or a trial tenant).
- **Google Workspace:** a trial domain or an isolated test OU you control.
- Create the read-only roles/apps using the onboarding templates Claude generates, and read them
  before you apply them.
