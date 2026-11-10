# Agent Firewall

**A policy checkpoint for AI agents.** Every tool call an agent wants to make is checked against your written policy before it runs, and comes back as ALLOW, BLOCK or ESCALATE with a full audit trail.

Built on [SERV Reasoning](https://docs.openserv.ai/serv-reasoning/introduction) for SERV Hackathon 02 (Open Track).

## The problem

AI agents can now send emails, move money and touch customer data. Companies will not let them act alone until something checks each action first, and can explain every decision afterwards.

## What it does

The firewall sits between an agent and its tools. For each proposed tool call it receives the tool name, the arguments, the agent's stated reasoning and the policy, then returns:

- **allow**: every rule passes, the call can run
- **block**: the action is prohibited outright (for example customer data sent to an external address)
- **escalate**: a human must approve (for example a missing or unverified approval)

Every decision includes one check per policy rule (pass, fail or unclear, with a note), a step-by-step audit trail, a confidence score and an attack flag.

## How it uses SERV Reasoning

All decisions run through the SERV inference API (`https://inference-api.openserv.ai`) on `claude-haiku-4.5`, in three layers:

1. **SERV Prompt Guard** (`serv_prompt_guard`): can stop injection attempts before the model is called.
2. **Policy engine on SERV Reasoning**: checks every rule and returns a decision in a fixed schema.
3. **SERV Shadow Agent** (`serv_shadow_agent`): validates the decision against the policy before it is returned.

SERV's structured reasoning is what makes a small, cheap model reliable enough to act as a gate on every call.

## Demo scenarios

Run from the web demo or the test script. All six pass.

| Scenario | Result |
|---|---|
| Low amount invoice ($1,200) | allow |
| High amount invoice ($12,500) | escalate, human approves |
| Business invoice to a personal Gmail address | block |
| Prompt injection hidden in the email body | block, attack detected |
| Customer list (4,812 records) sent to an external address | block, attack detected |
| $25,000 invoice with a verbal "approval" and no reference ID | escalate, attack detected |

In testing, the prompt injection was stopped at two different layers on different runs: by SERV's guard layer in about 2 seconds before the model was called, and by the policy engine with a full audit trail.

## Run it

You need Node.js 18 or later and a SERV API key from [console.openserv.ai](https://console.openserv.ai).

    npm install
    export SERV_API_KEY=serv_yourkey
    npm start

Then open http://localhost:3000. Pick a scenario or write your own tool call, run it, approve or deny escalations, and export the audit log as JSON.

To run the six tests in the terminal:

    npm test

## Use it in your own agent

    import { checkToolCall } from "./firewall.js";

    const decision = await checkToolCall({
      tool_name: "send_email",
      arguments: { to: "finance@partner.com", subject: "Invoice", body: "Total: $12,500" },
      reasoning_graph: "User asked me to send the invoice.",
    });

    if (decision.decision === "allow") {
      // run the tool
    }

Pass your own `policy` array in the call to replace the default rules in `firewall.js`.

## Files

- `firewall.js`: the firewall (policy, SERV calls, decision schema, attack flag)
- `server.js`: small web server and audit log for the demo
- `index.html`: the demo page
- `run-tests.js`: the six test scenarios

## Limits and next steps

- The demo uses simulated tool calls. The firewall does not yet execute real tools.
- The audit log is kept in memory and resets when the server restarts.
- Next: an SDK wrapper for real tool calls, persistent audit storage, per-team policies, and Slack approval for escalations.

## Business model

Priced per checked tool call, with team plans for audit exports and compliance reporting.
