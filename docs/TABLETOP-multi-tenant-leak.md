# Tabletop: prompt injection in a customer-facing assistant leaks another tenant's data

**Duration** 90 minutes · **Participants** incident manager (facilitator), SOC analyst,
application engineer, cloud/platform engineer, legal or privacy representative, comms lead
· **Format** injects delivered in sequence; participants may ask for any evidence the
facilitator holds

This exercise is built on the lab in this repository, so every piece of evidence the
facilitator hands out can be *generated* rather than invented: `make ir-demo` produces the
detections, evidence packs and timelines referenced below.

---

## Facilitator brief (do not read aloud)

**What actually happened.** A support-knowledge document uploaded through the normal
content pipeline contained an instruction block. The assistant followed it, called
`lookup_ticket` on a record outside the asking customer's scope, and included the contents
in its reply. Attack chain: **A01 → A04**, detections **D005 → D013**.

**The decision that matters** is not "was there an injection" — the team will get there.
It is: *can we determine which customers' data was exposed, and to whom?* The answer is
**no**, because the agent holds one application identity, so the audit trail records the
application as the accessor rather than the asking user. That is the finding. A team that
spends the session hunting for attribution in telemetry that structurally cannot contain
it has learned the wrong lesson.

**Keep the clock visible.** If this is genuine personal-data exposure, GDPR Article 33 is
72 hours from becoming aware. Note when the group decides awareness began — that argument
is the most valuable ten minutes of the exercise.

---

## Inject 1 — T+0 (10 min)

> A support agent raises a ticket: a customer complained that the AI assistant's answer
> "mentioned a phishing incident we never reported." The support agent cannot reproduce it.

**Ask the group:** Is this an incident? What is the severity, and on what basis? What do
you need in the next 15 minutes?

*Facilitator notes.* Watch for premature closure — "the model hallucinated" is the
comfortable answer and it is wrong. The distinguishing question is whether the content was
*specific*: a hallucination invents plausible detail, an exfiltration reproduces real
detail. Reward anyone who asks to see the actual response text.

Evidence available on request: the assistant's response (`agent_traces.final_response`).

---

## Inject 2 — T+25 (15 min)

> Detection **D013** has fired: `lookup_ticket` returned `TKT-1003` — the security team's
> own incident record — in a session belonging to an external customer. **D005** also
> fired, reporting `injection_region = retrieved_context`.

**Ask:** What does D005's region field change about your response? Which document? How many
other sessions retrieved it?

*Facilitator notes.* This is the branch point. `retrieved_context` means a poisoned
document and the corpus is the blast radius. `system_prompt` would have meant the tool
catalogue itself is compromised — a supply-chain incident with a far wider scope. If the
group does not notice the distinction, ask them what they would do differently if the field
said `system_prompt`.

Evidence: `incidents/*-R005/evidence/blast_radius.json` — every session that retrieved the
same document, whether or not it was flagged.

---

## Inject 3 — T+45 (20 min) — the hard one

> Legal asks a direct question: **"Which customers' data was accessed, and by whom?"**

**Ask:** Answer it from the telemetry. If you cannot, say so precisely — what *can* you
establish, and what can you not?

*Facilitator notes.* The group cannot answer it, and the reason is structural, not a gap in
logging: `agent_traces.principal_arn` holds one value for every session because the agent
acts as itself. Evidence pack `attribution_available.json` shows exactly one principal
across all traces.

What *can* be established: which sessions retrieved the poisoned document, which tool calls
returned restricted records, and the exact window. What cannot: which human sat behind each
session, unless the application separately logged it.

**The right output of this inject** is a decision to treat every session in the window as
potentially implicated, plus a remediation item to propagate end-user identity into tool
calls. A team that keeps digging for per-user attribution is burning the notification clock.

---

## Inject 4 — T+65 (15 min)

> The platform engineer proposes disabling `lookup_ticket` immediately. The support director
> objects: it handles 40% of ticket-status queries and disabling it will breach SLA.

**Ask:** Make the call. Who owns it? What is the rollback?

*Facilitator notes.* Both positions are defensible; the exercise is whether the decision is
*made and recorded* rather than deferred. Note that `make ir-respond` performs exactly this
containment, and that the lab's own automation refuses to quarantine baseline documents
after a false-positive quarantine took down two legitimate ones. Mitigation options short of
a full disable: quarantine the document only, enforce output redaction, add the restricted
record to a denylist.

---

## Inject 5 — T+80 (10 min)

> Comms asks for customer-facing wording. Legal asks whether the 72-hour clock started at
> the support ticket (T+0) or at the D013 detection (T+25).

**Ask:** Draft two sentences for customers. Then settle the clock.

*Facilitator notes.* There is no single correct answer and the disagreement is the point.
The defensible position is that awareness begins when the organisation had enough
information to conclude a personal-data breach was likely — which is closer to T+25 than
T+0, but a regulator may read the support ticket as the trigger. What matters is that the
reasoning is documented at the time, not reconstructed later.

---

## Debrief (15 min)

1. When did you know this was data exposure rather than a model error? What told you?
2. Did anyone try to answer "who accessed this" before establishing it was answerable?
3. D005's region field changed the response scope. Would you have caught that without it?
4. Four of this lab's attacks succeed against a fully hardened baseline. Could this
   incident have been *prevented*, or only detected faster?
5. What is the one telemetry field whose absence cost you the most time?

## Expected findings

A run that goes well produces roughly these, and they are deliberately unflattering:

| Finding | Severity | Owner |
|---|---|---|
| End-user identity is not propagated into tool calls, so per-user attribution is impossible | High | Application |
| No corpus-integrity control: documents are ingested without provenance or signing | High | Platform |
| No per-user authorization between agent and tools — argument validation is not authorization | High | Application |
| Breach-awareness trigger for AI incidents is undefined, so the regulatory clock is contestable | Medium | Legal / IR |
| Prompt-injection response has no pre-agreed containment decision tree, so availability vs exposure is argued live | Medium | IR |

## Running it against the lab

```bash
make clean-data
make attack                 # or: console -> Attacks -> Run all
make detect                 # D005 and D013 among those firing
make ir-respond             # generates the evidence packs referenced above
```

The evidence in `incidents/*/evidence/` is real output from a real attack chain. Handing a
participant `attribution_available.json` and letting them discover the single-principal
problem themselves lands considerably harder than being told.
