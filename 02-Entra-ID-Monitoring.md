# Entra ID Monitoring - TryHackMe

**Room**: [Entra ID Monitoring](https://tryhackme.com/room/entraidmonitoring)

**Category**: SOC Monitoring / Cloud Identity

**Tools used**: Splunk SPL

**MITRE ATT&CK mapping**: T1110.001 (Brute Force), T1110.003 (Password Spraying), T1078 (Valid Accounts), T1621 (MFA Request Generation), T1557 (Adversary-in-the-Middle), T1090 (Proxy/Anonymized Infrastructure), T1136 (Create Account), T1098 (Account Manipulation), T1098.005 (Additional Cloud Credentials - MFA Registration), T1528 (OAuth Token Abuse / Cloud Account Access), T1566 (Phishing), T1087 (Account Discovery)


## Scenario

This room follows a single Entra ID identity, from the first failed login attempt all the way to long-term persistence through OAuth consent. Acting as an L2 SOC analyst for the fictional org FineGalo, I worked through six stages of a cloud account takeover using Splunk against Entra ID Sign-in logs, Audit logs, and Identity Protection logs (risk detection + risky user).

## Why This Matters

In on-prem environments attackers go after Active Directory, domain controllers, and Kerberos. In the cloud, the identity provider itself is the target. If an attacker compromises an Entra ID account they can often reach Outlook, Teams, SharePoint, OneDrive, Azure subscriptions, Microsoft 365, and any app using SSO — no malware or network breach required. Microsoft's own guidance is that over 99% of account compromise attacks are preventable with MFA, a reminder that most successful attacks exploit weak identity security rather than sophisticated tooling. (Note: Entra ID is just Microsoft's rebrand of Azure AD — same product, same functionality.) This room walks through the full attacker lifecycle stage by stage: initial access, defenses, credential abuse, privilege escalation, and persistence.


## Investigation Workflow

### 1. Identify initial access — password spraying vs brute force (Sign-in Logs)

Entra ID's Sign-in log fields are the starting point for any authentication investigation: user, result, IP address, country, device, browser, client app (browser/PowerShell/IMAP/etc.), MFA status, Conditional Access outcome, and Microsoft's risk level. The standard triage sequence is: who logged in → was it successful → where did it originate → has this IP appeared before → was MFA completed → did the user do anything suspicious afterward (mailbox rules, downloads, SharePoint access, privilege changes).

**Password spraying** spreads one or a few common passwords across many different accounts specifically to dodge account lockout policies (e.g. trying Winter2026! against alice, bob, john, mary...). Indicators: same source IP, many distinct usernames, few attempts per user, short time window.

**Brute force** (throttled) instead focuses repeated password attempts against one account, often spaced out over time to stay under lockout thresholds. Indicators: one IP, one user, many failures, longer duration.

The SPL distinguishing factor is whether dc(userPrincipalName) is high (spray) or the failures cluster on a single ipAddress + userPrincipalName pair (brute force).

**Password spraying detection:**

index="task-2" sourcetype="azure:aad:signin"
"status.errorCode"!=0
conditionalAccessStatus!=success
| stats dc(userPrincipalName) as targeted_accounts, count as failures by ipAddress
| sort - failures


Result: 94.20.222.248 → 7 accounts targeted, 14 failed attempts. One IP hitting 7 different accounts is the signature of password spraying.

Brute force detection (same filters, but grouped by IP and user so a single heavily-targeted account stands out instead of being buried inside an IP's total):

index="task-2" sourcetype="azure:aad:signin"
"status.errorCode"!=0
conditionalAccessStatus!=success
| stats count as failures, dc(userPrincipalName) as targeted_accounts by ipAddress, userPrincipalName
| sort - failures

Result: 38.165.231.218 → amanda.costa@finegalo.thm, 4 failures against one account only. Compromised user: amanda.costa@finegalo.thm

Follow-up queries once a suspicious IP/user is identified — check for a successful login by that user, and separately check for any successful login from that same suspicious IP, to see whether the attack actually landed:

index="task-2" sourcetype="azure:aad:signin" status.errorCode=0
| where userPrincipalName="<TARGET_USER>"
| stats count by userPrincipalName, ipAddress

index="task-2" sourcetype="azure:aad:signin" status.errorCode=0
| where ipAddress="<SUSPICIOUS_IP>"
| stats count by userPrincipalName

Note on conditionalAccessStatus!=success: some sign-in events log a non-zero errorCode even on eventually-successful logins, because Conditional Access evaluates authentication in stages. Excluding conditionalAccessStatus=success filters out those intermediate artifacts so the failure count reflects genuine failed attempts rather than false positives.


**Detection-rule shorthand**: password spraying = same IP + more than 10 users + within 10 minutes + mostly failures; brute force = one IP/one user with many failures over time.


### 2. Correlate risk signals with policy outcomes (Identity Protection + Conditional Access)

The core mental model here: authentication happens in layers, not a single password check.

Username + password verified → Identity Protection asks "is this sign-in risky, anonymized IP, impossible travel, new device?" → Conditional Access asks "require MFA, block this country, is the device compliant, is risk too high?" → grant / challenge / block.

**Conditional Access (CA)** is Entra ID's policy engine — it evaluates conditions before deciding what to do, rather than just checking a password. Common policies:


* Require MFA
* Block legacy authentication (IMAP/POP3/SMTP AUTH, which often bypass MFA entirely)
* Block suspicious countries
* Require a compliant device
* Risk-based policies driven by Identity Protection scores


A CA policy is only as good as who it's applied to — e.g. "Require MFA → All Users → EXCEPT Service Accounts" means a compromised service account can walk right past MFA. Every sign-in records a CA result per policy: success (applied), failure (blocked the sign-in), notApplied (conditions not met), or reportOnly (would have applied but wasn't enforced).

**Identity Protection** is Microsoft's risk analysis engine — it doesn't block anyone directly, it calculates risk and feeds that into Conditional Access. Two risk types:


**Sign-in risk** — evaluates one authentication attempt (anonymous IP, impossible travel, new device, suspicious ASN)

**User risk** — evaluates the overall likelihood an account is compromised (breached password, multiple risky logins, suspicious mailbox activity)


Risk levels: Low / Medium / High.

Three log sources matter for this stage:

* azure:aad:signin — login attempts, MFA status, CA outcome, sign-in risk
  
* azure:aad:identity_protection:riskdetection — riskEventType, riskLevel, detection reason (e.g. anonymizedIPAddress, impossibleTravel, malwareLinkedIP), triggering activity, source IP
  
* azure:aad:identity_protection:risky_user — user risk, risk state, risk detail; generated whenever a user's overall risk status changes


**Identify risky users:**

index="task-3" sourcetype="azure:aad:identity_protection:risky_user"
| table _time, userPrincipalName, riskLevel, riskState, riskDetail
| sort - _time

Result: risky user allan.senna@finegalo.thm

Risk detection findings: last risky sign-in 2026-03-03 13:51, risk type anonymizedIPAddress (traffic from a VPN, proxy, or Tor exit node). An anonymized IP alone isn't proof of compromise — plenty of legitimate users are behind corporate VPNs or privacy tools. It's a signal to correlate against other evidence, not a verdict on its own.

**Conditional Access investigation** — this query pulls apart the nested appliedConditionalAccessPolicies array to see which specific policy blocked a sign-in:

index="task-3" sourcetype="azure:aad:signin"
conditionalAccessStatus=failure
| spath output=policies path=appliedConditionalAccessPolicies{}
| mvexpand policies
| spath input=policies output=policy_result path=result
| spath input=policies output=policy_name path=displayName
| where policy_result="failure"
| stats values(policy_name) as FailedPolicies by _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus
| eval FailedPolicies=mvjoin(FailedPolicies,", ")
| table _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus, FailedPolicies
| sort - _time


Three SPL functions worth knowing cold here:


* spath — extracts fields out of nested JSON (e.g. pulling displayName/result out of a policy object)
* mvexpand — splits an event containing multiple array values (like several CA policies evaluated on one sign-in) into one row per value, so each can be analyzed individually
* mvjoin — does the reverse, stitching multiple values back into a single readable string for a report

Findings: blocked policy "Block Suspicious Countries", blocked IP 94.20.222.251.

A simple three-question mental model for this stage: What did Microsoft detect (Identity Protection)? What action was taken (Conditional Access)? What actually happened during the sign-in (Sign-in Logs)? That sequence — intelligence → decision → evidence — is how a real analyst pieces together a cloud identity incident instead of treating each log source in isolation.


### 3. Reconstruct the MFA bypass timeline (Sign-in Logs)

Even with a valid username and password, an attacker still needs to satisfy the second factor. Authentication here is two stages: credentials verified → MFA challenge → approve/deny → only on approval is a session token issued. Attackers rarely break MFA cryptographically — they exploit the person or the workflow around it.

**MFA Fatigue (prompt bombing)**: the attacker already has the password and simply repeats the push notification until the victim approves one, accidentally or out of frustration. This is social engineering, not a cryptographic attack. Indicators: multiple MFA prompts, the same user repeatedly targeted, specific error codes (50074 = MFA required, 50076 = additional authentication required, 500121 = MFA challenge not successfully completed), and eventual success (errorCode 0).


index="task-4" sourcetype="azure:aad:signin"
(status.errorCode=50074 OR status.errorCode=50076 OR status.errorCode=500121)
| stats count as mfa_failures, values(status.errorCode) as errorCodes, values(status.failureReason) as failureReasons by userPrincipalName, ipAddress
| sort - mfa_failures

Result: igor.bicalho@finegalo.thm was the most-targeted user, with repeated 500121 failures.

At this point the analyst thought process is: password was probably correct, MFA repeatedly failed — did the attacker eventually succeed? Before calling anything malicious, build a baseline of what "normal" looks like for that user:

index="task-4" sourcetype="azure:aad:signin" status.errorCode=0
| table _time, userPrincipalName, ipAddress, location.countryOrRegion
| sort - _time

Baseline: igor.bicalho's normal sign-in country is DK. Against a run of DK, DK, DK, DK, DK entries, a single BR (Brazil) entry stands out immediately.

Reconstructing the full timeline for just that user (rather than looking at individual events) turns isolated failures into a story:

index="task-4" sourcetype="azure:aad:signin"
| search userPrincipalName="igor.bicalho@finegalo.thm"
| table _time, status.errorCode, ipAddress, location.countryOrRegion
| sort _time

Timeline: 500121 at 13:20 → 500121 at 13:21 → 500121 at 13:23 → success (errorCode 0) at 13:26. Password correct → repeated MFA challenges → user rejects x3 → user approves → successful login.

**Compromised user**: igor.bicalho@finegalo.thm | Normal country: DK | Successful attack: 2026-03-04 13:26

Two other MFA bypass paths worth knowing even though they didn't fire in this scenario:


* **SIM Swapping** — the attacker convinces the victim's mobile carrier to transfer their phone number to a SIM the attacker controls, so SMS-based MFA codes go straight to the attacker. Detection clues: new device, new browser, new country, successful MFA specifically via SMS.
  
* **Adversary-in-the-Middle (AiTM)** — the more dangerous one, because MFA isn't bypassed, it's completed legitimately. The victim logs into a fake Microsoft login page that proxies to the real one; MFA completes as normal; the session token issued afterward is stolen by the attacker's proxy and reused directly. Every individual signal — MFA success, CA success — looks completely legitimate. The only tell is the resulting session suddenly being used from a different IP or country (impossible travel). Detecting AiTM requires correlating sign-in history and geography rather than trusting MFA/CA status at face value.

**Impossible Travel** deserves its own note as a detection pattern that spans several of these techniques: a user logging in from Denmark at 09:00 and Brazil at 09:20 is either using AiTM/a stolen token, or there's a legitimate explanation (VPN, corporate proxy, split tunneling, cloud service IP) that needs to be ruled out before calling it malicious.


### 4. Identify privilege escalation and persistence (Audit Logs)

This is where the investigation shifts from "who got in" (Sign-in Logs) to "what did they do" (Audit Logs). The shorthand: Sign-in Logs tell you who got in; Audit Logs tell you what they did. Every audit investigation should answer three questions: what changed, who changed it, and what was affected — answered respectively by the activityDisplayName, initiatedBy, and targetResources fields.

Backdoor account creation. If the compromised account gets disabled, the attacker loses access — unless they've already created a spare account to fall back on.

index="task-5" sourcetype="azure:aad:audit"
activityDisplayName="Add user"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| eval userCreated='targetResources{}.userPrincipalName'
| table _time, activityDisplayName, initiator, userCreated

coalesce() matters here because an action can be initiated by either a human user or an application (e.g. Microsoft Graph) — it just returns whichever of the two fields is non-null, so you always get a usable initiator value instead of navigating deeply nested JSON by hand.

Result: new backdoor account rafael.maciel@finegalo.thm

**Privilege escalation**. Creating a user isn't enough on its own — the attacker wants privileges. High-value target roles include Global Administrator (full tenant control), Exchange Administrator (mailboxes), User Administrator (can reset passwords), and Application Administrator (OAuth abuse).

index="task-5" sourcetype="azure:aad:audit"
activityDisplayName="Add member to role"
| table _time, activityDisplayName, initiatedBy.user.userPrincipalName, targetResources{}.userPrincipalName, targetResources{}.modifiedProperties{}.newValue
| sort - _time

Result: **Global Administrator assigned** — effectively "Domain Admin" for the whole tenant, letting the attacker reset any password, create other admins, modify Conditional Access, disable security controls, and manage all of M365/Azure. Any time an incident involves this role, it should be treated as critical.

**MFA registration for persistence**. This is one of the cleverer moves: even if the victim resets their password, the attacker keeps access if they've already registered their own MFA method on the account.

index="task-5" sourcetype="azure:aad:audit"
activityDisplayName="User started security info registration"
loggedByService="Authentication Methods"
operationType="Add"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| table _time, activityDisplayName, initiator, initiatedBy.user.ipAddress, additionalDetails{}.value

Result: new MFA registration at 2026-03-04 13:36

Full chain for this stage: password spray → password obtained → MFA fatigue → user approves → successful login → backdoor account created → Global Administrator assigned → new MFA device registered → persistent access.


### 5. Check for OAuth application abuse (Audit Logs)

The last and most durable persistence mechanism: OAuth consent. A common misconception is "reset the password and the attacker is gone" — that's not true if the attacker has convinced a user (or admin) to consent to a malicious OAuth application, because that app gets its own access token, independent of the user's password. In the OAuth flow, the app never sees the password at all: user authenticates → consent screen → user allows → OAuth token issued → app calls Microsoft Graph directly. Once consent is granted, password changes, MFA resets, and account lockouts all fail to remove the app's access — it keeps working until consent is explicitly revoked or the token becomes invalid.

**Delegated permissions** mean the app acts as the signed-in user — it can only do what that user could do (e.g. Mail.Read lets it read only that one user's mailbox). Lower risk, requires a signed-in user, and can be approved by the user themselves or an admin.

**Application permissions** mean the app acts as itself, tenant-wide, with no signed-in user required (e.g. Mail.Read.All lets it read every mailbox in the tenant) — much higher risk, and high-privilege scopes require admin consent specifically.


**High-risk permission scopes to flag during triage:**

| Scope | Why it's dangerous |
|-------|---------------------|
| `Mail.Read.All` | Read every mailbox. |
| `Mail.ReadWrite.All` | Modify every mailbox. |
| `Files.ReadWrite.All` | Access all SharePoint and OneDrive files. |
| `Directory.ReadWrite.All` | Modify Entra ID objects. |
| `RoleManagement.ReadWrite.Directory` | Assign privileged roles. |
| `offline_access` | Grants a refresh token, allowing the app to keep renewing access indefinitely without requiring the user to sign in again. |


index="main" sourcetype="azure:aad:audit"
activityDisplayName="Consent to application"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| eval appName='targetResources{}.displayName'
| eval permissionsGranted='targetResources{}.modifiedProperties{}.newValue'
| table _time, initiator, appName, permissionsGranted
| sort - _time

When an OAuth consent event turns up, the questions to ask are: who granted consent, which application received it, what permissions were granted, and are those permissions excessive for what the app claims to do (e.g. a "Payroll Helper" app requesting Mail.Read.All, Files.ReadWrite.All, and offline_access has no legitimate reason to need mailbox access, SharePoint write access, or long-lived refresh tokens — exactly the kind of mismatch that should trigger deeper investigation). This is where analyst judgment matters as much as the query itself.

Typical attack chain ending in OAuth abuse: phishing → user credentials → MFA completed → user grants OAuth consent → application receives token → password reset → MFA reset → application still has access. Remediation isn't done after resetting a password and MFA — always also check whether any OAuth consent was granted during the compromise window.


# Key Takeaway

The full chain reconstructed across this room: password spray/brute force → valid credentials → Conditional Access evaluation → Identity Protection risk assessment → MFA challenge → MFA bypass (fatigue/AiTM/SIM swap) → successful login → backdoor account creation → Global Administrator assignment → attacker-registered MFA → OAuth consent for long-term access. No single log source proves any of it on its own — Sign-in Logs show authentication, Identity Protection shows risk, Conditional Access shows the enforcement decision, and Audit Logs show what the attacker did with the access. Reconstructing the timeline across all four is what turns isolated alerts into one coherent incident.

## Quick Reference: Log Sources

| Log Source | `sourcetype` | Purpose | Used For |
|------------|--------------|----------|----------|
| Sign-in Logs | `azure:aad:signin` | Authentication events | Login attempts, MFA results, Conditional Access outcomes, IP addresses, and sign-in locations. |
| Audit Logs | `azure:aad:audit` | Administrative activity | User creation, role assignments, MFA registration, OAuth consent, and other directory changes. |
| Risk Detection Logs | `azure:aad:identity_protection:riskdetection` | Identity Protection detections | Impossible travel, anonymous IPs, atypical travel, malware-linked IPs, and other risky sign-ins. |
| Risky User Logs | `azure:aad:identity_protection:risky_user` | User risk state | Accounts identified as potentially compromised and their current risk status. |


### SOC analyst checklist for a suspected Entra ID compromise


 Did the user successfully authenticate?
 
 Was MFA completed or bypassed?
 
 Did the sign-in come from an unusual IP/device/location?
 
 Did any Conditional Access policy trigger?
 
 Did Identity Protection assign a risk score?
 
 Was a new user account created?
 
 Were privileged roles assigned?
 
 Were new MFA methods registered?
 
 Was consent granted to any OAuth application?


A "yes" to any of these means the investigation isn't done yet, even if the initial password has already been reset.


# What I Learned

**The core shift in mindset**: in on-prem environments, attackers go after the network — AD, domain controllers, Kerberos, LDAP. In the cloud, the identity itself is the perimeter. Compromise one Entra ID account and you potentially have Outlook, Teams, SharePoint, OneDrive, Azure, and every SSO-connected app, with no malware and no network foothold needed. Over 99% of these compromises are preventable with MFA — which tells you most of these attacks exploit weak identity hygiene, not sophisticated tooling.

**Stage 1 — getting in**. Password spraying (few passwords, many accounts, evades lockouts) and brute force (many passwords, one account, usually throttled) look similar in logs but need different SPL: dc(userPrincipalName) grouped by IP surfaces spraying; grouping by IP and user surfaces brute force. A subtlety I had to actually sit with: filtering conditionalAccessStatus!=success alongside errorCode!=0 matters because Entra sometimes logs a non-zero error code as an intermediate step even on a login that ultimately succeeds — so without that filter you'd overcount failures.

**Stage 2 — what stood in the way**. Conditional Access and Identity Protection get confused with each other constantly, so the distinction is worth having cold: Identity Protection is the intelligence layer (calculates risk — impossible travel, anonymized IP, new device); Conditional Access is the decision/enforcement layer (allow, challenge, block, based on that risk plus admin-defined policies like "require MFA" or "block legacy auth"). A policy is only as strong as its scope — excluding service accounts from an MFA requirement is a classic gap attackers exploit. An anonymized IP by itself is not proof of compromise — loads of legitimate users are behind VPNs — so it's a correlation input, not a verdict.

**Stage 3 — beating the second factor**. This was the most interesting part to explain in the notes and probably the best interview material. MFA fatigue is social engineering, not a crypto attack: attacker already has the password, just spams push prompts (error codes 50074/50076/500121) until the victim taps approve once, out of habit or annoyance. What made the concept click for me wasn't the definition, it was seeing the actual event sequence: 500121, 500121, 500121, then 0 — laid out in time order that's an unmistakable "attacker wore the user down" pattern, whereas "there were repeated MFA failures" as a standalone fact is much weaker. Building a baseline first (this user normally logs in from DK) is what makes the eventual BR/foreign-country login stand out as anomalous rather than assumed. Two other MFA-bypass techniques worth being able to name: SIM swapping (carrier moves the victim's number to an attacker-controlled SIM, so SMS codes go straight to them) and AiTM (Adversary-in-the-Middle) — the scarier one, because MFA actually succeeds legitimately via a proxy login page, and the attacker just steals the resulting session token. Every individual field looks clean here; only correlating IP/country changes after a "successful" MFA reveals it.

**Stage 4 — after they're in**. This is the pivot point I'd call out as the single most important concept from the whole room: once an account is authenticated, stop looking at Sign-in Logs and start looking at Audit Logs, because that's where objectives show up, not just access. Attackers who assume they might get caught do three things to survive remediation: create a backdoor account (so disabling the original account doesn't matter), escalate privileges — Global Administrator being the crown jewel, equivalent to Domain Admin on-prem — and register their own MFA device (so even a victim-initiated password reset doesn't lock them out, since MFA re-registration isn't tied to the password).

**Stage 5 — the persistence mechanism most people forget**. OAuth consent is the one that actually survives everything — password reset, MFA reset, account lockout — because the malicious app has its own independent access token. The delegated vs. application permission distinction is the crux of it: delegated = app can only do what the signed-in user can do; application = app acts tenant-wide with no user context at all, which is why high-privilege application scopes require admin consent. offline_access is the sleeper scope — it's what lets a token keep renewing itself indefinitely without the user ever re-authenticating, and it's easy to skim past in a permissions list if you're not looking for it specifically.

How I'd summarize this room in one line for an interview: cloud identity incidents are a lifecycle, not a single alert — password attack, defenses, credential/MFA abuse, privilege escalation, and OAuth-based persistence are all stages of one intrusion, and the analyst's job is correlating Sign-in Logs (authentication), Identity Protection (risk), Conditional Access (enforcement), and Audit Logs (administrative action) into a single timeline rather than reacting to each event in isolation.





















