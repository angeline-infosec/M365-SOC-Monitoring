# M365 Monitoring Basics - TryHackMe

**Room**: [M365 Monitoring Basics](https://tryhackme.com/room/m365monitoringbasics)

**Category**: SOC Monitoring / Cloud Identity

**Tools used**: Splunk SPL

**MITRE ATT&CK mapping**: T1078 (Valid Accounts), T1110 (Brute Force), T1098 (Account Manipulation), T1564.008 (Hide Artifacts: Email Hiding Rules)

## Scenario

Acting as an L2 SOC Analyst at a fictional org (FineGalo), I investigated an alert involving multiple failed authentication attempts against a cloud account followed by a successful login. With no endpoint or network telemetry available, the entire investigation relied on Entra ID and Microsoft 365 (M365) log analysis in Splunk.


## Why This Matters

Most orgs running M365 use Entra ID as their identity provider, which means a single compromised identity can grant an attacker legitimate access across Outlook, Teams, and SharePoint- without malware or a network foothold. This room walks through the two log sources that matter most when that happens:


-> Entra ID logs → tell you who authenticated and how

-> M365 Unified Audit Logs → tell you what they did after


## Investigation Workflow

### **1. Identify the compromised account (Entra ID Sign-in logs)**

Filtered sign-in logs for failed authentication attempts using status.errorCode, then pivoted on the source IP to find the subsequent successful login:

                    index=scenario sourcetype="azure:aad:signin" "status.errorCode"!=0
                    | stats count as event_count values(ipAddress) as ip_addresses
                    values(appDisplayName) as applications values(status.errorCode) as errorCodes by userPrincipalName
                    | sort - event_count

* Compromised account: allan.smith@finegalo.thm
  
* Attacker IP geolocated to Belo Horizonte (inconsistent with expected user location, a clear anomaly)
  
* First successful login traced to a specific timestamp immediately following the failed attempts, confirming a brute-force-to-success pattern


### **2. Identify post-compromise account changes (Entra ID Audit logs)**

Once the account was confirmed compromised, audit logs revealed the attacker's persistence actions:


* User started security info registration → attacker added their own MFA method to lock out detection

* Reset password (self-service) → attacker reset the password to maintain control
  

This is a classic account-takeover persistence pattern: register new auth factor → reset credentials.


### **3. Identify attacker actions inside M365 (Unified Audit Log)**

Pivoted into the o365:management: activity sourcetype to see what the attacker did with the access:


* Operated within Exchange (Workload field)
  
* Created a malicious inbox rule (New-InboxRule), a common technique for hiding outbound fraud emails or auto-forwarding
  
* Sent a phishing/BEC-style email with subject "URGENT: Approval for new internal VPN Access", a pretext designed to harvest further credentials or approvals from internal contacts
  
* Filtered specifically on Operation="MailItemsAccessed" and the attacker's source IP to find exactly when the victim's reply was read, then used spath to extract the folder path field (Folders{}.Path) from the nested log structure
  
* Found the victim's reply moved to \Deleted Items - meaning the inbox rule successfully hid the response from the legitimate user


                     index=scenario sourcetype="o365:management:activity" UserId="<compromised-user>"
                     | where Operation="MailItemsAccessed"
                     | spath path=Folders{}.Path output=PathName
                     | table _time, Operation, PathName



## Key Takeaway

The attack chain here is a textbook cloud account takeover: **brute force → successful login → MFA registration for persistence → password reset → mailbox rule for concealment → BEC-style phishing from the compromised inbox**. No single log source tells the full story — correlating Entra ID sign-in logs, Entra ID audit logs, and M365 Unified Audit logs in a timeline was what surfaced the complete picture.



## What I Learned

Most companies don't run their own email servers or login systems anymore; everything's tied to one identity provider (Entra ID, in this case) and Microsoft 365. That's convenient, but it also means if an attacker gets just one person's password, they don't need to hack anything else. One login gets them into email, files, chat, everything.


What this room really taught me is that you can't catch an attack like this by looking at one log and calling it done. I had to follow a trail: first I checked who failed to log in a bunch of times and then succeeded (that's the break-in), then I checked what they changed on the account afterward, and then I checked what they actually did once inside. In this case, a fake "urgent VPN approval" email was sent to someone, with the reply hidden so the real user wouldn't notice it. 


The part that stuck with me most was the inbox rule. It's such a simple trick: just quietly move replies to Deleted Items, but it means the attacker can keep a phishing conversation going for days without the account owner ever seeing it. That's a good reminder that attackers don't always need to be technically advanced; they just need to know where to hide. 


Big picture: this room made the case for why identity logs matter so much in cloud environments. There's no firewall alert for "someone used a stolen password correctly." You only catch it by watching the logs.
























