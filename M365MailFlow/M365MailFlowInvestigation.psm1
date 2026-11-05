#Requires -Version 5.1
<#
.SYNOPSIS
    Engine for the Microsoft 365 mail flow investigation tool.

.DESCRIPTION
    Import this module and call Invoke-M365MailFlowInvestigation, or use the
    command-line wrapper / WinForms GUI in this folder. The module does not
    exit the host, so a GUI can run it and keep the Exchange session alive.

.NOTES
    Version 2.1.0 fixes, relative to the 2.0.0 script:
      - Multiple senders, recipients, message IDs, and (on V2) statuses are queried
        one value at a time. Those cmdlets accept a single string, and splatting
        an array made the trace fail.
      - Header analysis no longer crashes on a From address. The address regex
        had a reversed character range.
      - Non-numeric SCL/BCL stamps no longer abort header analysis.
      - Unrecognized Received time zones (PST, EST, ...) are left unknown instead
        of being reported as UTC. Offsets written as +00:00 are accepted.
      - Get-EXOMailbox is no longer asked for AccountDisabled, which is not a
        valid -Properties value and failed the entire mailbox lookup. Get-Mailbox
        is used when the EXO cmdlet is unavailable.
      - Quarantine and restricted-sender lookups connect to Security & Compliance.
        They are not Exchange Online cmdlets.
      - An existing Exchange session is not disconnected unless this tool opened it
        or -DisconnectWhenDone / Disconnect-M365MailFlowSession -Force is used.
      - Log lines are appended as UTF-8 without a BOM on every line.
      - Subject filters match literal text. Wildcard characters in the subject are
        no longer treated as -like patterns.
      - CSV text fields that start with = + - or @ are neutralized.
      - Generic "Delivery FAILED" no longer hides the enhanced status code.
      - Trace detail windows that collapse to an empty range are corrected.
      - V2 result paging stops if the cursor does not advance.
      - Header-only and extended-report runs still write a report when Exchange
        connectivity fails. -Offline skips the connection entirely.
      - Connector and rule names must match as a whole token so short names do
        not false-positive.
      - Inbox-rule sender matching is exact, not a substring.
      - Message trace "Data" XML is parsed with DTDs disabled.
#>

$script:ScriptVersion = '2.1.2'
$script:SeverityRank  = @{ 'Critical' = 3; 'Warning' = 2; 'Info' = 1 }
$script:LogFile       = $null
$script:RequestTimes  = New-Object 'System.Collections.Generic.Queue[datetime]'
$script:UseV2         = $true
$script:TraceSummaryCommand = 'Get-MessageTraceV2'
$script:TraceDetailCommand  = 'Get-MessageTraceDetailV2'
$script:Connected     = $false
$script:IppsReady     = $false
$script:OpenedExo     = $false
$script:OpenedIpps    = $false
$script:AcceptedDomains = @()
$script:TransportRules  = @()
$script:Connectors      = @()
$script:DerivedTraceId  = $null
$script:BoundParams     = @{}
$script:UiSync          = $null
$script:Cache = @{
    Recipient = @{}; Mailbox = @{}; Dns = @{}; Quarantine = @{}
    Blocked = @{}; InboxRules = @{}; Junk = @{}; Group = @{}
}
$script:Config = @{
    SenderAddress = @(); RecipientAddress = @(); MessageId = @(); Status = @()
    MessageTraceId = $null; MessageTraceIdSpecified = $false
    Subject = $null; SubjectFilterType = 'Contains'
    FromIP = $null; ToIP = $null
    StartDate = (Get-Date).AddDays(-2); EndDate = (Get-Date)
    StartDateSpecified = $false; EndDateSpecified = $false
    MaxResults = 5000; MaxDetailLookups = 250
    ProblemsOnly = $false; SkipDetail = $false
    SkipEnrichment = $false; IncludeMailboxChecks = $false; SkipDnsChecks = $false
    LatencyWarningMinutes = 10
    HeaderFile = $null; ExtendedReportCsv = $null
    SubmitHistoricalSearch = $false; NotifyAddress = @()
    OutputPath = $null; OpenReport = $false; Offline = $false
    UserPrincipalName = $null; AppId = $null; CertificateThumbprint = $null; Organization = $null
    DisconnectWhenDone = $false; UseDeviceCode = $false; DisableWAM = $false
    SearchBackForMessageId = $true
}

$script:AllowedStatus = @('Delivered','Expanded','Failed','FilteredAsSpam','GettingStatus','Pending','Quarantined')

#region Knowledge base
# Format: 'Meaning|Likely cause|Recommended action'
$script:DsnKb = @{
    '4.3.1'   = 'Insufficient system resources on the receiving server.|The remote server is temporarily out of disk, memory or queue capacity.|Transient. Exchange Online retries automatically. If it persists, contact the remote mail administrator.'
    '4.3.2'   = 'Remote system not accepting network messages.|The receiving server is in maintenance, shutting down, or rejecting new connections.|Transient. Wait for retries. If persistent, the remote administrator must check their MTA.'
    '4.4.1'   = 'Connection timed out.|No answer from the destination server on TCP 25 (firewall, wrong MX, server down).|Test-NetConnection <mx-host> -Port 25 from a neutral network; verify MX records and remote firewall.'
    '4.4.2'   = 'Connection dropped.|The connection was closed mid-session (network instability, remote IPS/anti-spam appliance, TLS issue).|Check for TLS inspection or IPS devices in front of the remote server; review remote SMTP logs.'
    '4.4.7'   = 'Message expired in the queue.|Exchange Online could not deliver within the retry window (destination down, DNS failure, persistent TLS/connector problem, greylisting never cleared).|Read the LastError/LED text of the DEFER events (shown in the journey) - that is the real cause. Fix the destination or connector and resend.'
    '4.4.62'  = 'Mail sent to the wrong Office 365 region/forest.|An on-premises or third-party connector is sending to an EXO endpoint that does not host the recipient domain, or the domain is not an accepted domain.|Verify the accepted domain exists in the tenant and that the sending connector smart host is <tenant>.mail.protection.outlook.com.'
    '4.4.316' = 'Connection refused by destination.|The destination host actively refused TCP 25 (service down, firewall, IP block of Microsoft ranges).|Verify the remote SMTP service is listening and allows Microsoft 365 outbound IP ranges.'
    '4.4.317' = 'Destination server does not support required TLS.|A connector or policy requires TLS but the remote server did not offer STARTTLS, or the certificate did not validate.|Review outbound connector TlsSettings/TlsDomain; ask the remote side to enable STARTTLS with a valid public certificate.'
    '4.4.318' = 'Connection closed abruptly by the remote server.|Remote server or network appliance closed the session (TLS failure, size limit, anti-spam).|Review remote SMTP logs for the session; check for TLS inspection devices.'
    '4.7.0'   = 'Temporary authentication/policy failure.|Greylisting, temporary TLS failure, rate limiting or temporary DNS issue at the receiver.|Usually transient. If persistent, read the full remote response text in the DEFER event.'
    '4.7.26'  = 'Remote server requires authenticated mail (temporary).|The receiver (often Gmail/Yahoo) could not validate SPF/DKIM/DMARC for your domain.|Fix SPF and DKIM for the sending domain and publish DMARC.'
    '4.7.650' = 'Server busy - IP reputation throttling (outbound).|The sending IP has a poor reputation with the receiver or is being throttled.|Usually transient. Check message content/volume; if outbound spam, review the sender account.'
    '5.0.350' = 'Generic remote rejection.|The remote system rejected the message with a non-specific code (often remote spam/policy filter, or a forwarding loop).|Read the remote response text in the FAIL event; contact the remote administrator with the response.'
    '5.1.0'   = 'Sender denied / invalid address.|Invalid sender address, or the sender is blocked by the recipient org.|Verify the sender address; check remote block lists.'
    '5.1.1'   = 'Bad destination mailbox address (user unknown).|The recipient address does not exist at the destination (typo, deleted user, stale autocomplete/X500 entry).|Verify the address. For internal recipients check the user exists and has the proxy address; clear Outlook autocomplete cache for stale entries.'
    '5.1.8'   = 'Access denied, bad outbound sender.|The sender account is restricted from sending (outbound spam detected - often a compromised account).|Secure the account (reset password, revoke sessions, review MFA/inbox rules) then remove it from Restricted entities (Get-BlockedSenderAddress / Remove-BlockedSenderAddress).'
    '5.1.10'  = 'Recipient not found.|No recipient with that SMTP address exists in the destination directory (Directory Based Edge Blocking).|Check the recipient exists and has that proxy address. For hybrid, verify directory sync.'
    '5.1.90'  = 'Sender reached its daily recipient/message limit.|The mailbox exceeded the recipient rate limit or the outbound spam policy limits.|Wait for the limit to reset or adjust outbound spam policy limits; use a bulk mailing service for high volumes.'
    '5.2.2'   = 'Recipient mailbox full / quota exceeded.|The recipient mailbox reached ProhibitSendReceiveQuota, or the sender exceeded a submission quota.|Free up space / archive / increase quota. See the mailbox quota check in Enrichment.'
    '5.2.3'   = 'Message too large.|The message exceeds the max receive/send size for the recipient, sender, connector or organization.|Check MaxSendSize/MaxReceiveSize on the mailboxes and organization transport config; use links instead of attachments.'
    '5.2.121' = 'Recipient per-hour message receive limit from this sender exceeded.|Too many messages from one sender to one recipient within an hour (often an app loop).|Find the looping application/rule; wait for the limit to reset.'
    '5.2.122' = 'Recipient per-hour message receive limit from all senders exceeded.|Recipient is receiving an extreme volume (mail storm / loop).|Identify the source of the volume; check for forwarding loops.'
    '5.3.190' = 'Journaling on-premises messages to Microsoft 365 is not supported.|A journal rule targets an Exchange Online mailbox for on-premises journaled mail.|Point the journal rule to a supported archiving destination.'
    '5.4.1'   = 'Recipient address rejected: Access denied (relay denied / DBEB).|The recipient domain is not hosted for this address, Directory Based Edge Blocking, or relay not allowed.|Verify the accepted domain type (Authoritative vs InternalRelay) and that the recipient exists. For relay, use a proper inbound connector.'
    '5.4.4'   = 'Unable to route - domain does not exist or has no MX/A.|DNS lookup for the destination domain returned nothing usable.|Check the recipient domain spelling; verify MX/A records with Resolve-DnsName.'
    '5.4.6'   = 'Routing loop detected.|Forwarding/connectors/MX send the message back and forth (e.g. hybrid misconfiguration, forwarding loop).|Review forwarding settings, connectors and MX records for circular routing.'
    '5.4.8'   = 'MX lookup points back to the local system / loop.|The MX or connector smart host for the domain points back to Exchange Online without an accepted domain match.|Review accepted domain type and outbound connector smart hosts.'
    '5.4.14'  = 'Hop count exceeded - possible mail loop.|The message passed through too many servers.|Look for forwarding or connector loops between systems.'
    '5.4.300' = 'Message expired.|Delivery retried until the expiration timeout (destination unreachable or persistently deferring).|Read the DEFER events in the journey for the actual last error.'
    '5.4.312' = 'DNS query failed.|The DNS lookup for the destination failed (SERVFAIL / broken DNSSEC / timeout).|Check the recipient domain DNS health (Resolve-DnsName, DNSSEC validation).'
    '5.4.316' = 'Message expired, connection refused.|The destination refused connections for the entire retry period.|Verify the remote SMTP service and firewall.'
    '5.6.11'  = 'Invalid characters in message (bare line feeds).|The sending application sent bare LF characters which are not allowed.|Fix the sending application to use CRLF, or send through a connector that normalizes content.'
    '5.7.1'   = 'Delivery not authorized / message refused.|Sender not allowed by recipient/group restrictions, mail flow rule reject, relay denied, or remote spam policy.|Check group restrictions (AcceptMessagesOnlyFrom, RequireSenderAuthenticationEnabled), mail flow rules, and the remote response text.'
    '5.7.3'   = 'Cannot achieve required authentication / TLS.|A connector requires TLS or certificate authentication which failed.|Verify connector TlsSettings/certificate names on both sides.'
    '5.7.12'  = 'Sender was not authenticated by organization.|The recipient group/mailbox only accepts authenticated (internal) senders.|Set RequireSenderAuthenticationEnabled to $false on the group if external senders are allowed.'
    '5.7.23'  = 'Rejected due to SPF failure.|The sending IP is not authorized in the SPF record of the sender domain.|Add the sending service/IP to the SPF record of the sender domain.'
    '5.7.25'  = 'Reverse DNS (PTR) missing for sending IPv6 address.|The sending IP has no PTR record.|Add a PTR record for the sending IP, or send over IPv4.'
    '5.7.26'  = 'Unauthenticated email rejected (DMARC / authentication policy).|The receiver (often Gmail/Yahoo/Outlook.com) requires SPF/DKIM aligned with the From domain.|Enable DKIM signing (Get-DkimSigningConfig), fix SPF, publish DMARC.'
    '5.7.57'  = 'Client was not authenticated to send anonymous mail during MAIL FROM.|An app/device tried to send via smtp.office365.com without SMTP AUTH or with bad credentials.|Use SMTP AUTH with valid credentials (and enable SMTP AUTH for the mailbox) or use direct send / a connector.'
    '5.7.64'  = 'TenantAttribution - Relay access denied.|Inbound connector (IP or certificate based) did not match the sending server.|Verify the inbound connector SenderIPAddresses or TlsSenderCertificateName matches the on-prem/relay server.'
    '5.7.124' = 'Sender not in the allowed senders list of the group.|Group delivery is restricted (AcceptMessagesOnlyFrom*).|Add the sender to the group delivery management list.'
    '5.7.133' = 'Sender not authenticated for group.|The group only accepts mail from internal (authenticated) senders.|Allow external senders on the group (RequireSenderAuthenticationEnabled $false).'
    '5.7.134' = 'Sender not authenticated for mailbox.|The mailbox only accepts authenticated senders.|Set RequireSenderAuthenticationEnabled $false on the mailbox if external senders are allowed.'
    '5.7.135' = 'Sender not authenticated for public folder.|The mail-enabled public folder only accepts authenticated senders.|Adjust the public folder delivery restrictions.'
    '5.7.136' = 'Sender not authenticated for mail user.|The mail user only accepts authenticated senders.|Adjust the mail user delivery restrictions.'
    '5.7.501' = 'Access denied, spam abuse detected.|The sending account was detected sending spam.|Secure the account, review outbound spam alerts.'
    '5.7.509' = 'Access denied, sending domain does not pass DMARC and has p=reject.|The From domain DMARC policy is reject and SPF/DKIM did not align.|Fix SPF/DKIM alignment for the From domain at the actual sending service.'
    '5.7.510' = 'Access denied, recipient does not accept email over IPv4 / policy.|Receiver-side policy rejection.|Read the full response text and contact the remote administrator.'
    '5.7.511' = 'Access denied, banned sender.|The sending IP is on the Microsoft banned list.|Request delisting via https://sender.office.com.'
    '5.7.520' = 'Access denied, your organization does not allow external forwarding.|Automatic external forwarding is blocked by the outbound spam policy (AutoForwardingMode).|Allow forwarding for this user via a custom outbound spam policy, or remove the forwarding/inbox rule.'
    '5.7.705' = 'Access denied, tenant has exceeded threshold.|Most mail from the tenant was spam; the whole tenant is blocked from sending.|Contact Microsoft support; find and secure compromised accounts.'
    '5.7.708' = 'Access denied, traffic not accepted from this IP.|Outbound mail classified as high risk / low reputation (often new tenants or compromised accounts).|Review sending accounts; for new tenants build reputation gradually; contact support if persistent.'
    '5.7.750' = 'Unregistered domain email restriction.|Sending from a domain not added/verified in the tenant.|Add and verify the domain under accepted domains, or send from a verified domain.'
}

$script:SfvKb = @{
    'NSPM' = 'Not spam - message passed spam filtering.'
    'SPM'  = 'Marked as spam by spam filtering.'
    'SKS'  = 'Marked as spam BEFORE spam filtering (e.g. mail flow rule).'
    'SKA'  = 'Filtering skipped - sender is in an allowed sender/domain list of an anti-spam policy.'
    'SKB'  = 'Marked as spam - sender matched a blocked sender/domain list in an anti-spam policy.'
    'SKI'  = 'Filtering skipped - intra-organization message.'
    'SKN'  = 'Marked as non-spam BEFORE filtering (e.g. mail flow rule set SCL -1).'
    'SKQ'  = 'Released from quarantine.'
    'SKU'  = 'Filtering skipped - Tenant Allow/Block List allow or similar.'
    'SFE'  = 'Filtering skipped - sender in the recipient Safe Senders list.'
    'BLK'  = 'Blocked - sender is in the recipient Blocked Senders list.'
}

$script:CatKb = @{
    'BULK'  = 'Bulk mail'
    'DIMP'  = 'Domain impersonation (Defender anti-phishing)'
    'GIMP'  = 'Mailbox intelligence impersonation'
    'HPHSH' = 'High confidence phishing'
    'HPHISH'= 'High confidence phishing'
    'HSPM'  = 'High confidence spam'
    'MALW'  = 'Malware'
    'PHSH'  = 'Phishing'
    'SPM'   = 'Spam'
    'SPOOF' = 'Spoofing (failed composite authentication)'
    'UIMP'  = 'User impersonation (Defender anti-phishing)'
    'AMP'   = 'Anti-malware policy'
    'SAP'   = 'Safe Attachments policy'
    'FTBP'  = 'Common attachments (file type) filter'
    'OSPM'  = 'Outbound spam'
    'INTOS' = 'Intra-organization phishing'
    'NONE'  = 'No threat category'
}

$script:EventKb = @(
    @{ Pattern = '^Receive';                         Sev = 'Info';     Text = 'Message received by the service from the previous hop (see FromIP / client).' }
    @{ Pattern = '^Submit';                          Sev = 'Info';     Text = 'Message submitted from a mailbox (Outlook/OWA/mobile/API) into transport.' }
    @{ Pattern = 'Send external';                    Sev = 'Info';     Text = 'Handed off to an external server (remote MX or connector smart host). Remote accepted it.' }
    @{ Pattern = '^Send';                            Sev = 'Info';     Text = 'Sent to the next hop (another server, connector or on-premises).' }
    @{ Pattern = '^Deliver';                         Sev = 'Info';     Text = 'Delivered to the recipient mailbox.' }
    @{ Pattern = '^Fail';                            Sev = 'Critical'; Text = 'Delivery failed - an NDR is normally generated to the sender.' }
    @{ Pattern = '^Defer';                           Sev = 'Warning';  Text = 'Delivery postponed - the service will retry.' }
    @{ Pattern = '^Expand';                          Sev = 'Info';     Text = 'Distribution group expanded into its members.' }
    @{ Pattern = '^Transfer|Bifurcat';               Sev = 'Info';     Text = 'Recipients moved to a forked copy (content conversion, recipient limits, or agent processing).' }
    @{ Pattern = '^Resolve';                         Sev = 'Info';     Text = 'Recipient address resolved to a different (primary) address.' }
    @{ Pattern = '^Redirect';                        Sev = 'Warning';  Text = 'Message redirected to another recipient (mail flow rule or forwarding).' }
    @{ Pattern = 'Spam';                             Sev = 'Warning';  Text = 'Anti-spam processing / verdict event.' }
    @{ Pattern = 'Malware';                          Sev = 'Critical'; Text = 'Anti-malware detection.' }
    @{ Pattern = 'Transport rule|Mail flow rule';    Sev = 'Info';     Text = 'A mail flow (transport) rule matched the message.' }
    @{ Pattern = 'DLP';                              Sev = 'Warning';  Text = 'Data Loss Prevention policy matched.' }
    @{ Pattern = '^Drop';                            Sev = 'Critical'; Text = 'Message dropped silently (no NDR) - typically malware, rule action or policy.' }
    @{ Pattern = 'Quarantin';                        Sev = 'Warning';  Text = 'Message placed in quarantine.' }
    @{ Pattern = 'Journal';                          Sev = 'Info';     Text = 'Journal report generated.' }
    @{ Pattern = 'Moderat|Approval';                 Sev = 'Warning';  Text = 'Message held for moderation / approval.' }
    @{ Pattern = 'Poison';                           Sev = 'Critical'; Text = 'Message moved to the poison queue (caused repeated transport crashes).' }
    @{ Pattern = 'Duplicate';                        Sev = 'Info';     Text = 'Duplicate delivery suppressed (message already delivered).' }
    @{ Pattern = 'Safe Attach|Detonat|Dynamic Deliv';Sev = 'Warning';  Text = 'Defender Safe Attachments scanning / detonation.' }
    @{ Pattern = 'ZAP|Zero-hour';                    Sev = 'Warning';  Text = 'Zero-hour auto purge moved the message after delivery.' }
    @{ Pattern = 'Bad ?mail';                        Sev = 'Critical'; Text = 'Message could not be processed (badmail).' }
)

$script:TextPatterns = @(
    @{ Category = 'TLS';          Sev = 'Warning';  Pattern = 'STARTTLS|TLS negotiation|TLS handshake|tls-required|certificate|TlsDomain|SChannel|cipher';
       Finding = 'TLS / certificate problem detected in a delivery attempt.';
       Fix = 'Verify the remote server offers STARTTLS with TLS 1.2+ and a valid public certificate. If a connector is involved, check TlsSettings / TlsDomain / TlsCertificateName on it.' }
    @{ Category = 'DNS';          Sev = 'Warning';  Pattern = 'DNS|NXDOMAIN|no such domain|MX record|SERVFAIL|DnsQueryFailed|DnsNonExistentDomain';
       Finding = 'DNS resolution problem for the destination.';
       Fix = 'Check MX/A records of the destination domain with Resolve-DnsName and validate DNSSEC. See the DNS section of Enrichment.' }
    @{ Category = 'Connectivity'; Sev = 'Warning';  Pattern = 'timed out|timeout|SocketError|connection refused|actively refused|unreachable|ConnectionReset|Connection dropped';
       Finding = 'Network connectivity problem to the next hop.';
       Fix = 'Verify the destination host listens on TCP 25 and permits Microsoft 365 outbound IP ranges; check firewalls / IPS.' }
    @{ Category = 'Authentication'; Sev = 'Warning'; Pattern = '\bSPF\b|DKIM|DMARC|compauth|spoof|unauthenticated';
       Finding = 'Email authentication (SPF/DKIM/DMARC/composite auth) is involved.';
       Fix = 'Validate SPF includes the actual sending service, enable DKIM signing, and confirm DMARC alignment of the From domain.' }
    @{ Category = 'Reputation';   Sev = 'Warning';  Pattern = 'blocklist|blacklist|banned|reputation|\bRBL\b|spamhaus|barracuda|spamcop|listed|HighRiskDeliveryPool|high risk delivery|\bHRDP\b';
       Finding = 'IP / sender reputation or block list involvement.';
       Fix = 'Check the sending IP on public block lists; if relayed via Microsoft high risk pool, review the sender for compromise / spam-like content.' }
    @{ Category = 'Quota';        Sev = 'Warning';  Pattern = 'quota|mailbox full|storage limit|MailboxFull|exceeded the size';
       Finding = 'Mailbox / storage quota problem.';
       Fix = 'Free up space, enable archive, or raise the mailbox quota.' }
    @{ Category = 'Loop';         Sev = 'Warning';  Pattern = 'loop|hop count';
       Finding = 'Possible mail loop.';
       Fix = 'Review forwarding, inbox rules, connectors and MX records for circular routing.' }
    @{ Category = 'Forwarding';   Sev = 'Warning';  Pattern = 'forward|AutoForward';
       Finding = 'Forwarding is involved in this journey.';
       Fix = 'Check mailbox forwarding (ForwardingSmtpAddress), inbox rules, and the outbound spam policy AutoForwardingMode.' }
    @{ Category = 'Size';         Sev = 'Warning';  Pattern = 'too large|size limit|MessageTooLarge|exceeds.*size';
       Finding = 'Message size limit hit.';
       Fix = 'Compare the message size with MaxSendSize/MaxReceiveSize of sender, recipient and organization.' }
    @{ Category = 'Relay';        Sev = 'Warning';  Pattern = 'relay|TenantAttribution|not permitted to relay';
       Finding = 'Relay was denied.';
       Fix = 'Configure an inbound connector matching the sending server IP/certificate, or use SMTP AUTH.' }
    @{ Category = 'Moderation';   Sev = 'Warning';  Pattern = 'moderat|approval';
       Finding = 'Message moderation / approval involved.';
       Fix = 'Check ModerationEnabled / ModeratedBy on the group and whether the moderator approved or rejected.' }
    @{ Category = 'Throttling';   Sev = 'Warning';  Pattern = 'throttl|rate limit|too many|try again later|server busy|greylist|graylist';
       Finding = 'Throttling / rate limiting / greylisting by a receiver.';
       Fix = 'Usually transient. Spread sending volume; for greylisting, confirm retries eventually succeed.' }
    @{ Category = 'Threat';       Sev = 'Critical'; Pattern = 'malware|virus|phish|detonat|Safe Attachments|ZAP|zero-hour';
       Finding = 'Threat protection (malware / phish / Safe Attachments / ZAP) acted on the message.';
       Fix = 'Review in Defender portal > Explorer (or Quarantine). Submit to Microsoft if it is a false positive.' }
    @{ Category = 'Connector';    Sev = 'Info';     Pattern = 'connector|smart ?host|SmartHost';
       Finding = 'A connector / smart host was used for routing.';
       Fix = 'Validate connector scope (RecipientDomains / SenderDomains), smart hosts and TLS settings. See Connectors in Enrichment.' }
)

$script:AuthReasonKb = @{
    '000' = 'Explicit authentication failure - DMARC reject/quarantine policy applied.'
    '001' = 'Implicit authentication failure - no or failed SPF/DKIM/DMARC (spoof intelligence).'
    '002' = 'Organization has a policy that explicitly prohibits this sender/domain pair.'
    '010' = 'DMARC policy reject/quarantine; message was not delivered inbound as a result.'
    '1'   = 'Pass (1xx) - explicit or implicit authentication passed.'
    '2'   = 'Soft pass (2xx).'
    '3'   = 'Not checked (3xx).'
    '4'   = 'Authentication bypassed (4xx) - e.g. intra-org or allow entry.'
    '6'   = 'Implicit fail (6xx).'
    '7'   = 'Pass (7xx) - implicit, sender passed via other signals.'
    '9'   = 'Bypassed (9xx).'
}
#endregion

#region Public configuration bridge
function Get-M365MailFlowVersion {
    $script:ScriptVersion
}

function Set-M365MailFlowUiBridge {
    param($Sync)
    $script:UiSync = $Sync
}

function Set-M365MailFlowConfig {
    <#
        Updates engine settings used by the analysis functions. Invoke-M365MailFlowInvestigation
        replaces these from its own parameters. Tests and the GUI bridge use this too.
    #>
    param([hashtable]$Values)
    if (-not $Values) { return }
    foreach ($k in @($Values.Keys)) {
        if ($k -eq 'AcceptedDomains') {
            $script:AcceptedDomains = @($Values[$k] | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $_ })
        } elseif ($k -eq 'UiSync') {
            $script:UiSync = $Values[$k]
        } elseif ($k -eq 'LogFile') {
            $script:LogFile = $Values[$k]
        } elseif ($k -eq 'TransportRules') {
            $script:TransportRules = @($Values[$k])
        } elseif ($k -eq 'Connectors') {
            $script:Connectors = @($Values[$k])
        } else {
            $script:Config[$k] = $Values[$k]
        }
    }
}
#endregion

#region Helpers
function Publish-UiEvent {
    param(
        [string]$Type = 'Log',
        [string]$Message = '',
        [string]$Level = 'INFO',
        [int]$Percent = -1,
        [string]$Activity = ''
    )
    $sync = $script:UiSync
    if (-not $sync -or -not $sync.Queue) { return }
    if ($Message -and $Message.Length -gt 4000) { $Message = $Message.Substring(0, 4000) + '...' }
    $entry = [pscustomobject]@{
        Type = $Type; Message = $Message; Level = $Level; Percent = $Percent
        Activity = $Activity; Time = (Get-Date)
    }
    try { $sync.Queue.Enqueue($entry) } catch { }
}

function Write-Log {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK', 'DEBUG')][string]$Level = 'INFO'
    )
    $line = '[{0}] [{1,-5}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $color = switch ($Level) { 'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'OK' { 'Green' } 'DEBUG' { 'DarkGray' } default { 'Gray' } }
    $show = ($Level -ne 'DEBUG' -or $VerbosePreference -ne 'SilentlyContinue')
    if ($show) {
        try { Write-Host $line -ForegroundColor $color } catch { }
    }
    if ($script:LogFile) {
        $utf8 = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::AppendAllText($script:LogFile, ($line + [Environment]::NewLine), $utf8)
    }
    if ($show -or $Level -eq 'DEBUG') {
        Publish-UiEvent -Type 'Log' -Message $line -Level $Level
    }
}

function Write-InvestigationProgress {
    param([string]$Activity, [string]$Status, [int]$Percent = -1)
    $pct = $Percent
    if ($pct -lt 0) { $pct = 0 }
    if ($pct -gt 100) { $pct = 100 }
    try { Write-Progress -Activity $Activity -Status $Status -PercentComplete $pct } catch { }
    Publish-UiEvent -Type 'Progress' -Activity $Activity -Message $Status -Percent $pct
}

function Test-InvestigationCancel {
    if ($script:UiSync -and $script:UiSync.Cancel) {
        throw (New-Object System.OperationCanceledException 'Investigation cancelled.')
    }
}

function Test-IsCancelError {
    param($ErrorRecord)
    if ($script:UiSync -and $script:UiSync.Cancel) { return $true }
    $ex = $null
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ex = $ErrorRecord.Exception }
    elseif ($ErrorRecord -is [System.Exception]) { $ex = $ErrorRecord }
    while ($ex) {
        if ($ex -is [System.OperationCanceledException]) { return $true }
        if ($ex -is [System.Management.Automation.PipelineStoppedException]) { return $true }
        $ex = $ex.InnerException
    }
    return $false
}

function Start-SleepInterruptible {
    param([int]$Seconds)
    $left = $Seconds
    while ($left -gt 0) {
        Test-InvestigationCancel
        $step = [math]::Min(2, $left)
        Start-Sleep -Seconds $step
        $left -= $step
    }
}

function Get-PropValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-UtcDate {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    try {
        $d = [datetime]$Value
        if ($d.Kind -eq [System.DateTimeKind]::Local) { return $d.ToUniversalTime() }
        if ($d.Kind -eq [System.DateTimeKind]::Utc) { return $d }
        # Exchange Online V2 returns UTC with Kind=Unspecified.
        return [datetime]::SpecifyKind($d, [System.DateTimeKind]::Utc)
    } catch { return $null }
}

function Format-Duration {
    param([double]$Seconds)
    if ($Seconds -lt 0) { $Seconds = 0 }
    $ts = [timespan]::FromSeconds($Seconds)
    if ($ts.TotalDays -ge 1) { return '{0}d {1:00}h {2:00}m' -f [int][math]::Floor($ts.TotalDays), $ts.Hours, $ts.Minutes }
    if ($ts.TotalHours -ge 1) { return '{0}h {1:00}m {2:00}s' -f [int][math]::Floor($ts.TotalHours), $ts.Minutes, $ts.Seconds }
    if ($ts.TotalMinutes -ge 1) { return '{0}m {1:00}s' -f [int][math]::Floor($ts.TotalMinutes), $ts.Seconds }
    return '{0}s' -f [int]$ts.TotalSeconds
}

function Get-DomainFromAddress {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $null }
    $m = [regex]::Match($Address, '(?i)([A-Z0-9._%+\-]+)@([A-Z0-9.\-]+\.[A-Z]{2,})')
    if ($m.Success) { return $m.Groups[2].Value.Trim().TrimEnd('>').ToLowerInvariant() }
    if ($Address -notmatch '@') { return $null }
    return ($Address.Split('@')[-1]).Trim().TrimEnd('>').ToLowerInvariant()
}

function Test-InternalDomain {
    param([string]$Domain)
    if (-not $Domain) { return $false }
    foreach ($ad in $script:AcceptedDomains) {
        if (-not $ad) { continue }
        if ($Domain -eq $ad) { return $true }
        if ($Domain.EndsWith('.' + $ad)) { return $true }
    }
    return $false
}

function ConvertTo-HtmlSafe {
    param($Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function ConvertTo-CsvSafe {
    param($Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    if ($s -match '^[\s]*[=+\-@\t\r]') { return "'" + $s }
    return $s
}

function ConvertTo-IntSafe {
    param($Value)
    $n = 0
    if ([int]::TryParse(([string]$Value).Trim(), [ref]$n)) { return $n }
    return $null
}

function Get-LatencyThresholdSeconds {
    $mins = 10
    if ($script:Config -and $null -ne $script:Config.LatencyWarningMinutes) {
        $parsed = ConvertTo-IntSafe $script:Config.LatencyWarningMinutes
        if ($null -ne $parsed -and $parsed -ge 0) { $mins = $parsed }
    }
    return ($mins * 60)
}

function Wait-ThrottleSlot {
    param([int]$Limit = 90, [int]$WindowSeconds = 300)
    while ($true) {
        Test-InvestigationCancel
        $now = Get-Date
        while ($script:RequestTimes.Count -gt 0 -and ($now - $script:RequestTimes.Peek()).TotalSeconds -ge $WindowSeconds) {
            [void]$script:RequestTimes.Dequeue()
        }
        if ($script:RequestTimes.Count -lt $Limit) { break }
        $wait = [int][math]::Ceiling($WindowSeconds - ($now - $script:RequestTimes.Peek()).TotalSeconds) + 2
        if ($wait -lt 1) { $wait = 1 }
        if ($wait -gt $WindowSeconds) { $wait = $WindowSeconds }
        Write-Log "Self-throttling to stay under the Exchange Online limit ($Limit requests / $WindowSeconds s). Waiting $wait s..." 'WARN'
        Start-SleepInterruptible -Seconds $wait
    }
    $script:RequestTimes.Enqueue((Get-Date))
}

function Invoke-ExoCommand {
    <#
        Runs an EXO cmdlet with throttle awareness and exponential back-off retry
        on transient errors. Unknown parameters are removed and the call is retried once.
    #>
    param(
        [Parameter(Mandatory)][string]$Command,
        [hashtable]$Parameters = @{},
        [int]$MaxAttempts = 5,
        [switch]$CountsAgainstTraceThrottle
    )
    $attempt = 0
    $p = @{}
    foreach ($k in $Parameters.Keys) { $p[$k] = $Parameters[$k] }
    $p['ErrorAction'] = 'Stop'
    $removed = @{}
    while ($true) {
        $attempt++
        if ($CountsAgainstTraceThrottle) { Wait-ThrottleSlot }
        try {
            $list = New-Object 'System.Collections.Generic.List[psobject]'
            $output = & $Command @p
            foreach ($item in @($output)) {
                if ($null -ne $item) { $list.Add($item) }
            }
            return ,$list.ToArray()
        } catch {
            if (Test-IsCancelError $_) { throw }
            $msg = $_.Exception.Message
            $unknown = [regex]::Match($msg, "parameter name '([^']+)'")
            if ($unknown.Success) {
                $name = $unknown.Groups[1].Value
                if ($p.ContainsKey($name) -and -not $removed.ContainsKey($name)) {
                    $removed[$name] = $true
                    [void]$p.Remove($name)
                    Write-Log "$Command does not support -$name on this module. Retrying without it." 'WARN'
                    $attempt--
                    continue
                }
            }
            $transient = $msg -match 'throttl|too many requests|429|timed out|timeout|temporarily|503|502|504|server busy|connection was closed|An error occurred while sending the request|Unable to connect|ServiceUnavailable|backend'
            if ($transient -and $attempt -lt $MaxAttempts) {
                $delay = [int][math]::Min(180, [math]::Pow(2, $attempt) * 5)
                Write-Log "$Command transient error (attempt $attempt/$MaxAttempts): $msg. Retrying in $delay s." 'WARN'
                Start-SleepInterruptible -Seconds $delay
                continue
            }
            throw
        }
    }
}

function Get-DateWindows {
    param([datetime]$Start, [datetime]$End, [int]$MaxHours = 239)
    $windows = New-Object 'System.Collections.Generic.List[psobject]'
    if ($End -le $Start) { return ,@() }
    $cursorEnd = $End
    $guard = 0
    while ($cursorEnd -gt $Start -and $guard -lt 1000) {
        $guard++
        $wStart = $cursorEnd.AddHours(-$MaxHours)
        if ($wStart -lt $Start) { $wStart = $Start }
        $windows.Add([pscustomobject]@{ Start = $wStart; End = $cursorEnd })
        if ($wStart -le $Start) { break }
        $cursorEnd = $wStart
    }
    return ,$windows.ToArray()
}

function Get-NormalizedTokenList {
    param($Values, [switch]$Lower)
    $list = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    foreach ($v in @($Values)) {
        if ($null -eq $v) { continue }
        foreach ($part in ([string]$v -split '[;\r\n]+')) {
            $t = $part.Trim()
            if (-not $t) { continue }
            $key = $t.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            if ($Lower) { $list.Add($key) } else { $list.Add($t) }
        }
    }
    return ,$list.ToArray()
}

function Get-NormalizedAddressList {
    param($Values)
    $list = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    $chunks = New-Object 'System.Collections.Generic.List[string]'
    foreach ($v in @($Values)) {
        if ($null -eq $v) { continue }
        foreach ($part in ([string]$v -split '[;\r\n]+')) {
            if ($part.Trim()) { $chunks.Add($part.Trim()) }
        }
    }
    $blob = ($chunks -join "`n")
    $found = @([regex]::Matches($blob, '(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}'))
    if ($found.Count -gt 0) {
        foreach ($m in $found) {
            $one = $m.Value
            $key = $one.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $list.Add($one)
        }
        return ,$list.ToArray()
    }
    foreach ($chunk in $chunks) {
        $key = $chunk.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $list.Add($chunk)
    }
    return ,$list.ToArray()
}

function Expand-MessageIdText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    # RFC 5322 folding, and a hard line break inside <id@domain> from a wrapped paste.
    $flat = [regex]::Replace($Text, '\r?\n[ \t]+', '')
    return [regex]::Replace($flat, '(?<=<[^>\r\n]{0,500})\r?\n(?=[^<>\r\n]{0,300}>)', '')
}

function ConvertTo-NormalizedMessageId {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $t = $Value.Trim().Trim('"').Trim("'")
    $t = $t -replace '^(?i)message-?id\s*:\s*', ''
    $t = ($t -replace '\s', '')
    if ($t -match '^<?([^<>@\s]+@[^<>@\s]+)>?$') { return '<' + $matches[1] + '>' }
    return $null
}

function Get-NormalizedMessageIdList {
    param($Values)
    $list = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    foreach ($v in @($Values)) {
        if ($null -eq $v) { continue }
        $text = Expand-MessageIdText ([string]$v)
        if (-not $text) { continue }
        $candidates = New-Object 'System.Collections.Generic.List[string]'
        $headerHits = [regex]::Matches($text, '(?im)^\s*Message-ID\s*:\s*(.+)$')
        if ($headerHits.Count -gt 0) {
            foreach ($h in $headerHits) { $candidates.Add($h.Groups[1].Value) }
        } else {
            $brackets = [regex]::Matches($text, '<\s*([^<>@\s]+@[^<>@\s]+)\s*>')
            foreach ($b in $brackets) { $candidates.Add($b.Groups[1].Value) }
            if ($candidates.Count -eq 0) {
                foreach ($line in ($text -split '\r?\n')) {
                    $bare = ConvertTo-NormalizedMessageId $line
                    if ($bare) { $candidates.Add($bare) }
                }
            }
        }
        foreach ($candidate in $candidates) {
            $id = ConvertTo-NormalizedMessageId $candidate
            if (-not $id) { continue }
            $key = ConvertTo-ComparableMessageId $id
            if (-not $key -or $seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $list.Add($id)
        }
    }
    return ,$list.ToArray()
}

function Get-MessageIdQueryForms {
    param([string]$MessageId)
    $forms = New-Object 'System.Collections.Generic.List[string]'
    if ($MessageId) { $forms.Add($MessageId) }
    $bare = ConvertTo-ComparableMessageId $MessageId
    if ($bare -and ($forms -notcontains $bare)) { $forms.Add($bare) }
    return ,$forms.ToArray()
}

function Get-MessageLocatorFromText {
    param([string]$Text)
    $ids = Get-NormalizedMessageIdList $Text
    $trace = $null
    $flat = Expand-MessageIdText ([string]$Text)
    $m = [regex]::Match($flat, '(?i)Network-Message-Id\s*:\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})')
    if ($m.Success) {
        $g = [guid]::Empty
        if ([guid]::TryParse($m.Groups[1].Value, [ref]$g)) { $trace = $g }
    }
    if (-not $trace -and $ids.Count -eq 0) {
        $g = [guid]::Empty
        if ([guid]::TryParse(($flat -replace '\s', ''), [ref]$g)) { $trace = $g }
    }
    $result = New-Object psobject
    $result | Add-Member -NotePropertyName MessageIds -NotePropertyValue $ids
    $result | Add-Member -NotePropertyName MessageTraceId -NotePropertyValue $trace
    return $result
}

function Get-SearchBackWindows {
    param(
        [datetime]$RequestedStart,
        [datetime]$RequestedEnd,
        [datetime]$Now,
        [datetime]$Oldest
    )
    $windows = New-Object 'System.Collections.Generic.List[psobject]'
    $cursor = $RequestedStart
    while ($cursor -gt $Oldest.AddMinutes(1)) {
        $wEnd = $cursor
        $wStart = $wEnd.AddHours(-239)
        if ($wStart -lt $Oldest) { $wStart = $Oldest }
        if ($wEnd -le $wStart.AddSeconds(30)) { break }
        $windows.Add([pscustomobject]@{ Start = $wStart; End = $wEnd })
        $cursor = $wStart
    }
    if ($RequestedEnd -lt $Now.AddMinutes(-2)) {
        $windows.Add([pscustomobject]@{ Start = $RequestedEnd; End = $Now })
    }
    return ,$windows.ToArray()
}

function ConvertTo-ComparableMessageId {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return (($Value -replace '[<>]', '').Trim().ToLowerInvariant())
}

function Get-NormalizedStatusList {
    param($Values)
    $list = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    foreach ($v in @($Values)) {
        if ($null -eq $v) { continue }
        foreach ($part in ([string]$v -split '[;,\s]+')) {
            $t = $part.Trim()
            if (-not $t) { continue }
            $match = $null
            foreach ($allowed in $script:AllowedStatus) {
                if ($allowed -eq $t) { $match = $allowed; break }
            }
            if (-not $match) { continue }
            if ($seen.ContainsKey($match)) { continue }
            $seen[$match] = $true
            $list.Add($match)
        }
    }
    return ,$list.ToArray()
}

function Test-SubjectFilterMatch {
    param([string]$SubjectText, [string]$Filter, [string]$Mode = 'Contains')
    if ([string]::IsNullOrEmpty($Filter)) { return $true }
    if ($null -eq $SubjectText) { $SubjectText = '' }
    switch ($Mode) {
        'StartsWith' { return $SubjectText.StartsWith($Filter, [System.StringComparison]::OrdinalIgnoreCase) }
        'EndsWith'   { return $SubjectText.EndsWith($Filter, [System.StringComparison]::OrdinalIgnoreCase) }
        default      { return ($SubjectText.IndexOf($Filter, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) }
    }
}

function Test-TextContainsToken {
    param([string]$Text, [string]$Token)
    if ([string]::IsNullOrWhiteSpace($Text) -or [string]::IsNullOrWhiteSpace($Token)) { return $false }
    if ($Token.Length -lt 3) { return $false }
    $escaped = [regex]::Escape($Token)
    return [regex]::IsMatch($Text, "(?i)(?<![A-Za-z0-9])$escaped(?![A-Za-z0-9])")
}

function Test-ParameterAcceptsCollection {
    param([string]$Command, [string]$Parameter)
    $cmd = Get-Command -Name $Command -ErrorAction SilentlyContinue
    if (-not $cmd -or -not $cmd.Parameters.ContainsKey($Parameter)) { return $false }
    $t = $cmd.Parameters[$Parameter].ParameterType
    if ($t -eq [string] -or $t -eq [datetime] -or $t -eq [guid] -or $t.IsEnum) { return $false }
    if ($t.IsArray) { return $true }
    $name = $t.FullName
    if ($name -match 'MultiValued|ICollection|IList|IEnumerable') { return $true }
    foreach ($i in @($t.GetInterfaces())) {
        if ($i.Name -eq 'IEnumerable' -or $i.Name -eq 'ICollection') { return $true }
    }
    return $false
}

function Get-CommandParameterSet {
    param([string]$Name)
    $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue
    if (-not $cmd) { return @() }
    return @($cmd.Parameters.Keys)
}

function Select-SupportedParameters {
    param([string]$Command, [hashtable]$Parameters)
    $supported = Get-CommandParameterSet $Command
    if ($supported.Count -eq 0) { return $Parameters }
    $kept = @{}
    foreach ($k in @($Parameters.Keys)) {
        if ($supported -contains $k -or $k -eq 'ErrorAction') { $kept[$k] = $Parameters[$k] }
        else {
            if (-not $script:ParamWarnOnce) { $script:ParamWarnOnce = @{} }
            $warnKey = "$Command|$k"
            if (-not $script:ParamWarnOnce.ContainsKey($warnKey)) {
                $script:ParamWarnOnce[$warnKey] = $true
                Write-Log "$Command does not support -$k. That filter will be applied locally when possible." 'WARN'
            }
        }
    }
    return $kept
}
#endregion

#region Decoders
function ConvertFrom-AgentData {
    param([string]$Text)
    $agents = New-Object 'System.Collections.Generic.List[psobject]'
    if ([string]::IsNullOrWhiteSpace($Text) -or $Text -notmatch 'S:') { return ,@() }
    $chunks = [regex]::Split($Text, '(?:^|;)\s*S:') | Where-Object { $_ -and $_.Trim() }
    foreach ($chunk in $chunks) {
        $eq = $chunk.IndexOf('=')
        if ($eq -lt 1) { continue }
        $agentName = $chunk.Substring(0, $eq).Trim()
        $rest = $chunk.Substring($eq + 1).TrimEnd(';')
        $values = [ordered]@{}
        $subType = $null
        foreach ($tok in ($rest -split '\|')) {
            if ($tok -match '^([^=]+)=(.*)$') {
                $k = $matches[1].Trim(); $v = $matches[2].Trim()
                if ($values.Contains($k)) { $values[$k] = "$($values[$k]),$v" } else { $values[$k] = $v }
            } elseif (-not $subType -and $tok.Trim()) {
                $subType = $tok.Trim()
            }
        }
        if ($values.Count -eq 0 -and -not $subType) { $subType = $rest }
        $agents.Add([pscustomobject]@{ Agent = $agentName; SubType = $subType; Values = $values; Raw = $chunk })
    }
    return ,$agents.ToArray()
}

function ConvertFrom-TraceDataXml {
    param([string]$Data)
    $h = [ordered]@{}
    if ([string]::IsNullOrWhiteSpace($Data)) { return $h }
    $xmlText = $Data.Trim()
    if ($xmlText -notmatch '^<root') { $xmlText = "<root>$xmlText</root>" }
    try {
        $settings = New-Object System.Xml.XmlReaderSettings
        $settings.XmlResolver = $null
        try { $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit } catch { }
        $reader = $null
        $sr = $null
        try {
            $sr = New-Object System.IO.StringReader $xmlText
            $reader = [System.Xml.XmlReader]::Create($sr, $settings)
            $x = New-Object System.Xml.XmlDocument
            $x.XmlResolver = $null
            $x.Load($reader)
            foreach ($mep in $x.SelectNodes('//MEP')) {
                $name = $mep.GetAttribute('Name')
                if (-not $name) { continue }
                $vals = @()
                foreach ($a in $mep.Attributes) { if ($a.Name -ne 'Name') { $vals += $a.Value } }
                $val = $vals -join ' '
                if ($h.Contains($name)) { $h[$name] = "$($h[$name]); $val" } else { $h[$name] = $val }
            }
        } finally {
            if ($reader) { $reader.Dispose() }
            if ($sr) { $sr.Dispose() }
        }
    } catch {
        $h['RawData'] = $Data
    }
    return $h
}

function Get-StatusCodes {
    param([string]$Text)
    $result = New-Object 'System.Collections.Generic.List[string]'
    if ([string]::IsNullOrWhiteSpace($Text)) { return ,@() }
    foreach ($m in [regex]::Matches($Text, '(?<![\d\.])([245]\.\d{1,3}\.\d{1,3})(?![\d\.])')) {
        $c = $m.Groups[1].Value
        if (-not $result.Contains($c)) { $result.Add($c) }
    }
    return ,$result.ToArray()
}

function Get-DsnInfo {
    param([string]$Code)
    if ($script:DsnKb.ContainsKey($Code)) {
        $p = $script:DsnKb[$Code] -split '\|'
        return [pscustomobject]@{ Code = $Code; Meaning = $p[0]; Cause = $p[1]; Fix = $p[2]; Exact = $true }
    }
    $parts = $Code -split '\.'
    if ($parts.Count -lt 3) {
        return [pscustomobject]@{ Code = $Code; Meaning = 'Unrecognized status code.'; Cause = 'Not in the built-in knowledge base.'; Fix = 'Read the full response text in the event detail.'; Exact = $false }
    }
    $class = 0; $subject = 0; $detail = 0
    [void][int]::TryParse($parts[0], [ref]$class)
    [void][int]::TryParse($parts[1], [ref]$subject)
    [void][int]::TryParse($parts[2], [ref]$detail)
    if ($subject -eq 7) {
        if ($class -eq 4 -and $detail -ge 500 -and $detail -le 699) {
            return [pscustomobject]@{ Code = $Code; Meaning = 'Access denied, please try again later (new / low-reputation sender throttling).'; Cause = 'The sending IP or domain is being throttled because it is new or has suspicious activity.'; Fix = 'Transient - retries usually succeed. If persistent, review sending patterns and authentication.'; Exact = $false }
        }
        if ($class -eq 5 -and $detail -ge 606 -and $detail -le 649) {
            return [pscustomobject]@{ Code = $Code; Meaning = 'Access denied, banned sending IP.'; Cause = 'The sending IP is on the Microsoft block list.'; Fix = 'Request delisting at https://sender.office.com.'; Exact = $false }
        }
        if ($class -eq 5 -and $detail -ge 700 -and $detail -le 749) {
            return [pscustomobject]@{ Code = $Code; Meaning = 'Access denied, tenant sending restricted.'; Cause = 'The tenant is blocked from sending (trial limits, abuse, unverified domains).'; Fix = 'Review the Microsoft 365 message center / contact support; secure compromised accounts.'; Exact = $false }
        }
    }
    $classText = switch ($class) { 2 { 'Success' } 4 { 'Transient failure (will be retried)' } 5 { 'Permanent failure (NDR)' } default { 'Unknown class' } }
    $subjText = switch ($subject) {
        0 { 'Other / undefined' } 1 { 'Addressing problem' } 2 { 'Mailbox problem' } 3 { 'Mail system problem' }
        4 { 'Network / routing problem' } 5 { 'Protocol problem' } 6 { 'Content / media problem' } 7 { 'Security or policy problem' }
        default { 'Unknown' }
    }
    return [pscustomobject]@{ Code = $Code; Meaning = "$classText - $subjText."; Cause = 'Not in the built-in knowledge base. Read the full response text in the event detail.'; Fix = 'Search the code at https://learn.microsoft.com/exchange/mail-flow-best-practices/non-delivery-reports-in-exchange-online/non-delivery-reports-in-exchange-online'; Exact = $false }
}

function Get-AntiSpamVerdicts {
    param([string]$Text)
    $v = [ordered]@{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return $v }
    $map = [ordered]@{
        'SFV'      = '(?i)\bSFV[=:]\s*([A-Z]+)'
        'SCL'      = '(?i)\bSCL[=:]\s*(-?\d+)'
        'CAT'      = '(?i)\bCAT[=:]\s*([A-Z]+)'
        'BCL'      = '(?i)\bBCL[=:]\s*(\d+)'
        'PCL'      = '(?i)\bPCL[=:]\s*(\d+)'
        'IPV'      = '(?i)\bIPV[=:]\s*([A-Z]+)'
        'SRV'      = '(?i)\bSRV[=:]\s*([A-Z]+)'
        'DIR'      = '(?i)\bDIR[=:]\s*([A-Z]+)'
        'SFTY'     = '(?i)\bSFTY[=:]\s*([\d\.]+)'
        'CTRY'     = '(?i)\bCTRY[=:]\s*([A-Z]{2})'
        'compauth' = '(?i)\bcompauth[=:]\s*([a-z]+)'
        'reason'   = '(?i)compauth[=:]\s*[a-z]+\s+reason[=:]\s*(\d{3})'
        'spf'      = '(?i)\bspf[=:]\s*([a-z]+)'
        'dkim'     = '(?i)\bdkim[=:]\s*([a-z]+)'
        'dmarc'    = '(?i)\bdmarc[=:]\s*([a-z]+)'
        'action'   = '(?i)\baction[=:]\s*([A-Za-z]+)'
    }
    foreach ($k in @($map.Keys)) {
        $m = [regex]::Match($Text, $map[$k])
        if ($m.Success) { $v[$k] = $m.Groups[1].Value }
    }
    return $v
}

function Get-EventExplanation {
    param([string]$EventName)
    foreach ($e in $script:EventKb) {
        if ($EventName -match $e.Pattern) { return $e }
    }
    return @{ Sev = 'Info'; Text = '' }
}

function Get-AuthReasonText {
    param([string]$Reason)
    if ([string]::IsNullOrWhiteSpace($Reason)) { return '' }
    if ($script:AuthReasonKb.ContainsKey($Reason)) { return [string]$script:AuthReasonKb[$Reason] }
    if ($Reason.Length -eq 3) {
        $prefix = $Reason.Substring(0, 1)
        if ($script:AuthReasonKb.ContainsKey($prefix)) { return [string]$script:AuthReasonKb[$prefix] }
    }
    return ''
}
#endregion

#region Message model
function New-MessageRecord {
    param($Summary, [string]$Source = 'MessageTrace')
    $sender = [string](Get-PropValue $Summary 'SenderAddress')
    $recip  = [string](Get-PropValue $Summary 'RecipientAddress')
    $sDom = Get-DomainFromAddress $sender
    $rDom = Get-DomainFromAddress $recip
    $sInt = Test-InternalDomain $sDom
    $rInt = Test-InternalDomain $rDom
    $direction = if ($script:AcceptedDomains.Count -eq 0) { 'Unknown' }
                 elseif ($sInt -and $rInt) { 'Intra-org' }
                 elseif ($sInt) { 'Outbound' }
                 elseif ($rInt) { 'Inbound' }
                 else { 'Relay/External' }
    [pscustomobject][ordered]@{
        Key               = '{0}|{1}' -f (Get-PropValue $Summary 'MessageTraceId'), $recip
        Source            = $Source
        ReceivedUtc       = ConvertTo-UtcDate (Get-PropValue $Summary 'Received')
        SenderAddress     = $sender
        RecipientAddress  = $recip
        Subject           = [string](Get-PropValue $Summary 'Subject')
        Status            = [string](Get-PropValue $Summary 'Status')
        FromIP            = [string](Get-PropValue $Summary 'FromIP')
        ToIP              = [string](Get-PropValue $Summary 'ToIP')
        Size              = Get-PropValue $Summary 'Size'
        MessageId         = [string](Get-PropValue $Summary 'MessageId')
        MessageTraceId    = [string](Get-PropValue $Summary 'MessageTraceId')
        Direction         = $direction
        SenderInternal    = $sInt
        RecipientInternal = $rInt
        DetailRetrieved   = $false
        DetailError       = $null
        TotalTransit      = $null
        Events            = New-Object 'System.Collections.Generic.List[psobject]'
        Findings          = New-Object 'System.Collections.Generic.List[psobject]'
        Enrichment        = [ordered]@{}
        PrimaryCause      = $null
    }
}

function New-JourneyEvent {
    param(
        $DateUtc, [string]$EventName, [string]$Action, [string]$Detail,
        [string]$DataRaw, [System.Collections.IDictionary]$Data, [string]$Source
    )
    if ($null -eq $Data) { $Data = [ordered]@{} }
    $allText = ($Detail + ' ' + (($Data.Values | ForEach-Object { [string]$_ }) -join ' ')).Trim()
    $agentText = (($Data.Values | Where-Object { "$_" -match 'S:' }) -join ';')
    $agents = ConvertFrom-AgentData $agentText
    $lastError = $null
    $led = [regex]::Match($allText, '(?i)LED=(.+?)(?=\};|\}\s*\]|\}\s*$|;\s*\{|$)')
    if ($led.Success) { $lastError = $led.Groups[1].Value.Trim() }
    $expl = Get-EventExplanation $EventName
    $codes = Get-StatusCodes $allText
    [pscustomobject][ordered]@{
        DateUtc     = $DateUtc
        Event       = $EventName
        Action      = $Action
        Detail      = $Detail
        Explanation = $expl.Text
        EventSev    = $expl.Sev
        Codes       = $codes
        LastError   = $lastError
        Verdicts    = (Get-AntiSpamVerdicts $allText)
        Agents      = $agents
        Data        = $Data
        DataRaw     = $DataRaw
        AllText     = $allText
        Source      = $Source
        Elapsed     = $null
        GapSeconds  = $null
    }
}

function Add-Finding {
    param(
        [Parameter(Mandatory)]$Msg,
        [ValidateSet('Critical', 'Warning', 'Info')][string]$Severity,
        [string]$Category, [string]$Finding, [string]$Evidence, [string]$Recommendation
    )
    foreach ($f in @($Msg.Findings)) {
        if ($f.Category -eq $Category -and $f.Finding -eq $Finding) { return }
    }
    $Msg.Findings.Add([pscustomobject][ordered]@{
        MessageTraceId = $Msg.MessageTraceId
        Recipient      = $Msg.RecipientAddress
        Severity       = $Severity
        Category       = $Category
        Finding        = $Finding
        Evidence       = $Evidence
        Recommendation = $Recommendation
    })
}
#endregion

#region Connection and org context
function Get-M365MailFlowPrerequisite {
    $mod = Get-Module -ListAvailable -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    [pscustomobject]@{
        PowerShell      = $PSVersionTable.PSVersion.ToString()
        ModuleInstalled = [bool]$mod
        ModuleVersion   = if ($mod) { $mod.Version.ToString() } else { $null }
        ModulePath      = if ($mod) { $mod.ModuleBase } else { $null }
        ScriptVersion   = $script:ScriptVersion
    }
}

function Get-M365MailFlowConnectionState {
    $exo = $null
    try {
        if (Get-Command -Name Get-ConnectionInformation -ErrorAction SilentlyContinue) {
            $exo = @(Get-ConnectionInformation -ErrorAction Stop) |
                Where-Object { $_.State -eq 'Connected' -and -not $_.IsEopSession } |
                Select-Object -First 1
        }
    } catch { $exo = $null }
    $ipps = $false
    try { $ipps = [bool](Get-Command -Name Get-QuarantineMessage -ErrorAction SilentlyContinue) } catch { $ipps = $false }
    [pscustomobject]@{
        Connected         = [bool]$exo
        UserPrincipalName = if ($exo) { [string](Get-PropValue $exo 'UserPrincipalName') } else { '' }
        TenantId          = if ($exo) { [string](Get-PropValue $exo 'TenantID') } else { '' }
        Ipps              = $ipps
    }
}

function Add-ConnectAuthParameter {
    param($CommandName, [hashtable]$Bag)
    $cmd = Get-Command -Name $CommandName -ErrorAction SilentlyContinue
    if (-not $cmd) { return }
    $cfg = $script:Config
    if ($cfg.AppId -and $cfg.CertificateThumbprint -and $cfg.Organization) {
        $Bag.AppId = $cfg.AppId
        $Bag.CertificateThumbprint = ($cfg.CertificateThumbprint -replace '\s', '')
        $Bag.Organization = $cfg.Organization
    } elseif ($cfg.UserPrincipalName) {
        $Bag.UserPrincipalName = $cfg.UserPrincipalName
    }
    if ($cfg.UseDeviceCode -and $cmd.Parameters.ContainsKey('Device')) { $Bag.Device = $true }
    if ($cfg.DisableWAM -and $cmd.Parameters.ContainsKey('DisableWAM')) { $Bag.DisableWAM = $true }
}

function Get-FirstCommandName {
    param([string]$Name)
    $cmd = $null
    try { $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1 } catch { $cmd = $null }
    if (-not $cmd) { return $null }
    return [string]$cmd.Name
}

function Get-MessageTraceCommandAvailability {
    $summaryV2 = Get-FirstCommandName 'Get-MessageTraceV2'
    $detailV2 = Get-FirstCommandName 'Get-MessageTraceDetailV2'
    $summary = Get-FirstCommandName 'Get-MessageTrace'
    $detail = Get-FirstCommandName 'Get-MessageTraceDetail'
    if (-not $summaryV2 -and -not $summary) {
        $wild = @()
        try { $wild = @(Get-Command -Name '*MessageTrace*' -ErrorAction SilentlyContinue) } catch { $wild = @() }
        foreach ($c in $wild) {
            $n = [string]$c.Name
            if (-not $detailV2 -and $n -match 'Get-MessageTraceDetailV2$') { $detailV2 = $n }
            elseif (-not $summaryV2 -and $n -match 'Get-MessageTraceV2$') { $summaryV2 = $n }
            elseif (-not $detail -and $n -match 'Get-MessageTraceDetail$') { $detail = $n }
            elseif (-not $summary -and $n -match 'Get-MessageTrace$') { $summary = $n }
        }
    }
    $useV2 = -not [string]::IsNullOrWhiteSpace($summaryV2)
    $summaryName = if ($useV2) { $summaryV2 } else { $summary }
    $detailName = if ($useV2) { $detailV2 } else { $detail }
    if ([string]::IsNullOrWhiteSpace($detailName)) {
        if ($useV2) { $detailName = 'Get-MessageTraceDetailV2' } else { $detailName = 'Get-MessageTraceDetail' }
    }
    return [pscustomobject]@{
        UseV2 = [bool]$useV2
        HasTrace = (-not [string]::IsNullOrWhiteSpace($summaryName))
        SummaryName = $summaryName
        DetailName = $detailName
    }
}

function Test-ExoSessionNeedsRefresh {
    param($ExistingConnection, [bool]$HasTraceCmdlet)
    return [bool](($null -ne $ExistingConnection) -and (-not $HasTraceCmdlet))
}

function Get-MessageTraceAccessError {
    param([string]$Identity)
    $who = $Identity
    if ([string]::IsNullOrWhiteSpace($who)) { $who = 'the signed-in account' }
    return ("Signed in as $who, but Exchange did not load Get-MessageTraceV2 or Get-MessageTrace. " +
        'Those cmdlets are added to the session only when the account has the Message Tracking role. ' +
        'Exchange Administrator in Microsoft Entra, or Organization Management in Exchange, includes that role. Exchange Recipient Administrator does not. ' +
        'If the role was just assigned, wait a few minutes, click Disconnect, then Connect, and run again. ' +
        'A session opened before the role change keeps the old cmdlet list, so this tool signs in again once when the cmdlets are missing.')
}

function Disconnect-ExoSessionQuiet {
    if (-not (Get-Command -Name 'Disconnect-ExchangeOnline' -ErrorAction SilentlyContinue)) { return }
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Log 'Disconnected the previous Exchange Online session so this window can sign in again.' 'OK'
    } catch {
        Write-Log "Could not disconnect the previous Exchange session: $($_.Exception.Message)" 'WARN'
    }
    $script:Connected = $false
    $script:IppsReady = $false
    $script:OpenedExo = $false
    $script:OpenedIpps = $false
}

function Connect-ExoSession {
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        throw 'ExchangeOnlineManagement module not found. Install it with: Install-Module ExchangeOnlineManagement -Scope CurrentUser'
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop -WarningAction SilentlyContinue
    $mod = Get-Module ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
    if ($mod.Version -lt [version]'3.0.0') {
        throw "ExchangeOnlineManagement $($mod.Version) is too old. Update with: Update-Module ExchangeOnlineManagement"
    }
    Write-Log "ExchangeOnlineManagement module version $($mod.Version)" 'DEBUG'

    $who = $null
    $refreshed = $false
    $avail = $null
    $guard = 0
    while ($guard -lt 3) {
        $guard++
        $existing = $null
        try {
            $existing = @(Get-ConnectionInformation -ErrorAction Stop) |
                Where-Object { $_.State -eq 'Connected' -and -not $_.IsEopSession } |
                Select-Object -First 1
        } catch { }
        if ($existing) { $who = [string](Get-PropValue $existing 'UserPrincipalName') }
        $avail = Get-MessageTraceCommandAvailability
        if ($existing -and $avail.HasTrace) {
            $tid = [string](Get-PropValue $existing 'TenantID')
            Write-Log "Reusing existing Exchange Online session ($who / $tid)" 'OK'
            break
        }
        if ((Test-ExoSessionNeedsRefresh -ExistingConnection $existing -HasTraceCmdlet $avail.HasTrace) -and -not $refreshed) {
            Write-Log "Signed in as $who, but this session does not include Get-MessageTraceV2 or Get-MessageTrace. Exchange keeps the cmdlet list from sign-in, so a role added afterward is invisible until you sign in again. Signing in again now." 'WARN'
            Disconnect-ExoSessionQuiet
            $refreshed = $true
            continue
        }
        if ($existing) { break }
        $p = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        Add-ConnectAuthParameter -CommandName 'Connect-ExchangeOnline' -Bag $p
        if ($script:Config.AppId -and $script:Config.CertificateThumbprint -and $script:Config.Organization) {
            Write-Log "Connecting to Exchange Online (app-only, AppId $($script:Config.AppId))..."
        } elseif ($script:Config.UserPrincipalName) {
            Write-Log "Connecting to Exchange Online as $($script:Config.UserPrincipalName)..."
        } elseif ($script:Config.UseDeviceCode) {
            Write-Log 'Connecting to Exchange Online with a device code. The code is shown below and in the sign-in window.'
        } else {
            Write-Log 'Connecting to Exchange Online. Complete the Microsoft sign-in window if it appears.'
        }
        Connect-ExchangeOnline @p
        $script:OpenedExo = $true
        Write-Log 'Connected to Exchange Online.' 'OK'
        $avail = Get-MessageTraceCommandAvailability
        break
    }
    $script:Connected = $true

    if ($avail.HasTrace) {
        $script:UseV2 = [bool]$avail.UseV2
        $script:TraceSummaryCommand = [string]$avail.SummaryName
        $script:TraceDetailCommand = [string]$avail.DetailName
        if ($script:UseV2) {
            Write-Log "Using $($script:TraceSummaryCommand) / $($script:TraceDetailCommand)." 'OK'
        } else {
            Write-Log "Get-MessageTraceV2 is not in this session. Using $($script:TraceSummaryCommand) (legacy, deprecated by Microsoft)." 'WARN'
        }
    } else {
        throw (Get-MessageTraceAccessError -Identity $who)
    }
}

function Connect-IppsSessionIfNeeded {
    if ($script:Config.SkipEnrichment -or $script:Config.Offline) { return }
    if (Get-Command -Name Get-QuarantineMessage -ErrorAction SilentlyContinue) {
        $script:IppsReady = $true
        Write-Log 'Security & Compliance cmdlets are already available.' 'DEBUG'
        return
    }
    if (-not (Get-Command -Name Connect-IPPSSession -ErrorAction SilentlyContinue)) {
        Write-Log 'Connect-IPPSSession is not available. Quarantine and restricted-sender lookups will be skipped.' 'WARN'
        return
    }
    try {
        $p = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        Add-ConnectAuthParameter -CommandName 'Connect-IPPSSession' -Bag $p
        Write-Log 'Connecting to Security & Compliance for quarantine and restricted-sender lookups. A second sign-in may appear.'
        Connect-IPPSSession @p
        $script:OpenedIpps = $true
        $script:IppsReady = [bool](Get-Command -Name Get-QuarantineMessage -ErrorAction SilentlyContinue)
        if ($script:IppsReady) { Write-Log 'Security & Compliance session is ready.' 'OK' }
        else { Write-Log 'Security & Compliance connected, but Get-QuarantineMessage is still unavailable for this account.' 'WARN' }
    } catch {
        Write-Log "Security & Compliance connection failed: $($_.Exception.Message). Quarantine lookups will be skipped." 'WARN'
    }
}

function Initialize-OrgContext {
    try {
        $domains = Invoke-ExoCommand -Command 'Get-AcceptedDomain'
        $script:AcceptedDomains = @(
            $domains | ForEach-Object { ([string](Get-PropValue $_ 'DomainName')).ToLowerInvariant() } | Where-Object { $_ }
        )
        Write-Log "Accepted domains: $($script:AcceptedDomains -join ', ')" 'OK'
    } catch { Write-Log "Could not read accepted domains: $($_.Exception.Message)" 'WARN' }

    if ($script:Config.SkipEnrichment) { return }

    try {
        $rules = Invoke-ExoCommand -Command 'Get-TransportRule' -Parameters @{ ResultSize = 'Unlimited' }
        $script:TransportRules = @(foreach ($rule in $rules) {
            [pscustomobject]@{
                Guid = [string](Get-PropValue $rule 'Guid'); Name = [string](Get-PropValue $rule 'Name')
                State = [string](Get-PropValue $rule 'State'); Mode = [string](Get-PropValue $rule 'Mode')
                Priority = Get-PropValue $rule 'Priority'; Description = [string](Get-PropValue $rule 'Description')
            }
        })
        Write-Log "Loaded $($script:TransportRules.Count) mail flow rules." 'OK'
    } catch { Write-Log "Could not read mail flow rules: $($_.Exception.Message)" 'WARN' }

    $conns = New-Object 'System.Collections.Generic.List[psobject]'
    foreach ($cmd in @('Get-InboundConnector', 'Get-OutboundConnector')) {
        try {
            foreach ($c in (Invoke-ExoCommand -Command $cmd)) {
                $conns.Add([pscustomobject][ordered]@{
                    Kind                         = if ($cmd -like '*Inbound*') { 'Inbound' } else { 'Outbound' }
                    Name                         = [string](Get-PropValue $c 'Name')
                    Identity                     = [string](Get-PropValue $c 'Identity')
                    Guid                         = [string](Get-PropValue $c 'Guid')
                    Enabled                      = Get-PropValue $c 'Enabled'
                    ConnectorType                = [string](Get-PropValue $c 'ConnectorType')
                    SmartHosts                   = ((Get-PropValue $c 'SmartHosts') -join ', ')
                    UseMXRecord                  = Get-PropValue $c 'UseMXRecord'
                    RecipientDomains             = ((Get-PropValue $c 'RecipientDomains') -join ', ')
                    SenderDomains                = ((Get-PropValue $c 'SenderDomains') -join ', ')
                    SenderIPAddresses            = ((Get-PropValue $c 'SenderIPAddresses') -join ', ')
                    TlsSettings                  = [string](Get-PropValue $c 'TlsSettings')
                    TlsDomain                    = [string](Get-PropValue $c 'TlsDomain')
                    TlsSenderCertificateName     = [string](Get-PropValue $c 'TlsSenderCertificateName')
                    RequireTls                   = Get-PropValue $c 'RequireTls'
                    RestrictDomainsToCertificate = Get-PropValue $c 'RestrictDomainsToCertificate'
                    RestrictDomainsToIPAddresses = Get-PropValue $c 'RestrictDomainsToIPAddresses'
                    IsTransportRuleScoped        = Get-PropValue $c 'IsTransportRuleScoped'
                })
            }
        } catch { Write-Log "Could not read connectors ($cmd): $($_.Exception.Message)" 'WARN' }
    }
    $script:Connectors = $conns.ToArray()
    Write-Log "Loaded $($script:Connectors.Count) connectors." 'OK'
}

function Connect-M365MailFlowSession {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [string]$AppId,
        [string]$CertificateThumbprint,
        [string]$Organization,
        [switch]$UseDeviceCode,
        [switch]$DisableWAM,
        [switch]$SkipEnrichment
    )
    if ($PSBoundParameters.ContainsKey('UserPrincipalName')) { $script:Config.UserPrincipalName = $UserPrincipalName }
    if ($PSBoundParameters.ContainsKey('AppId')) { $script:Config.AppId = $AppId }
    if ($PSBoundParameters.ContainsKey('CertificateThumbprint')) { $script:Config.CertificateThumbprint = $CertificateThumbprint }
    if ($PSBoundParameters.ContainsKey('Organization')) { $script:Config.Organization = $Organization }
    $script:Config.UseDeviceCode = [bool]$UseDeviceCode
    $script:Config.DisableWAM = [bool]$DisableWAM
    if ($PSBoundParameters.ContainsKey('SkipEnrichment')) { $script:Config.SkipEnrichment = [bool]$SkipEnrichment }
    Connect-ExoSession
    try {
        $probe = Invoke-ExoCommand -Command 'Get-AcceptedDomain'
        $names = @($probe | ForEach-Object { [string](Get-PropValue $_ 'DomainName') } | Where-Object { $_ })
        Write-Log ("Connection check succeeded. Accepted domains: {0}" -f ($names -join ', ')) 'OK'
    } catch {
        throw "Signed in, but Get-AcceptedDomain failed: $($_.Exception.Message)"
    }
    return (Get-M365MailFlowConnectionState)
}

function Disconnect-M365MailFlowSession {
    [CmdletBinding()]
    param([switch]$Force)
    $should = $Force -or ($script:Config -and $script:Config.DisconnectWhenDone)
    if (-not $should) { return }
    if (-not (Get-Command -Name Disconnect-ExchangeOnline -ErrorAction SilentlyContinue)) {
        $script:Connected = $false
        $script:IppsReady = $false
        return
    }
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
        Write-Log 'Disconnected from Exchange Online.' 'OK'
    } catch {
        Write-Log "Disconnect failed: $($_.Exception.Message)" 'WARN'
    } finally {
        $script:Connected = $false
        $script:IppsReady = $false
        $script:OpenedExo = $false
        $script:OpenedIpps = $false
    }
}
#endregion

#region Data retrieval
function Get-TraceQueryCombinations {
    param([switch]$FanOutStatus)
    $senders = Get-NormalizedAddressList $script:Config.SenderAddress
    $recips  = Get-NormalizedAddressList $script:Config.RecipientAddress
    $ids     = Get-NormalizedMessageIdList $script:Config.MessageId
    $statuses = Get-NormalizedStatusList $script:Config.Status

    if ($senders.Count -eq 0) { $senders = @($null) }
    if ($recips.Count -eq 0) { $recips = @($null) }
    if ($ids.Count -eq 0) { $ids = @($null) }

    $combos = New-Object 'System.Collections.Generic.List[psobject]'
    foreach ($s in $senders) {
        foreach ($r in $recips) {
            foreach ($id in $ids) {
                if ($FanOutStatus -and $statuses.Count -gt 0) {
                    foreach ($st in $statuses) {
                        $combos.Add([pscustomobject]@{ SenderAddress = $s; RecipientAddress = $r; MessageId = $id; Status = $st })
                    }
                } else {
                    $statusValue = $null
                    if ($statuses.Count -gt 0) { $statusValue = $statuses }
                    $combos.Add([pscustomobject]@{ SenderAddress = $s; RecipientAddress = $r; MessageId = $id; Status = $statusValue })
                }
            }
        }
    }
    if ($combos.Count -gt 25) {
        throw "This search would run $($combos.Count) separate message trace queries (maximum 25). Narrow the sender, recipient, message ID, or status filters."
    }
    return ,$combos.ToArray()
}

function Test-SummaryMatchesClientFilter {
    param($Row)
    $subjectFilter = [string]$script:Config.Subject
    if ($subjectFilter) {
        $mode = [string]$script:Config.SubjectFilterType
        if (-not $mode) { $mode = 'Contains' }
        if (-not (Test-SubjectFilterMatch -SubjectText ([string](Get-PropValue $Row 'Subject')) -Filter $subjectFilter -Mode $mode)) {
            return $false
        }
    }
    $statuses = Get-NormalizedStatusList $script:Config.Status
    if ($statuses.Count -gt 0) {
        $st = [string](Get-PropValue $Row 'Status')
        if ($statuses -notcontains $st) { return $false }
    }
    $senders = Get-NormalizedAddressList $script:Config.SenderAddress
    if ($senders.Count -gt 0) {
        $actual = ([string](Get-PropValue $Row 'SenderAddress')).ToLowerInvariant()
        $ok = $false
        foreach ($s in $senders) { if ($s.ToLowerInvariant() -eq $actual) { $ok = $true; break } }
        if (-not $ok) { return $false }
    }
    $recips = Get-NormalizedAddressList $script:Config.RecipientAddress
    if ($recips.Count -gt 0) {
        $actual = ([string](Get-PropValue $Row 'RecipientAddress')).ToLowerInvariant()
        $ok = $false
        foreach ($s in $recips) { if ($s.ToLowerInvariant() -eq $actual) { $ok = $true; break } }
        if (-not $ok) { return $false }
    }
    $ids = Get-NormalizedMessageIdList $script:Config.MessageId
    if ($ids.Count -gt 0) {
        $actual = ConvertTo-ComparableMessageId ([string](Get-PropValue $Row 'MessageId'))
        $ok = $false
        foreach ($id in $ids) {
            if ((ConvertTo-ComparableMessageId $id) -eq $actual) { $ok = $true; break }
        }
        if (-not $ok) { return $false }
    }
    if ($script:Config.FromIP) {
        if (([string](Get-PropValue $Row 'FromIP')) -ne [string]$script:Config.FromIP) { return $false }
    }
    if ($script:Config.ToIP) {
        if (([string](Get-PropValue $Row 'ToIP')) -ne [string]$script:Config.ToIP) { return $false }
    }
    return $true
}

function Get-TraceSummary {
    param([datetime]$Start, [datetime]$End)
    $all = New-Object 'System.Collections.Generic.List[psobject]'
    $seen = @{}
    $traceCmd = [string]$script:TraceSummaryCommand
    if (-not $traceCmd) {
        if ($script:UseV2) { $traceCmd = 'Get-MessageTraceV2' } else { $traceCmd = 'Get-MessageTrace' }
    }
    $fanOutStatus = -not (Test-ParameterAcceptsCollection -Command $traceCmd -Parameter 'Status')
    $combos = Get-TraceQueryCombinations -FanOutStatus:$fanOutStatus
    $windows = Get-DateWindows -Start $Start -End $End
    Write-Log ("Querying message trace with {0} filter combination(s) in {1} window(s) between {2:u} and {3:u}..." -f $combos.Count, $windows.Count, $Start, $End)
    $comboIndex = 0
    foreach ($combo in $combos) {
        Test-InvestigationCancel
        $comboIndex++
        $labelBits = @()
        if ($combo.SenderAddress) { $labelBits += "sender=$($combo.SenderAddress)" }
        if ($combo.RecipientAddress) { $labelBits += "recipient=$($combo.RecipientAddress)" }
        if ($combo.MessageId) { $labelBits += "messageId=$($combo.MessageId)" }
        if ($combo.Status) { $labelBits += "status=$($combo.Status -join ',')" }
        $label = if ($labelBits.Count) { $labelBits -join '; ' } else { 'no address filter' }
        Write-Log ("Trace query {0}/{1}: {2}" -f $comboIndex, $combos.Count, $label)
        $idForms = @($null)
        if ($combo.MessageId) { $idForms = Get-MessageIdQueryForms ([string]$combo.MessageId) }
        foreach ($activeMessageId in $idForms) {
            $countBeforeForm = $all.Count
            if ($activeMessageId -and $combo.MessageId -and [string]$activeMessageId -ne [string]$combo.MessageId) {
                Write-Log "No rows for $($combo.MessageId). Retrying the same dates without angle brackets ($activeMessageId)." 'WARN'
            }
        foreach ($w in $windows) {
            Test-InvestigationCancel
            if ($all.Count -ge [int]$script:Config.MaxResults) { break }
            if ($script:UseV2) {
                $currentEnd = $w.End
                $startingRecipient = $null
                $round = 0
                $prevCursor = $null
                while ($true) {
                    Test-InvestigationCancel
                    $round++
                    if ($round -gt 200) {
                        Write-Log 'Stopped V2 paging after 200 rounds so a stuck cursor cannot loop forever.' 'WARN'
                        break
                    }
                    $remaining = [int]$script:Config.MaxResults - $all.Count
                    if ($remaining -le 0) { break }
                    $size = [math]::Min(5000, $remaining)
                    $p = @{ StartDate = $w.Start; EndDate = $currentEnd; ResultSize = $size }
                    if ($combo.SenderAddress) { $p.SenderAddress = [string]$combo.SenderAddress }
                    if ($combo.RecipientAddress) { $p.RecipientAddress = [string]$combo.RecipientAddress }
                    if ($activeMessageId) { $p.MessageId = [string]$activeMessageId }
                    if ($combo.Status) { $p.Status = $combo.Status }
                    if ($script:Config.FromIP) { $p.FromIP = [string]$script:Config.FromIP }
                    if ($script:Config.ToIP) { $p.ToIP = [string]$script:Config.ToIP }
                    if ($script:Config.MessageTraceIdSpecified -and $script:Config.MessageTraceId) { $p.MessageTraceId = [guid]$script:Config.MessageTraceId }
                    elseif ($script:DerivedTraceId) { $p.MessageTraceId = [guid]$script:DerivedTraceId }
                    if ($script:Config.Subject) {
                        $p.Subject = [string]$script:Config.Subject
                        $p.SubjectFilterType = [string]$script:Config.SubjectFilterType
                    }
                    if ($startingRecipient) { $p.StartingRecipientAddress = $startingRecipient }
                    $cursorKey = '{0:o}|{1}' -f $currentEnd, $startingRecipient
                    if ($cursorKey -eq $prevCursor) {
                        Write-Log 'Stopped V2 paging because the page cursor did not advance.' 'WARN'
                        break
                    }
                    $prevCursor = $cursorKey
                    $p = Select-SupportedParameters -Command 'Get-MessageTraceV2' -Parameters $p
                    Write-Log ("  Window {0:u} -> {1:u}, round {2}" -f $w.Start, $currentEnd, $round) 'DEBUG'
                    $batch = Invoke-ExoCommand -Command 'Get-MessageTraceV2' -Parameters $p -CountsAgainstTraceThrottle
                    $new = 0
                    foreach ($r in $batch) {
                        if (-not (Test-SummaryMatchesClientFilter $r)) { continue }
                        $k = '{0}|{1}' -f (Get-PropValue $r 'MessageTraceId'), ([string](Get-PropValue $r 'RecipientAddress')).ToLowerInvariant()
                        if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $all.Add($r); $new++ }
                    }
                    if ($batch.Count -lt $size -or $new -eq 0) { break }
                    $last = $batch[$batch.Count - 1]
                    $nextEnd = ConvertTo-UtcDate (Get-PropValue $last 'Received')
                    if ($nextEnd) { $currentEnd = $nextEnd.ToLocalTime() }
                    $startingRecipient = [string](Get-PropValue $last 'RecipientAddress')
                    if (-not $startingRecipient) { break }
                }
            } else {
                $page = 1
                while ($page -le 1000) {
                    Test-InvestigationCancel
                    $p = @{ StartDate = $w.Start; EndDate = $w.End; PageSize = 5000; Page = $page }
                    if ($combo.SenderAddress) { $p.SenderAddress = [string]$combo.SenderAddress }
                    if ($combo.RecipientAddress) { $p.RecipientAddress = [string]$combo.RecipientAddress }
                    if ($activeMessageId) { $p.MessageId = [string]$activeMessageId }
                    if ($combo.Status) { $p.Status = $combo.Status }
                    if ($script:Config.FromIP) { $p.FromIP = [string]$script:Config.FromIP }
                    if ($script:Config.ToIP) { $p.ToIP = [string]$script:Config.ToIP }
                    if ($script:Config.MessageTraceIdSpecified -and $script:Config.MessageTraceId) { $p.MessageTraceId = [guid]$script:Config.MessageTraceId }
                    elseif ($script:DerivedTraceId) { $p.MessageTraceId = [guid]$script:DerivedTraceId }
                    $p = Select-SupportedParameters -Command 'Get-MessageTrace' -Parameters $p
                    $batch = Invoke-ExoCommand -Command 'Get-MessageTrace' -Parameters $p -CountsAgainstTraceThrottle
                    foreach ($r in $batch) {
                        if (-not (Test-SummaryMatchesClientFilter $r)) { continue }
                        $k = '{0}|{1}' -f (Get-PropValue $r 'MessageTraceId'), ([string](Get-PropValue $r 'RecipientAddress')).ToLowerInvariant()
                        if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $all.Add($r) }
                    }
                    if ($batch.Count -lt 5000 -or $all.Count -ge [int]$script:Config.MaxResults) { break }
                    $page++
                }
            }
        }
            if ($all.Count -gt $countBeforeForm) { break }
        }
    }

    $result = @($all)
    if ($result.Count -gt [int]$script:Config.MaxResults) {
        $result = @($result | Sort-Object { ConvertTo-UtcDate (Get-PropValue $_ 'Received') } -Descending | Select-Object -First ([int]$script:Config.MaxResults))
        Write-Log "Truncated results to the $($script:Config.MaxResults) most recent rows (-MaxResults)." 'WARN'
    }
    Write-Log "Message trace returned $($result.Count) message/recipient row(s)." 'OK'
    return ,$result
}

function Get-TraceDetailWindow {
    param($Msg)
    if (-not $Msg.ReceivedUtc) { throw 'No Received timestamp on summary row.' }
    $recvLocal = $Msg.ReceivedUtc.ToLocalTime()
    $start = $recvLocal.AddDays(-1)
    $oldest = (Get-Date).AddDays(-90).AddHours(1)
    if ($start -lt $oldest) { $start = $oldest }
    $end = $recvLocal.AddDays(8)
    if ($end -gt $start.AddHours(239)) { $end = $start.AddHours(239) }
    $now = Get-Date
    if ($end -gt $now) { $end = $now }
    if ($end -le $start) {
        $end = $now
        $start = $end.AddHours(-1)
        if ($start -lt $oldest) { $start = $oldest }
        if ($end -le $start) { $end = $start.AddMinutes(5) }
    }
    return [pscustomobject]@{ Start = $start; End = $end }
}

function Get-TraceDetailEvents {
    param($Msg)
    $window = Get-TraceDetailWindow -Msg $Msg
    $traceId = [string]$Msg.MessageTraceId
    $parsed = [guid]::Empty
    if (-not [guid]::TryParse($traceId, [ref]$parsed)) {
        throw "MessageTraceId '$traceId' is not a GUID, so journey detail cannot be queried."
    }
    $p = @{
        MessageTraceId   = $parsed
        RecipientAddress = $Msg.RecipientAddress
        StartDate        = $window.Start
        EndDate          = $window.End
    }
    $cmd = [string]$script:TraceDetailCommand
    if (-not $cmd) {
        if ($script:UseV2) { $cmd = 'Get-MessageTraceDetailV2' } else { $cmd = 'Get-MessageTraceDetail' }
    }
    $p = Select-SupportedParameters -Command $cmd -Parameters $p
    $raw = Invoke-ExoCommand -Command $cmd -Parameters $p -CountsAgainstTraceThrottle

    $events = New-Object 'System.Collections.Generic.List[psobject]'
    foreach ($d in ($raw | Sort-Object { ConvertTo-UtcDate (Get-PropValue $_ 'Date') })) {
        $dataRaw = [string](Get-PropValue $d 'Data')
        $events.Add((New-JourneyEvent -DateUtc (ConvertTo-UtcDate (Get-PropValue $d 'Date')) -EventName ([string](Get-PropValue $d 'Event')) `
                    -Action ([string](Get-PropValue $d 'Action')) -Detail ([string](Get-PropValue $d 'Detail')) -DataRaw $dataRaw `
                    -Data (ConvertFrom-TraceDataXml $dataRaw) -Source 'MessageTraceDetail'))
    }
    return ,$events.ToArray()
}

function Read-TextFileAuto {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        return [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        return [System.Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    $sample = [math]::Min(200, $bytes.Length)
    $zeros = 0
    for ($i = 0; $i -lt $sample; $i++) { if ($bytes[$i] -eq 0) { $zeros++ } }
    if ($sample -gt 0 -and ($zeros / $sample) -gt 0.2) {
        return [System.Text.Encoding]::Unicode.GetString($bytes)
    }
    return (New-Object System.Text.UTF8Encoding $false).GetString($bytes)
}

function ConvertFrom-CsvRecords {
    param([string]$Text)
    $records = New-Object 'System.Collections.Generic.List[psobject]'
    if ([string]::IsNullOrEmpty($Text)) { return ,@() }
    $field = New-Object System.Text.StringBuilder
    $fields = New-Object 'System.Collections.Generic.List[string]'
    $inQuotes = $false
    $chars = $Text.ToCharArray()
    $i = 0
    while ($i -lt $chars.Length) {
        $c = $chars[$i]
        if ($inQuotes) {
            if ($c -eq '"') {
                if (($i + 1) -lt $chars.Length -and $chars[$i + 1] -eq '"') {
                    [void]$field.Append('"')
                    $i += 2
                    continue
                }
                $inQuotes = $false
                $i++
                continue
            }
            [void]$field.Append($c)
            $i++
            continue
        }
        if ($c -eq '"') { $inQuotes = $true; $i++; continue }
        if ($c -eq ',') {
            $fields.Add($field.ToString())
            [void]$field.Clear()
            $i++
            continue
        }
        if ($c -eq "`r") { $i++; continue }
        if ($c -eq "`n") {
            $fields.Add($field.ToString())
            [void]$field.Clear()
            $records.Add($fields.ToArray())
            $fields = New-Object 'System.Collections.Generic.List[string]'
            $i++
            continue
        }
        [void]$field.Append($c)
        $i++
    }
    if ($field.Length -gt 0 -or $fields.Count -gt 0) {
        $fields.Add($field.ToString())
        $records.Add($fields.ToArray())
    }
    return ,$records.ToArray()
}

function Import-ExtendedReport {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Extended report not found: $Path" }
    $text = Read-TextFileAuto -Path (Resolve-Path -LiteralPath $Path).Path
    $records = ConvertFrom-CsvRecords -Text $text
    $headerIdx = -1
    for ($i = 0; $i -lt $records.Count; $i++) {
        foreach ($col in @($records[$i])) {
            if ($col -eq 'date_time_utc') { $headerIdx = $i; break }
        }
        if ($headerIdx -ge 0) { break }
    }
    if ($headerIdx -lt 0) { throw "Extended report '$Path' has no date_time_utc header. Download the MessageTraceDetail (Extended) report." }
    $header = @($records[$headerIdx])
    $rows = New-Object 'System.Collections.Generic.List[psobject]'
    for ($i = $headerIdx + 1; $i -lt $records.Count; $i++) {
        $rec = @($records[$i])
        $any = $false
        foreach ($cell in $rec) { if ($cell) { $any = $true; break } }
        if (-not $any) { continue }
        $obj = [ordered]@{}
        for ($c = 0; $c -lt $header.Count; $c++) {
            $name = [string]$header[$c]
            if (-not $name) { continue }
            $val = if ($c -lt $rec.Count) { $rec[$c] } else { '' }
            $obj[$name] = $val
        }
        $rows.Add([pscustomobject]$obj)
    }
    Write-Log "Extended report: $($rows.Count) rows loaded from $Path" 'OK'
    if ($rows.Count -eq 0) { return ,@() }

    $messages = New-Object 'System.Collections.Generic.List[psobject]'
    $groups = $rows | Group-Object {
        $id = [string](Get-PropValue $_ 'network_message_id')
        if ($id) { return $id }
        $fallback = '{0}|{1}|{2}' -f (Get-PropValue $_ 'message_id'), (Get-PropValue $_ 'sender_address'), (Get-PropValue $_ 'date_time_utc')
        if ($fallback -eq '||') { return [guid]::NewGuid().ToString() }
        return $fallback
    }
    foreach ($g in $groups) {
        $gRows = @($g.Group | Sort-Object { ConvertTo-UtcDate (Get-PropValue $_ 'date_time_utc') })
        $recips = @(
            $gRows | ForEach-Object { ([string](Get-PropValue $_ 'recipient_address')) -split ';' } |
                Where-Object { $_ -and $_.Trim() } |
                ForEach-Object { $_.Trim().ToLowerInvariant() } |
                Select-Object -Unique
        )
        if ($recips.Count -eq 0) { $recips = @('(unknown)') }
        $first = $gRows[0]
        foreach ($rcpt in $recips) {
            $rRows = @($gRows | Where-Object {
                $ra = [string](Get-PropValue $_ 'recipient_address')
                (-not $ra) -or (($ra -split ';' | ForEach-Object { $_.Trim().ToLowerInvariant() }) -contains $rcpt)
            })
            $statusEvent = $rRows | Where-Object { (Get-PropValue $_ 'event_id') -match '^(DELIVER|SEND|FAIL|DROP|DEFER|EXPAND|BADMAIL|POISONMESSAGE)' } | Select-Object -Last 1
            $evId = [string](Get-PropValue $statusEvent 'event_id')
            $derived = switch -Regex ($evId) {
                '^(DELIVER|SEND)' { 'Delivered' }
                '^(FAIL|DROP|BADMAIL|POISONMESSAGE)' { 'Failed' }
                '^DEFER' { 'Pending' }
                '^EXPAND' { 'Expanded' }
                default { 'Unknown' }
            }
            $summary = [pscustomobject]@{
                Received = Get-PropValue $first 'date_time_utc'; SenderAddress = Get-PropValue $first 'sender_address'
                RecipientAddress = $rcpt; Subject = Get-PropValue $first 'message_subject'; Status = $derived
                FromIP = Get-PropValue $first 'original_client_ip'; ToIP = Get-PropValue $statusEvent 'server_ip'
                Size = Get-PropValue $first 'total_bytes'; MessageId = Get-PropValue $first 'message_id'
                MessageTraceId = $g.Name
            }
            $msg = New-MessageRecord -Summary $summary -Source 'ExtendedReport'
            $dirCol = [string](Get-PropValue $first 'directionality')
            if ($msg.Direction -eq 'Unknown' -and $dirCol) { $msg.Direction = $dirCol }
            foreach ($r in $rRows) {
                $data = [ordered]@{}
                foreach ($col in @(
                    'source_context','connector_id','client_ip','client_hostname','server_ip','server_hostname',
                    'original_client_ip','original_server_ip','return_path','message_info','reference',
                    'related_recipient_address','recipient_count','directionality','custom_data'
                )) {
                    $val = [string](Get-PropValue $r $col)
                    if ($val) { $data[$col] = $val }
                }
                $msg.Events.Add((New-JourneyEvent -DateUtc (ConvertTo-UtcDate (Get-PropValue $r 'date_time_utc')) `
                        -EventName ([string](Get-PropValue $r 'event_id')) -Action ([string](Get-PropValue $r 'source')) `
                        -Detail ([string](Get-PropValue $r 'recipient_status')) -DataRaw '' -Data $data -Source 'ExtendedReport'))
            }
            $msg.DetailRetrieved = $true
            $messages.Add($msg)
        }
    }
    return ,$messages.ToArray()
}
#endregion

#region Header analysis
function ConvertFrom-RfcDate {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $m = [regex]::Match($Text, '(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?\s*([+-]\d{2}:\d{2}|[+-]\d{4}|GMT|UTC|UT|Z)?')
    if (-not $m.Success) { return $null }
    $after = ''
    $end = $m.Index + $m.Length
    if ($end -lt $Text.Length) { $after = $Text.Substring($end) }
    if (-not $m.Groups[7].Success -and $after -match '^\s*[A-Za-z]{2,5}\b') { return $null }
    $sec = if ($m.Groups[6].Success) { [int]$m.Groups[6].Value } else { 0 }
    $off = $m.Groups[7].Value
    if (-not $off -or $off -match '^(?i)(GMT|UTC|UT|Z)$') { $offFmt = '+00:00' }
    elseif ($off -match '^[+-]\d{2}:\d{2}$') { $offFmt = $off }
    elseif ($off -match '^[+-]\d{4}$') { $offFmt = '{0}:{1}' -f $off.Substring(0, 3), $off.Substring(3, 2) }
    else { $offFmt = '+00:00' }
    $mon = $m.Groups[2].Value
    if ($mon.Length -ge 1) {
        $mon = $mon.Substring(0, 1).ToUpperInvariant() + $mon.Substring(1).ToLowerInvariant()
    }
    $s = '{0:00} {1} {2} {3:00}:{4:00}:{5:00} {6}' -f [int]$m.Groups[1].Value, $mon, [int]$m.Groups[3].Value, [int]$m.Groups[4].Value, [int]$m.Groups[5].Value, $sec, $offFmt
    $dto = [datetimeoffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AllowWhiteSpaces
    if ([datetimeoffset]::TryParseExact($s, 'dd MMM yyyy HH:mm:ss zzz', [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dto)) {
        return $dto.UtcDateTime
    }
    return $null
}

function Get-HeaderAnalysis {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Header file not found: $Path" }
    $raw = (Read-TextFileAuto -Path (Resolve-Path -LiteralPath $Path).Path).TrimStart()
    $blank = [regex]::Match($raw, '\r?\n[ \t]*\r?\n')
    $headerText = if ($blank.Success) { $raw.Substring(0, $blank.Index) } else { $raw }
    $unfolded = [regex]::Replace($headerText, '\r?\n[ \t]+', ' ')

    $headers = New-Object 'System.Collections.Generic.List[psobject]'
    foreach ($line in ($unfolded -split '\r?\n')) {
        if ($line -match '^([^\s:]+):\s*(.*)$') {
            $headers.Add([pscustomobject]@{ Name = $matches[1]; Value = $matches[2] })
        }
    }
    function Get-H([string]$n) { @($headers | Where-Object { $_.Name -eq $n } | ForEach-Object { $_.Value }) }

    $findings = New-Object 'System.Collections.Generic.List[psobject]'
    $addF = {
        param($sev, $cat, $text, $evidence, $fix)
        $findings.Add([pscustomobject][ordered]@{ Severity = $sev; Category = $cat; Finding = $text; Evidence = $evidence; Recommendation = $fix })
    }
    $latencySeconds = Get-LatencyThresholdSeconds

    $received = @(Get-H 'Received')
    [array]::Reverse($received)
    $hops = New-Object 'System.Collections.Generic.List[psobject]'
    $prev = $null
    $i = 0
    foreach ($r in $received) {
        $i++
        $from = if ($r -match '\bfrom\s+(\S+)(?:\s+\(([^)]*)\))?') { $matches[1] + $(if ($matches[2]) { " ($($matches[2]))" } else { '' }) } else { '' }
        $by   = if ($r -match '\bby\s+(\S+)') { $matches[1] } else { '' }
        $with = if ($r -match '\bwith\s+(.+?)(?:\s+id\s+|\s+via\s+|;|$)') { $matches[1].Trim() } else { '' }
        $semi = $r.LastIndexOf(';')
        $when = if ($semi -ge 0) { ConvertFrom-RfcDate $r.Substring($semi + 1) } else { $null }
        $delay = $null
        if ($when -and $prev) { $delay = ($when - $prev).TotalSeconds }
        $tls = ($with -match 'ESMTPS|TLS|SMTPS|version=TLS') -or ($r -match 'version=TLS|cipher=')
        $hops.Add([pscustomobject][ordered]@{
            Hop = $i; From = $from; By = $by; With = $with; TimeUtc = $when
            DelaySeconds = $delay; Delay = $(if ($null -ne $delay) { Format-Duration $delay } else { '' })
            Encrypted = [bool]$tls
        })
        if ($null -ne $delay -and $delay -gt $latencySeconds) {
            & $addF 'Warning' 'Latency' "Hop $i delayed by $(Format-Duration $delay)." "from $from by $by" 'Check the server that held the message (queue backlog, deferrals, antivirus scanning, greylisting).'
        }
        if ($null -ne $delay -and $delay -lt -120) {
            & $addF 'Info' 'Clock' "Hop $i timestamp is earlier than the previous hop ($(Format-Duration ([math]::Abs($delay))))." "by $by" 'Clock skew on one of the servers - latency numbers around this hop are unreliable.'
        }
        if (-not $tls -and $by -and $with -match 'SMTP' -and $from -notmatch 'localhost|127\.0\.0\.1') {
            & $addF 'Info' 'TLS' "Hop $i appears unencrypted ($with)." "from $from by $by" 'Enable TLS on the sending/receiving servers or connectors if this hop crosses the internet.'
        }
        if ($when) { $prev = $when }
    }
    $timedHops = @($hops | Where-Object { $_.TimeUtc })
    $totalTransit = $null
    if ($timedHops.Count -ge 2) {
        $totalTransit = ($timedHops[-1].TimeUtc - $timedHops[0].TimeUtc).TotalSeconds
        if ($totalTransit -gt $latencySeconds) {
            & $addF 'Warning' 'Latency' "Total transit time across Received headers: $(Format-Duration $totalTransit)." "$($timedHops.Count) timed hops" 'See the hop table to find which hop introduced the delay.'
        }
    }

    $authResults = @(Get-H 'Authentication-Results')
    $auth = [ordered]@{}
    $authLine = ($authResults | Where-Object { $_ -match 'compauth' } | Select-Object -First 1)
    if (-not $authLine) { $authLine = $authResults | Select-Object -First 1 }
    if ($authLine) {
        foreach ($pair in @(
            @('spf', 'spf=(\w+)'), @('dkim', 'dkim=(\w+)'), @('dmarc', 'dmarc=(\w+)'), @('dmarcAction', 'dmarc=\w+\s+action=(\w+)'),
            @('compauth', 'compauth=(\w+)'), @('reason', 'compauth=\w+\s+reason=(\d+)'),
            @('smtpMailFrom', 'smtp\.mailfrom=([^;\s]+)'), @('headerFrom', 'header\.from=([^;\s]+)'), @('headerD', 'header\.d=([^;\s]+)')
        )) {
            $m = [regex]::Match([string]$authLine, $pair[1], 'IgnoreCase')
            if ($m.Success) { $auth[$pair[0]] = $m.Groups[1].Value }
        }
    }
    foreach ($k in @('spf', 'dkim', 'dmarc')) {
        if ($auth.Contains($k) -and $auth[$k] -match 'fail|permerror|temperror|softfail') {
            & $addF 'Warning' 'Authentication' "$($k.ToUpper()) result: $($auth[$k])." $authLine "Fix $($k.ToUpper()) for the sending domain at the actual sending service."
        }
        if ($auth.Contains($k) -and $auth[$k] -eq 'none') {
            & $addF 'Info' 'Authentication' "$($k.ToUpper()) result: none (not published / not signed)." $authLine "Publish/enable $($k.ToUpper()) for the sending domain."
        }
    }
    if ($auth.Contains('compauth') -and $auth['compauth'] -match 'fail') {
        $reason = [string]$auth['reason']
        $reasonText = Get-AuthReasonText $reason
        & $addF 'Critical' 'Authentication' "Composite authentication FAILED (reason $reason). $reasonText" $authLine 'The message is treated as spoofed. Fix SPF/DKIM/DMARC alignment, or create a spoof allow entry in the Tenant Allow/Block List if legitimate.'
    }

    $fopeLine = (Get-H 'X-Forefront-Antispam-Report') -join ';'
    $antispam = [ordered]@{}
    foreach ($m in [regex]::Matches([string]$fopeLine, '([A-Za-z]+):([^;]*)')) { $antispam[$m.Groups[1].Value] = $m.Groups[2].Value.Trim() }
    $msAntispam = (Get-H 'X-Microsoft-Antispam') -join ';'
    $bcl = [regex]::Match([string]$msAntispam, 'BCL:(\d+)')
    if ($bcl.Success) { $antispam['BCL'] = $bcl.Groups[1].Value }
    $orgScl = (Get-H 'X-MS-Exchange-Organization-SCL') | Select-Object -First 1
    if ($orgScl) { $antispam['OrgSCL'] = $orgScl }

    if ($antispam.Contains('SFV') -and $script:SfvKb.ContainsKey($antispam['SFV'])) {
        $sev = if ($antispam['SFV'] -match 'SPM|SKS|SKB|BLK') { 'Warning' } else { 'Info' }
        & $addF $sev 'Anti-spam' "SFV=$($antispam['SFV']): $($script:SfvKb[$antispam['SFV']])" $fopeLine 'If unexpected, check anti-spam policies, Tenant Allow/Block List and user Safe/Blocked senders.'
    }
    if ($antispam.Contains('CAT') -and $antispam['CAT'] -and $antispam['CAT'] -ne 'NONE') {
        $catText = if ($script:CatKb.ContainsKey($antispam['CAT'])) { $script:CatKb[$antispam['CAT']] } else { $antispam['CAT'] }
        & $addF 'Warning' 'Anti-spam' "Protection category CAT=$($antispam['CAT']) ($catText)." $fopeLine 'This category determined the policy action (junk/quarantine). Review the matching policy in Defender.'
    }
    $sclNum = ConvertTo-IntSafe $(if ($antispam.Contains('SCL')) { $antispam['SCL'] } else { $null })
    if ($null -ne $sclNum -and $sclNum -ge 5) {
        & $addF 'Warning' 'Anti-spam' "Spam Confidence Level SCL=$sclNum (5-6 spam, 7-9 high confidence spam)." $fopeLine 'Message was routed to Junk or quarantine according to the anti-spam policy.'
    }
    $bclNum = ConvertTo-IntSafe $(if ($antispam.Contains('BCL')) { $antispam['BCL'] } else { $null })
    if ($null -ne $bclNum -and $bclNum -ge 6) {
        & $addF 'Warning' 'Anti-spam' "Bulk Complaint Level BCL=$bclNum." $msAntispam 'Default bulk threshold is 7 (Standard). Lower or raise the threshold in the anti-spam policy, or allow the sender.'
    }
    if ($antispam.Contains('IPV') -and $antispam['IPV'] -eq 'CAL') {
        & $addF 'Info' 'Anti-spam' 'IPV=CAL: sending IP is on the connection filter allow list (spam filtering is skipped).' $fopeLine 'Make sure this allow is intended; it bypasses spam filtering.'
    }

    $firstHeader = {
        param($Name)
        $vals = @(Get-H $Name)
        if ($vals.Count -eq 0) { return $null }
        return $vals[0]
    }
    # Header names are case-insensitive, so Message-ID and Message-Id are the same field.
    $headerMessageIds = @(Get-H 'Message-ID' | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $info = [ordered]@{
        From               = & $firstHeader 'From'
        To                 = & $firstHeader 'To'
        Subject            = & $firstHeader 'Subject'
        Date               = & $firstHeader 'Date'
        MessageId          = $(if ($headerMessageIds.Count -gt 0) { $headerMessageIds[0] } else { $null })
        ReturnPath         = & $firstHeader 'Return-Path'
        NetworkMessageId   = & $firstHeader 'X-MS-Exchange-Organization-Network-Message-Id'
        AuthAs             = & $firstHeader 'X-MS-Exchange-Organization-AuthAs'
        AuthSource         = & $firstHeader 'X-MS-Exchange-Organization-AuthSource'
        Directionality     = & $firstHeader 'X-MS-Exchange-Organization-MessageDirectionality'
        OriginatorOrg      = & $firstHeader 'X-OriginatorOrg'
        CrossTenantId      = & $firstHeader 'X-MS-Exchange-CrossTenant-id'
        TotalTransit       = $(if ($null -ne $totalTransit) { Format-Duration $totalTransit } else { '' })
    }
    $fromDom = Get-DomainFromAddress ([string]$info.From)
    $rpDom = Get-DomainFromAddress ([string]$info.ReturnPath)
    if ($fromDom -and $rpDom -and $fromDom -ne $rpDom -and -not $rpDom.EndsWith('.' + $fromDom)) {
        & $addF 'Info' 'Authentication' "Return-Path domain ($rpDom) differs from From domain ($fromDom)." 'SPF aligns with Return-Path, not From.' 'DMARC will rely on DKIM alignment for the From domain - make sure DKIM d= matches the From domain.'
    }

    return [pscustomobject][ordered]@{
        File     = $Path
        Summary  = $info
        Hops     = $hops.ToArray()
        Auth     = $auth
        AntiSpam = $antispam
        Findings = $findings.ToArray()
    }
}
#endregion

#region Enrichment
function Get-DomainDnsInfo {
    param([string]$Domain)
    if (-not $Domain) { return $null }
    $key = $Domain.ToLowerInvariant()
    if ($script:Cache.Dns.ContainsKey($key)) { return $script:Cache.Dns[$key] }
    $info = [ordered]@{ Domain = $key; MX = @(); A = $false; SPF = $null; DMARC = $null; DMARCPolicy = $null; Errors = @() }
    if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
        $info.Errors += 'Resolve-DnsName not available on this machine.'
        $script:Cache.Dns[$key] = $info
        return $info
    }
    try {
        $info.MX = @(Resolve-DnsName -Name $key -Type MX -DnsOnly -QuickTimeout -ErrorAction Stop |
            Where-Object { $_.Type -eq 'MX' } | Sort-Object Preference | ForEach-Object { '{0} ({1})' -f $_.NameExchange, $_.Preference })
    } catch { $info.Errors += "MX: $($_.Exception.Message)" }
    if (@($info.MX).Count -eq 0) {
        try { $info.A = [bool](Resolve-DnsName -Name $key -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'A' }) } catch { }
    }
    try {
        $txt = @(Resolve-DnsName -Name $key -Type TXT -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'TXT' } | ForEach-Object { $_.Strings -join '' })
        $info.SPF = ($txt | Where-Object { $_ -match '^v=spf1' }) -join ' || '
    } catch { $info.Errors += "TXT: $($_.Exception.Message)" }
    try {
        $dm = @(Resolve-DnsName -Name "_dmarc.$key" -Type TXT -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'TXT' } | ForEach-Object { $_.Strings -join '' })
        $info.DMARC = ($dm | Where-Object { $_ -match '^v=DMARC1' }) -join ' || '
        if ($info.DMARC -match '\bp=(\w+)') { $info.DMARCPolicy = $matches[1] }
    } catch { }
    $script:Cache.Dns[$key] = $info
    return $info
}

function Get-SpfRecordAssessment {
    param([string]$Spf, [string]$Domain)
    $findings = New-Object 'System.Collections.Generic.List[psobject]'
    if (-not $Spf) {
        $findings.Add([pscustomobject]@{ Severity = 'Warning'; Finding = "Sender domain '$Domain' publishes no SPF record."; Evidence = 'TXT lookup'; Recommendation = 'Publish v=spf1 including all legitimate sending services.' })
    } elseif ($Spf -match '\|\|') {
        $findings.Add([pscustomobject]@{ Severity = 'Critical'; Finding = "Sender domain '$Domain' publishes MULTIPLE SPF records (SPF permerror)."; Evidence = $Spf; Recommendation = 'Merge into a single v=spf1 record.' })
    } elseif ($Spf -match '(?i)\+all(\s|$)') {
        $findings.Add([pscustomobject]@{ Severity = 'Warning'; Finding = "Sender domain SPF ends with +all (allows anyone)."; Evidence = $Spf; Recommendation = 'Use -all or ~all.' })
    }
    return ,$findings.ToArray()
}

function Get-QuarantineInfo {
    param($Msg)
    if (-not $Msg.MessageId) { return $null }
    $key = $Msg.MessageId.ToLowerInvariant()
    if ($script:Cache.Quarantine.ContainsKey($key)) { return $script:Cache.Quarantine[$key] }
    if (-not (Get-Command -Name Get-QuarantineMessage -ErrorAction SilentlyContinue)) {
        $res = 'Quarantine lookup unavailable (Security & Compliance session not connected).'
        $script:Cache.Quarantine[$key] = $res
        return $res
    }
    $res = $null
    try {
        $q = Invoke-ExoCommand -Command 'Get-QuarantineMessage' -Parameters @{ MessageId = $Msg.MessageId }
        $res = @($q | ForEach-Object {
            [pscustomobject][ordered]@{
                Identity = [string](Get-PropValue $_ 'Identity'); ReceivedTime = Get-PropValue $_ 'ReceivedTime'
                Type = [string](Get-PropValue $_ 'Type'); QuarantineTypes = [string](Get-PropValue $_ 'QuarantineTypes')
                PolicyType = [string](Get-PropValue $_ 'PolicyType'); PolicyName = [string](Get-PropValue $_ 'PolicyName')
                ReleaseStatus = [string](Get-PropValue $_ 'ReleaseStatus'); Expires = Get-PropValue $_ 'Expires'
                RecipientAddress = ((Get-PropValue $_ 'RecipientAddress') -join ', '); Direction = [string](Get-PropValue $_ 'Direction')
            }
        })
    } catch { $res = "Lookup failed: $($_.Exception.Message)" }
    $script:Cache.Quarantine[$key] = $res
    return $res
}

function Get-RecipientInfo {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return [pscustomobject]@{ Found = $false; Error = 'Empty recipient address.' } }
    $key = $Address.ToLowerInvariant()
    if ($script:Cache.Recipient.ContainsKey($key)) { return $script:Cache.Recipient[$key] }
    $res = $null
    try {
        $cmd = if (Get-Command Get-EXORecipient -ErrorAction SilentlyContinue) { 'Get-EXORecipient' } else { 'Get-Recipient' }
        $r = Invoke-ExoCommand -Command $cmd -Parameters @{ Identity = $Address } | Select-Object -First 1
        if ($r) {
            $res = [pscustomobject][ordered]@{
                Found = $true; DisplayName = [string](Get-PropValue $r 'DisplayName'); RecipientTypeDetails = [string](Get-PropValue $r 'RecipientTypeDetails')
                PrimarySmtpAddress = [string](Get-PropValue $r 'PrimarySmtpAddress'); ExternalEmailAddress = [string](Get-PropValue $r 'ExternalEmailAddress')
                HiddenFromAddressListsEnabled = Get-PropValue $r 'HiddenFromAddressListsEnabled'
            }
        }
    } catch {
        if ($_.Exception.Message -match "couldn't be found|not found|ManagementObjectNotFound|doesn't exist") {
            $res = [pscustomobject]@{ Found = $false; Error = $_.Exception.Message }
        } else {
            $res = [pscustomobject]@{ Found = $null; Error = $_.Exception.Message }
        }
    }
    if (-not $res) { $res = [pscustomobject]@{ Found = $false; Error = 'No recipient returned.' } }
    $script:Cache.Recipient[$key] = $res
    return $res
}

function ConvertTo-Bytes {
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = [string]$Value
    if ($s -match 'Unlimited') { return [double]::PositiveInfinity }
    $m = [regex]::Match($s, '\(([\d,\.]+)\s*bytes\)')
    if ($m.Success) { return [double]($m.Groups[1].Value -replace '[,\.]', '') }
    return $null
}

function Get-MailboxInfo {
    param([string]$Address)
    $key = $Address.ToLowerInvariant()
    if ($script:Cache.Mailbox.ContainsKey($key)) { return $script:Cache.Mailbox[$key] }
    $res = [ordered]@{}
    try {
        $safeProps = @(
            'ForwardingSmtpAddress','ForwardingAddress','DeliverToMailboxAndForward','ProhibitSendReceiveQuota',
            'ProhibitSendQuota','RecipientTypeDetails','RequireSenderAuthenticationEnabled','MaxReceiveSize',
            'MaxSendSize','IsInactiveMailbox'
        )
        $cmd = $null
        if (Get-Command Get-EXOMailbox -ErrorAction SilentlyContinue) { $cmd = 'Get-EXOMailbox' }
        elseif (Get-Command Get-Mailbox -ErrorAction SilentlyContinue) { $cmd = 'Get-Mailbox' }
        else { throw 'Neither Get-EXOMailbox nor Get-Mailbox is available.' }
        $params = @{ Identity = $Address }
        if ($cmd -eq 'Get-EXOMailbox') { $params.Properties = $safeProps }
        $mbx = Invoke-ExoCommand -Command $cmd -Parameters $params | Select-Object -First 1
        if ($mbx) {
            foreach ($n in $safeProps) { $res[$n] = [string](Get-PropValue $mbx $n) }
            $res['AcceptMessagesOnlyFrom'] = ((Get-PropValue $mbx 'AcceptMessagesOnlyFrom') -join ', ')
            $res['RejectMessagesFrom'] = ((Get-PropValue $mbx 'RejectMessagesFrom') -join ', ')
            if (-not $res['AcceptMessagesOnlyFrom'] -and -not $res['RejectMessagesFrom'] -and (Get-Command Get-Mailbox -ErrorAction SilentlyContinue)) {
                try {
                    $full = Invoke-ExoCommand -Command 'Get-Mailbox' -Parameters @{ Identity = $Address } | Select-Object -First 1
                    if ($full) {
                        $res['AcceptMessagesOnlyFrom'] = ((Get-PropValue $full 'AcceptMessagesOnlyFrom') -join ', ')
                        $res['RejectMessagesFrom'] = ((Get-PropValue $full 'RejectMessagesFrom') -join ', ')
                    }
                } catch { $res['RestrictionLookupError'] = $_.Exception.Message }
            }
            try {
                $statCmd = if (Get-Command Get-EXOMailboxStatistics -ErrorAction SilentlyContinue) { 'Get-EXOMailboxStatistics' } else { 'Get-MailboxStatistics' }
                $st = Invoke-ExoCommand -Command $statCmd -Parameters @{ Identity = $Address } | Select-Object -First 1
                $res['TotalItemSize'] = [string](Get-PropValue $st 'TotalItemSize')
                $res['ItemCount'] = Get-PropValue $st 'ItemCount'
                $used = ConvertTo-Bytes (Get-PropValue $st 'TotalItemSize')
                $quota = ConvertTo-Bytes (Get-PropValue $mbx 'ProhibitSendReceiveQuota')
                if ($null -ne $used -and $null -ne $quota -and -not [double]::IsInfinity($quota) -and $quota -gt 0) {
                    $res['QuotaUsedPercent'] = [math]::Round(($used / $quota) * 100, 1)
                }
            } catch { $res['StatisticsError'] = $_.Exception.Message }
        }
    } catch { $res['Error'] = $_.Exception.Message }
    $script:Cache.Mailbox[$key] = $res
    return $res
}

function Get-GroupInfo {
    param([string]$Address, [string]$Type)
    $key = "$Type|$($Address.ToLowerInvariant())"
    if ($script:Cache.Group.ContainsKey($key)) { return $script:Cache.Group[$key] }
    $res = [ordered]@{}
    try {
        $cmd = if ($Type -eq 'GroupMailbox') { 'Get-UnifiedGroup' }
               elseif ($Type -eq 'DynamicDistributionGroup') { 'Get-DynamicDistributionGroup' }
               else { 'Get-DistributionGroup' }
        if (-not (Get-Command -Name $cmd -ErrorAction SilentlyContinue)) { throw "$cmd is not available." }
        $g = Invoke-ExoCommand -Command $cmd -Parameters @{ Identity = $Address } | Select-Object -First 1
        if ($g) {
            $res['RequireSenderAuthenticationEnabled'] = [string](Get-PropValue $g 'RequireSenderAuthenticationEnabled')
            $res['ModerationEnabled'] = [string](Get-PropValue $g 'ModerationEnabled')
            $res['ModeratedBy'] = ((Get-PropValue $g 'ModeratedBy') -join ', ')
            $res['AcceptMessagesOnlyFromSendersOrMembers'] = ((Get-PropValue $g 'AcceptMessagesOnlyFromSendersOrMembers') -join ', ')
            $res['RejectMessagesFromSendersOrMembers'] = ((Get-PropValue $g 'RejectMessagesFromSendersOrMembers') -join ', ')
            $res['MaxReceiveSize'] = [string](Get-PropValue $g 'MaxReceiveSize')
        }
    } catch { $res['Error'] = $_.Exception.Message }
    $script:Cache.Group[$key] = $res
    return $res
}

function Get-BlockedSenderInfo {
    param([string]$Address)
    $key = $Address.ToLowerInvariant()
    if ($script:Cache.Blocked.ContainsKey($key)) { return $script:Cache.Blocked[$key] }
    if (-not (Get-Command Get-BlockedSenderAddress -ErrorAction SilentlyContinue)) {
        $res = 'Get-BlockedSenderAddress is not available (Security & Compliance session required).'
        $script:Cache.Blocked[$key] = $res
        return $res
    }
    $res = $null
    try {
        $res = Invoke-ExoCommand -Command 'Get-BlockedSenderAddress' -Parameters @{ SenderAddress = $Address } |
            Select-Object SenderAddress, Reason, CreatedDatetime, ChangedDatetime
    } catch { $res = "Lookup failed: $($_.Exception.Message)" }
    $script:Cache.Blocked[$key] = $res
    return $res
}

function Test-RuleMatchesSender {
    param([string]$RuleFrom, [string]$SenderAddress)
    if ([string]::IsNullOrWhiteSpace($RuleFrom) -or [string]::IsNullOrWhiteSpace($SenderAddress)) { return $false }
    $sender = $SenderAddress.Trim().ToLowerInvariant()
    foreach ($part in ($RuleFrom -split ',')) {
        $token = $part.Trim().ToLowerInvariant()
        if (-not $token) { continue }
        $m = [regex]::Match($token, '<([^>]+)>')
        if ($m.Success) { $token = $m.Groups[1].Value.Trim().ToLowerInvariant() }
        if ($token -eq $sender) { return $true }
    }
    return $false
}

function Get-MailboxSideChecks {
    param([string]$Mailbox)
    $key = $Mailbox.ToLowerInvariant()
    $out = [ordered]@{ InboxRules = @(); Junk = $null; Errors = @() }
    if ($script:Cache.InboxRules.ContainsKey($key)) {
        $out.InboxRules = $script:Cache.InboxRules[$key]
    } else {
        try {
            $rules = Invoke-ExoCommand -Command 'Get-InboxRule' -Parameters @{ Mailbox = $Mailbox; IncludeHidden = $true }
            $out.InboxRules = @($rules | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name = [string](Get-PropValue $_ 'Name'); Enabled = Get-PropValue $_ 'Enabled'; Priority = Get-PropValue $_ 'Priority'
                    From = ((Get-PropValue $_ 'From') -join ', '); SubjectContainsWords = ((Get-PropValue $_ 'SubjectContainsWords') -join ', ')
                    SubjectOrBodyContainsWords = ((Get-PropValue $_ 'SubjectOrBodyContainsWords') -join ', ')
                    MoveToFolder = [string](Get-PropValue $_ 'MoveToFolder'); DeleteMessage = Get-PropValue $_ 'DeleteMessage'
                    SoftDeleteMessage = Get-PropValue $_ 'SoftDeleteMessage'; MarkAsRead = Get-PropValue $_ 'MarkAsRead'
                    ForwardTo = ((Get-PropValue $_ 'ForwardTo') -join ', '); RedirectTo = ((Get-PropValue $_ 'RedirectTo') -join ', ')
                    ForwardAsAttachmentTo = ((Get-PropValue $_ 'ForwardAsAttachmentTo') -join ', ')
                    StopProcessingRules = Get-PropValue $_ 'StopProcessingRules'; Description = [string](Get-PropValue $_ 'Description')
                }
            })
        } catch { $out.Errors += "Inbox rules: $($_.Exception.Message)" }
        $script:Cache.InboxRules[$key] = $out.InboxRules
    }
    if ($script:Cache.Junk.ContainsKey($key)) {
        $out.Junk = $script:Cache.Junk[$key]
    } else {
        try {
            $j = Invoke-ExoCommand -Command 'Get-MailboxJunkEmailConfiguration' -Parameters @{ Identity = $Mailbox } | Select-Object -First 1
            $out.Junk = [pscustomobject][ordered]@{
                Enabled = Get-PropValue $j 'Enabled'
                TrustedListsOnly = Get-PropValue $j 'TrustedListsOnly'
                ContactsTrusted = Get-PropValue $j 'ContactsTrusted'
                TrustedSendersAndDomains = @(Get-PropValue $j 'TrustedSendersAndDomains')
                BlockedSendersAndDomains = @(Get-PropValue $j 'BlockedSendersAndDomains')
            }
        } catch { $out.Errors += "Junk configuration: $($_.Exception.Message)" }
        $script:Cache.Junk[$key] = $out.Junk
    }
    return $out
}

function Invoke-MessageEnrichment {
    param($Msg)
    $problem = $Msg.Status -notin @('Delivered', 'Expanded')
    $allCodes = @($Msg.Events | ForEach-Object { $_.Codes } | Where-Object { $_ })
    $allText = ($Msg.Events | ForEach-Object { $_.AllText }) -join ' '

    if ($Msg.Status -in @('Quarantined', 'FilteredAsSpam') -or $allText -match 'quarantin') {
        $q = Get-QuarantineInfo $Msg
        $Msg.Enrichment['Quarantine'] = $q
        foreach ($item in @($q | Where-Object { $_ -isnot [string] -and $null -ne $_ })) {
            Add-Finding $Msg 'Warning' 'Quarantine' "Message is in quarantine: type '$($item.Type)', policy '$($item.PolicyName)' ($($item.PolicyType)), release status '$($item.ReleaseStatus)'." `
                "Expires $($item.Expires); Identity $($item.Identity)" 'Review and release in Defender portal > Quarantine (or Release-QuarantineMessage). If false positive, submit to Microsoft and adjust the policy.'
        }
    }

    if ($Msg.RecipientInternal -and ($problem -or ($allCodes -match '^[45]\.(1|2)\.'))) {
        $ri = Get-RecipientInfo $Msg.RecipientAddress
        $Msg.Enrichment['Recipient'] = $ri
        if ($ri.Found -eq $false) {
            Add-Finding $Msg 'Critical' 'Recipient' 'Recipient address does not exist in the directory.' $ri.Error 'Check spelling, whether the user was deleted, or add the address as a proxy address. In hybrid, confirm directory sync.'
        } elseif ($ri.Found) {
            $type = [string]$ri.RecipientTypeDetails
            if ($type -match 'Mailbox' -and $type -ne 'GroupMailbox') {
                $mi = Get-MailboxInfo $Msg.RecipientAddress
                $Msg.Enrichment['Mailbox'] = $mi
                if ($mi.Contains('QuotaUsedPercent') -and $mi['QuotaUsedPercent'] -ge 95) {
                    Add-Finding $Msg 'Critical' 'Quota' "Recipient mailbox is $($mi['QuotaUsedPercent'])% of ProhibitSendReceiveQuota." "$($mi['TotalItemSize']) of $($mi['ProhibitSendReceiveQuota'])" 'Free space, enable/expand archive, or raise the quota.'
                }
                if ($mi['ForwardingSmtpAddress'] -or $mi['ForwardingAddress']) {
                    Add-Finding $Msg 'Warning' 'Forwarding' "Mailbox forwarding is configured to '$($mi['ForwardingSmtpAddress'])$($mi['ForwardingAddress'])' (DeliverToMailboxAndForward=$($mi['DeliverToMailboxAndForward']))." 'Get-EXOMailbox forwarding properties' 'If external forwarding is blocked by the outbound spam policy, this produces 5.7.520 NDRs.'
                }
                if ($mi['RequireSenderAuthenticationEnabled'] -eq 'True' -and -not $Msg.SenderInternal) {
                    Add-Finding $Msg 'Critical' 'Restriction' 'Recipient mailbox only accepts mail from authenticated (internal) senders.' 'RequireSenderAuthenticationEnabled = True' 'Set-Mailbox -RequireSenderAuthenticationEnabled $false if external mail must be accepted.'
                }
                if ($mi['AcceptMessagesOnlyFrom'] -or $mi['RejectMessagesFrom']) {
                    Add-Finding $Msg 'Warning' 'Restriction' 'Recipient mailbox has delivery restrictions.' "AcceptOnlyFrom: $($mi['AcceptMessagesOnlyFrom']); RejectFrom: $($mi['RejectMessagesFrom'])" 'Review mailbox delivery management settings.'
                }
            } elseif ($type -match 'Group') {
                $gi = Get-GroupInfo -Address $Msg.RecipientAddress -Type $type
                $Msg.Enrichment['Group'] = $gi
                if ($gi['RequireSenderAuthenticationEnabled'] -eq 'True' -and -not $Msg.SenderInternal) {
                    Add-Finding $Msg 'Critical' 'Restriction' 'Group only accepts mail from internal (authenticated) senders.' 'RequireSenderAuthenticationEnabled = True' 'Allow external senders on the group if required.'
                }
                if ($gi['ModerationEnabled'] -eq 'True') {
                    Add-Finding $Msg 'Warning' 'Moderation' "Group is moderated (moderators: $($gi['ModeratedBy']))." 'ModerationEnabled = True' 'Messages wait for approval; rejected/expired approvals generate NDRs.'
                }
                if ($gi['AcceptMessagesOnlyFromSendersOrMembers']) {
                    Add-Finding $Msg 'Warning' 'Restriction' 'Group restricts who can send to it.' $gi['AcceptMessagesOnlyFromSendersOrMembers'] 'Add the sender to the allowed senders, or remove the restriction.'
                }
            } elseif ($type -match 'MailUser|MailContact' -and $ri.ExternalEmailAddress) {
                Add-Finding $Msg 'Info' 'Routing' "Recipient is a $type that routes to an external address ($($ri.ExternalEmailAddress))." 'Get-EXORecipient' 'Delivery depends on the external system; check the target domain.'
            }
        }
    }

    if ($script:Config.IncludeMailboxChecks -and $Msg.RecipientInternal -and $Msg.Status -in @('Delivered', 'FilteredAsSpam')) {
        $ri = Get-RecipientInfo $Msg.RecipientAddress
        if ($ri.Found -and [string]$ri.RecipientTypeDetails -match 'Mailbox' -and [string]$ri.RecipientTypeDetails -ne 'GroupMailbox') {
            $mc = Get-MailboxSideChecks $Msg.RecipientAddress
            $Msg.Enrichment['MailboxSide'] = $mc
            $senderLc = $Msg.SenderAddress.ToLowerInvariant()
            $senderDom = Get-DomainFromAddress $senderLc
            if ($mc.Junk) {
                $blocked = @($mc.Junk.BlockedSendersAndDomains | ForEach-Object { ([string]$_).ToLowerInvariant() })
                if ($blocked -contains $senderLc -or ($senderDom -and $blocked -contains $senderDom)) {
                    Add-Finding $Msg 'Critical' 'User junk settings' 'Sender (or sender domain) is in the recipient Blocked Senders list - message goes to Junk.' "BlockedSendersAndDomains contains $senderLc / $senderDom" 'Remove the entry from the user Blocked Senders list (Outlook > Junk > Junk Email Options).'
                }
                $trusted = @($mc.Junk.TrustedSendersAndDomains | ForEach-Object { ([string]$_).ToLowerInvariant() })
                if ($trusted -contains $senderLc -or ($senderDom -and $trusted -contains $senderDom)) {
                    Add-Finding $Msg 'Info' 'User junk settings' 'Sender is in the recipient Safe Senders list.' 'TrustedSendersAndDomains' 'Safe senders bypass spam filtering (SFV=SFE) but not high-confidence phish/malware.'
                }
                if ($mc.Junk.TrustedListsOnly) {
                    Add-Finding $Msg 'Warning' 'User junk settings' 'Recipient uses "Safe lists only" - everything not in Safe Senders goes to Junk.' 'TrustedListsOnly = True' 'Disable TrustedListsOnly or add the sender to Safe Senders.'
                }
            }
            foreach ($rule in @($mc.InboxRules | Where-Object { $_.Enabled })) {
                $actions = @()
                if ($rule.DeleteMessage) { $actions += 'DELETES message' }
                if ($rule.SoftDeleteMessage) { $actions += 'soft-deletes message' }
                if ($rule.MoveToFolder) { $actions += "moves to '$($rule.MoveToFolder)'" }
                if ($rule.MarkAsRead) { $actions += 'marks as read' }
                if ($rule.ForwardTo) { $actions += "forwards to $($rule.ForwardTo)" }
                if ($rule.RedirectTo) { $actions += "redirects to $($rule.RedirectTo)" }
                if ($rule.ForwardAsAttachmentTo) { $actions += "forwards as attachment to $($rule.ForwardAsAttachmentTo)" }
                if ($actions.Count -eq 0) { continue }
                $matchesSender = Test-RuleMatchesSender -RuleFrom $rule.From -SenderAddress $senderLc
                $matchesSubject = $false
                foreach ($w in (($rule.SubjectContainsWords + ',' + $rule.SubjectOrBodyContainsWords) -split ',')) {
                    if ($w.Trim() -and $Msg.Subject -and $Msg.Subject.IndexOf($w.Trim(), [StringComparison]::OrdinalIgnoreCase) -ge 0) { $matchesSubject = $true }
                }
                $sev = if ($matchesSender -or $matchesSubject) { 'Critical' } elseif ($rule.DeleteMessage -or $rule.RedirectTo -or $rule.ForwardTo) { 'Warning' } else { 'Info' }
                $why = if ($matchesSender) { ' - MATCHES this sender' } elseif ($matchesSubject) { ' - MATCHES this subject' } else { '' }
                Add-Finding $Msg $sev 'Inbox rule' "Inbox rule '$($rule.Name)' $($actions -join ', ')$why." $rule.Description 'Review/disable the rule (Get-InboxRule / Remove-InboxRule). Hidden rules can be created by attackers on compromised mailboxes.'
            }
        }
    }

    if ($Msg.SenderInternal -and ($allCodes -match '^5\.1\.8$|^5\.1\.90$|^5\.7\.501$|^5\.7\.70[0-9]$' -or $allText -match 'restricted|bad outbound sender')) {
        $b = Get-BlockedSenderInfo $Msg.SenderAddress
        $Msg.Enrichment['RestrictedSender'] = $b
        $blockedRows = @($b | Where-Object { $_ -isnot [string] -and $null -ne (Get-PropValue $_ 'SenderAddress') })
        if ($blockedRows.Count -gt 0) {
            Add-Finding $Msg 'Critical' 'Compromise' "Sender $($Msg.SenderAddress) is on the Restricted entities list (blocked from sending)." (($blockedRows | ForEach-Object { "$($_.Reason) since $($_.CreatedDatetime)" }) -join '; ') 'Investigate for compromise (sign-ins, inbox rules, OAuth apps), reset credentials, then Remove-BlockedSenderAddress.'
        }
    }

    if (@($script:Connectors).Count -gt 0) {
        $used = @($script:Connectors | Where-Object {
            ($_.Guid -and $allText.IndexOf([string]$_.Guid, [StringComparison]::OrdinalIgnoreCase) -ge 0) -or
            (Test-TextContainsToken -Text $allText -Token $_.Name)
        })
        if ($used.Count -gt 0) {
            $Msg.Enrichment['Connectors'] = $used
            foreach ($c in $used) {
                $sev = if ($problem) { 'Warning' } else { 'Info' }
                $evidence = "Smart hosts: $($c.SmartHosts); UseMX: $($c.UseMXRecord); TLS: $($c.TlsSettings) $($c.TlsDomain)$($c.TlsSenderCertificateName); Domains: $($c.RecipientDomains)$($c.SenderDomains); IPs: $($c.SenderIPAddresses); Enabled: $($c.Enabled)"
                Add-Finding $Msg $sev 'Connector' "$($c.Kind) connector '$($c.Name)' was used in the journey." $evidence 'Validate the connector (Validate connector in the EAC). For TLS errors compare TlsDomain/TlsCertificateName with the remote certificate.'
            }
        }
    }

    if (-not $script:Config.SkipDnsChecks) {
        $authCodes = $allCodes -match '^5\.7\.(1|23|25|26|509)$|^4\.7\.26$'
        $routingIssue = ($allCodes -match '^[45]\.4\.') -or ($allText -match 'DNS|MX record|no such domain')
        if (-not $Msg.RecipientInternal -and ($problem -or $routingIssue)) {
            $dns = Get-DomainDnsInfo (Get-DomainFromAddress $Msg.RecipientAddress)
            $Msg.Enrichment['RecipientDomainDns'] = $dns
            if ($dns -and @($dns.MX).Count -eq 0 -and -not $dns.A) {
                Add-Finding $Msg 'Critical' 'DNS' "Recipient domain '$($dns.Domain)' has no MX and no A record." (($dns.Errors) -join '; ') 'The domain cannot receive mail. Verify spelling or contact the recipient.'
            }
        }
        $verdictText = ($Msg.Events | ForEach-Object { ($_.Verdicts.Values) -join ' ' }) -join ' '
        if ($authCodes -or $Msg.Status -in @('FilteredAsSpam', 'Quarantined') -or $verdictText -match 'fail|SPOOF|PHSH') {
            $dns = Get-DomainDnsInfo (Get-DomainFromAddress $Msg.SenderAddress)
            $Msg.Enrichment['SenderDomainDns'] = $dns
            if ($dns) {
                foreach ($spfFinding in (Get-SpfRecordAssessment -Spf $dns.SPF -Domain $dns.Domain)) {
                    Add-Finding $Msg $spfFinding.Severity 'DNS' $spfFinding.Finding $spfFinding.Evidence $spfFinding.Recommendation
                }
                if (-not $dns.DMARC) {
                    Add-Finding $Msg 'Warning' 'DNS' "Sender domain '$($dns.Domain)' publishes no DMARC record." "_dmarc.$($dns.Domain)" 'Publish a DMARC record (start with p=none and rua reporting).'
                } else {
                    Add-Finding $Msg 'Info' 'DNS' "Sender domain DMARC policy p=$($dns.DMARCPolicy)." $dns.DMARC 'With p=reject/quarantine, unaligned mail is rejected/quarantined by receivers.'
                }
            }
        }
    }
}
#endregion

#region Root cause engine
function Invoke-RootCauseAnalysis {
    param($Msg)
    $nowUtc = (Get-Date).ToUniversalTime()
    $events = @($Msg.Events)
    $latencySeconds = Get-LatencyThresholdSeconds

    if ($events.Count -gt 0) {
        $first = ($events | Where-Object { $_.DateUtc } | Select-Object -First 1)
        $prev = $null
        foreach ($ev in $events) {
            if ($ev.DateUtc -and $first) { $ev.Elapsed = Format-Duration ($ev.DateUtc - $first.DateUtc).TotalSeconds }
            if ($ev.DateUtc -and $prev -and $prev.DateUtc) { $ev.GapSeconds = [math]::Round(($ev.DateUtc - $prev.DateUtc).TotalSeconds, 0) }
            if ($ev.DateUtc) { $prev = $ev }
        }
        $last = ($events | Where-Object { $_.DateUtc } | Select-Object -Last 1)
        if ($first -and $last) { $Msg.TotalTransit = Format-Duration ($last.DateUtc - $first.DateUtc).TotalSeconds }
    }

    switch ($Msg.Status) {
        'Delivered' {
            if ($Msg.Direction -eq 'Outbound' -or $Msg.Direction -eq 'Relay/External') {
                Add-Finding $Msg 'Info' 'Status' "Accepted by the external server $($Msg.ToIP)." 'Status Delivered on an outbound message = the remote server returned 250 OK.' 'If the recipient says it never arrived, the message is inside THEIR system (spam filter, quarantine, rules). Give them the Message-ID and the time to search their logs.'
            } else {
                Add-Finding $Msg 'Info' 'Status' 'Delivered to the recipient mailbox.' '' 'If the user cannot see it: check Junk, Quarantine, inbox rules (-IncludeMailboxChecks), Focused/Other, retention/ZAP, and mobile/Outlook filters. Search with Get-MessageTraceDetailV2 / Content Search for the Message-ID.'
            }
        }
        'Failed'        { Add-Finding $Msg 'Critical' 'Status' 'Delivery FAILED.' "Last event: $((@($events) | Select-Object -Last 1).Event)" 'See the decoded status codes and FAIL event below for the precise reason.' }
        'Pending' {
            $age = if ($Msg.ReceivedUtc) { ($nowUtc - $Msg.ReceivedUtc).TotalMinutes } else { 0 }
            $sev = if ($age -gt 60) { 'Warning' } else { 'Info' }
            Add-Finding $Msg $sev 'Status' "Delivery pending for $(Format-Duration ($age * 60))." 'Status Pending' 'The service is retrying. Exchange Online keeps retrying for up to roughly 24 hours before an expiry NDR (4.4.7 / 5.4.300). Read the DEFER events for the last error.'
        }
        'FilteredAsSpam' { Add-Finding $Msg 'Warning' 'Status' 'Message was filtered as spam (Junk folder or quarantine per policy).' 'Status FilteredAsSpam' 'See the anti-spam verdict findings for SFV/CAT/SCL/BCL.' }
        'Quarantined'    { Add-Finding $Msg 'Warning' 'Status' 'Message was quarantined.' 'Status Quarantined' 'See the Quarantine enrichment for the policy and release status.' }
        'Expanded'       { Add-Finding $Msg 'Info' 'Status' 'Distribution group expanded. Each member has its own trace row.' 'Status Expanded' 'Investigate the individual member rows (search by MessageTraceId).' }
        'GettingStatus'  { Add-Finding $Msg 'Info' 'Status' 'Status is still being calculated by the service.' 'Status GettingStatus' 'Re-run in a few minutes.' }
        default          { Add-Finding $Msg 'Info' 'Status' "Status is '$($Msg.Status)'." '' 'Review the journey events for the delivery outcome.' }
    }

    if (-not $Msg.DetailRetrieved) {
        $why = if ($Msg.DetailError) { $Msg.DetailError } elseif ($script:Config.SkipDetail) { 'Skipped (-SkipDetail).' } else { 'Not retrieved (MaxDetailLookups / ProblemsOnly).' }
        Add-Finding $Msg 'Info' 'Data' 'Journey detail events were not retrieved for this message.' $why 'Re-run targeting this MessageTraceId to get the full journey.'
        return
    }
    if ($events.Count -eq 0) {
        Add-Finding $Msg 'Info' 'Data' 'Trace detail returned no events.' '' 'Detail data can lag by up to a few hours, and is not available for some very old messages. Use -SubmitHistoricalSearch for the Extended report.'
    }

    $codesSeen = @{}
    foreach ($ev in $events) {
        foreach ($c in @($ev.Codes)) {
            if (-not $c -or $c.StartsWith('2') -or $codesSeen.ContainsKey($c)) { continue }
            $codesSeen[$c] = $true
            $info = Get-DsnInfo $c
            $isExpiry = $c -in @('4.4.7', '5.4.300', '5.4.316')
            $failed = ($ev.Event -match 'Fail|Drop|Reject') -or $Msg.Status -eq 'Failed'
            $sev = if ($isExpiry) { 'Warning' }
                   elseif ($failed -and ($c.StartsWith('5') -or $ev.Event -match 'Fail|Drop|Reject' -or ($ev.LastError -and $ev.LastError.Contains($c)))) { 'Critical' }
                   else { 'Warning' }
            $when = if ($ev.DateUtc) { '{0:yyyy-MM-dd HH:mm:ss}' -f $ev.DateUtc } else { '?' }
            $evidence = "[$($ev.Event) @ $when UTC] $($ev.Detail)"
            if ($ev.LastError) { $evidence += " | LastError: $($ev.LastError)" }
            Add-Finding $Msg $sev 'Status code' "$c - $($info.Meaning) Likely cause: $($info.Cause)" $evidence $info.Fix
        }
    }

    foreach ($ev in $events) {
        $n = [string]$ev.Event
        if ($n -match '^Drop') {
            Add-Finding $Msg 'Critical' 'Dropped' 'Message was DROPPED (silently discarded, no NDR to sender).' "$($ev.Detail)" 'Typical causes: malware with delete action, mail flow rule "Delete the message without notifying anyone", or high-confidence phish policy. Check the preceding events.'
        }
        if ($n -match 'Malware') {
            Add-Finding $Msg 'Critical' 'Threat' 'Anti-malware detected malicious content.' "$($ev.Detail)" 'Check Defender portal > Explorer / Quarantine. Submit as false positive if needed.'
        }
        if ($n -match '^Redirect') {
            Add-Finding $Msg 'Warning' 'Routing' 'Message was redirected to a different recipient.' "$($ev.Detail)" 'Look for a mail flow rule "Redirect the message to" or mailbox forwarding.'
        }
        if ($n -match '^Resolve') {
            Add-Finding $Msg 'Info' 'Routing' 'Recipient address was resolved to another address.' "$($ev.Detail)" 'Normal for aliases. Unexpected targets point to proxy address conflicts.'
        }
        if ($n -match 'Moderat|Approval') {
            Add-Finding $Msg 'Warning' 'Moderation' 'Message entered moderation.' "$($ev.Detail)" 'Ask the moderators to approve; moderation requests expire after 2 days by default.'
        }
        if ($n -match 'Poison|Bad ?mail') {
            Add-Finding $Msg 'Critical' 'Transport' 'Message could not be processed by transport (poison/badmail).' "$($ev.Detail)" 'Malformed content. Resend with a simpler format or open a Microsoft support case with the MessageTraceId.'
        }
        if ($n -match 'DLP') {
            Add-Finding $Msg 'Warning' 'DLP' 'A DLP policy matched this message.' "$($ev.Detail)" 'Review the DLP policy match in Purview (Activity explorer) - it may have blocked, encrypted or added a policy tip.'
        }
        if ($n -match 'Journal') {
            Add-Finding $Msg 'Info' 'Journal' 'A journal report was generated.' "$($ev.Detail)" ''
        }
        if ($n -match 'ZAP|Zero-hour') {
            Add-Finding $Msg 'Warning' 'Threat' 'Zero-hour auto purge acted after delivery (moved to Junk/quarantine).' "$($ev.Detail)" 'That explains "it arrived and then disappeared". Review in Defender > Explorer.'
        }

        foreach ($ag in @($ev.Agents)) {
            if ($ag.Agent -eq 'AMA' -and $ag.Values -and $ag.Values.Contains('action') -and $ag.Values['action']) {
                Add-Finding $Msg 'Critical' 'Threat' "Anti-malware agent action '$($ag.Values['action'])'." $ag.Raw 'Review the malware detection in Defender.'
            }
            if ($ag.Agent -eq 'DeliveryPriority' -and "$($ag.SubType)$($ag.Raw)" -match 'Low') {
                Add-Finding $Msg 'Warning' 'Reputation' 'Message was sent with Low delivery priority (possibly via the high risk delivery pool).' $ag.Raw 'Outbound mail judged risky (spam-like, high volume, or an unauthenticated domain). Recipients may junk/reject it. Review content and sender.'
            }
        }

        $isProblem = ($n -match 'Fail|Defer|Drop|Reject|Quarantin|Spam|Malware|Redirect|DLP|Moderat|Poison|Bad ?mail|Delay|Phish|ZAP|Zero-hour|Detonat|Block') -or (@($ev.Codes) | Where-Object { $_ -match '^[45]' })
        if ($isProblem) {
            foreach ($tp in $script:TextPatterns) {
                if ($ev.AllText -match $tp.Pattern) {
                    $snippet = [string]$ev.AllText
                    if ($snippet.Length -gt 400) { $snippet = $snippet.Substring(0, 400) + '...' }
                    Add-Finding $Msg $tp.Sev $tp.Category $tp.Finding "[$n] $snippet" $tp.Fix
                }
            }
        }
    }

    $defers = @($events | Where-Object { $_.Event -match '^Defer' })
    if ($defers.Count -gt 0) {
        $span = 'n/a'
        if ($defers.Count -gt 1 -and $defers[-1].DateUtc -and $defers[0].DateUtc) {
            $span = Format-Duration ($defers[-1].DateUtc - $defers[0].DateUtc).TotalSeconds
        }
        $lastDefer = $defers[-1]
        $reason = if ($lastDefer.LastError) { $lastDefer.LastError } else { $lastDefer.Detail }
        $distinct = @($defers | ForEach-Object { if ($_.LastError) { $_.LastError } else { $_.Detail } } | Select-Object -Unique)
        $sev = if ($Msg.Status -in @('Pending', 'Failed')) { 'Warning' } else { 'Info' }
        $tail = if ($Msg.Status -eq 'Delivered') { ' The message was eventually delivered - the deferrals explain the delay.' } else { '' }
        $spanText = if ($defers.Count -gt 1) { " over $span" } else { '' }
        Add-Finding $Msg $sev 'Deferral' "Delivery was deferred $($defers.Count) time(s)$spanText.$tail" "Last error: $reason | Distinct errors: $($distinct.Count)" 'The LastError text is the real root cause - remote response, DNS, TLS or connection errors. Compare with the decoded status codes.'
    }

    $verdicts = [ordered]@{}
    foreach ($ev in $events) { foreach ($k in @($ev.Verdicts.Keys)) { if (-not $verdicts.Contains($k)) { $verdicts[$k] = $ev.Verdicts[$k] } } }
    $Msg.Enrichment['AntiSpamVerdicts'] = $verdicts
    if ($verdicts.Contains('SFV')) {
        $sfv = ([string]$verdicts['SFV']).ToUpper()
        $text = if ($script:SfvKb.ContainsKey($sfv)) { $script:SfvKb[$sfv] } else { 'Unknown SFV value.' }
        $sev = if ($sfv -match '^(SPM|SKS|SKB|BLK)$') { 'Warning' } else { 'Info' }
        Add-Finding $Msg $sev 'Anti-spam' "Spam filter verdict SFV=$sfv - $text" (($verdicts.Keys | ForEach-Object { "$_=$($verdicts[$_])" }) -join '; ') 'SKB/SKS = your own policy or rule did this; BLK = the user Blocked Senders list; SPM = Microsoft filtering (submit false positives).'
    }
    if ($verdicts.Contains('CAT')) {
        $cat = ([string]$verdicts['CAT']).ToUpper()
        if ($cat -ne 'NONE') {
            $text = if ($script:CatKb.ContainsKey($cat)) { $script:CatKb[$cat] } else { $cat }
            Add-Finding $Msg 'Warning' 'Anti-spam' "Protection category CAT=$cat ($text)." '' 'The action taken comes from the policy configured for this category (anti-spam / anti-phish / anti-malware).'
        }
    }
    if ($verdicts.Contains('SCL')) {
        $scl = ConvertTo-IntSafe $verdicts['SCL']
        if ($null -ne $scl -and $scl -ge 5) { Add-Finding $Msg 'Warning' 'Anti-spam' "Spam Confidence Level SCL=$scl." 'SCL 5-6 = spam, 7-9 = high confidence spam.' 'If a mail flow rule set this SCL, the rule is the root cause (look for SFV=SKS).' }
        if ($null -ne $scl -and $scl -eq -1) { Add-Finding $Msg 'Info' 'Anti-spam' 'SCL=-1: spam filtering bypassed (mail flow rule, allow list or internal).' '' 'Bypass rules can let malicious mail in - make sure this is intended.' }
    }
    if ($verdicts.Contains('BCL')) {
        $bclValue = ConvertTo-IntSafe $verdicts['BCL']
        if ($null -ne $bclValue -and $bclValue -ge 6) {
            Add-Finding $Msg 'Warning' 'Anti-spam' "Bulk Complaint Level BCL=$bclValue." '' 'Adjust the bulk threshold in the anti-spam policy or allow the sender if this is wanted bulk mail.'
        }
    }
    if ($verdicts.Contains('compauth') -and $verdicts['compauth'] -match 'fail') {
        $r = [string](Get-PropValue $verdicts 'reason')
        $rt = Get-AuthReasonText $r
        Add-Finding $Msg 'Critical' 'Authentication' "Composite authentication failed (reason $r). $rt" '' 'Treated as spoofed. Fix SPF/DKIM/DMARC alignment at the sender, or create a spoof allow in the Tenant Allow/Block List.'
    }
    foreach ($k in @('spf', 'dkim', 'dmarc')) {
        if ($verdicts.Contains($k) -and $verdicts[$k] -match 'fail|permerror|temperror') {
            Add-Finding $Msg 'Warning' 'Authentication' "$($k.ToUpper())=$($verdicts[$k])." '' "Fix $($k.ToUpper()) for the sending domain."
        }
    }

    foreach ($ev in $events) {
        $isRuleEvent = ($ev.Event -match 'Transport rule|Mail flow rule') -or (@($ev.Agents) | Where-Object { $_.Agent -eq 'TRA' })
        if (-not $isRuleEvent) { continue }
        $guids = @([regex]::Matches([string]$ev.AllText, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') | ForEach-Object { $_.Value.ToLowerInvariant() } | Select-Object -Unique)
        $matched = @($script:TransportRules | Where-Object {
            ($guids -contains ([string]$_.Guid).ToLowerInvariant()) -or (Test-TextContainsToken -Text $ev.AllText -Token $_.Name)
        })
        $traActions = @($ev.Agents | Where-Object { $_.Agent -eq 'TRA' } | ForEach-Object { Get-PropValue $_.Values 'action' } | Where-Object { $_ })
        if ($matched.Count -gt 0) {
            foreach ($rule in $matched) {
                $desc = ([string]$rule.Description -replace '\s+', ' ').Trim()
                $sev = if ($desc -match 'reject|delete|redirect|quarantine|moderat|approval|block|spam confidence level|SCL|forward|bcc') { 'Warning' } else { 'Info' }
                Add-Finding $Msg $sev 'Mail flow rule' "Mail flow rule '$($rule.Name)' matched (priority $($rule.Priority), state $($rule.State), mode $($rule.Mode))." $desc 'If this rule caused the outcome, adjust its conditions/exceptions in EAC > Mail flow > Rules.'
            }
        } else {
            $idsText = if ($guids) { $guids -join ', ' } else { 'n/a' }
            Add-Finding $Msg 'Info' 'Mail flow rule' "A mail flow rule matched (rule id(s): $idsText; actions: $($traActions -join ', '))." $ev.AllText 'Run Get-TransportRule -Identity <id> to inspect the rule (it may have been deleted since).'
        }
    }

    for ($gi = 1; $gi -lt $events.Count; $gi++) {
        $g = $events[$gi]
        if (-not $g.GapSeconds -or $g.GapSeconds -le $latencySeconds) { continue }
        if ($g.Event -match '^Defer') { continue }
        $before = [string]$events[$gi - 1].Event
        if ($before -match '^Defer') { continue }
        $when = if ($g.DateUtc) { '{0:yyyy-MM-dd HH:mm:ss}' -f $g.DateUtc } else { '?' }
        Add-Finding $Msg 'Warning' 'Latency' "Gap of $(Format-Duration $g.GapSeconds) between '$before' and '$($g.Event)'." "$when UTC" 'Long gaps before Deliver usually mean mailbox-side delays, Safe Attachments detonation, moderation, or retries without explicit DEFER events.'
    }

    $sendExt = @($events | Where-Object { $_.Event -match 'Send external' }) | Select-Object -Last 1
    if ($sendExt) { $Msg.Enrichment['ExternalHandoff'] = "$($sendExt.Detail)" }
}

function Set-PrimaryCause {
    param($Msg)
    $best = $null
    $bestRank = -1
    foreach ($f in @($Msg.Findings)) {
        $base = $script:SeverityRank[$f.Severity]
        if ($null -eq $base) { $base = 0 }
        $rank = $base * 10
        $generic = $f.Category -in @('Status', 'Data') -and $f.Finding -match '^(Delivery FAILED|Delivered to the recipient mailbox|Accepted by the external|Delivery pending|Message was filtered as spam|Message was quarantined|Distribution group expanded|Status is still being calculated|Journey detail|Trace detail returned|Status is )'
        if ($generic) { $rank -= 10 }
        elseif ($f.Category -notin @('Status', 'Data', 'DNS', 'Connector')) { $rank += 2 }
        elseif ($f.Category -ne 'Status' -and $f.Category -ne 'Data') { $rank += 1 }
        if ($rank -gt $bestRank) { $best = $f; $bestRank = $rank }
    }
    $Msg.PrimaryCause = $best
}
#endregion

#region Reporting
function Export-RowsCsv {
    param($Rows, [string]$Path)
    $data = @($Rows)
    if ($data.Count -eq 0) {
        $utf8Bom = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($Path, '', $utf8Bom)
        return
    }
    $data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function Export-InvestigationCsv {
    param([object[]]$Messages, [string]$Folder)
    $messageRows = @(foreach ($m in @($Messages)) {
        [pscustomobject][ordered]@{
            ReceivedUtc = $m.ReceivedUtc
            Status = ConvertTo-CsvSafe $m.Status
            Direction = ConvertTo-CsvSafe $m.Direction
            Sender = ConvertTo-CsvSafe $m.SenderAddress
            Recipient = ConvertTo-CsvSafe $m.RecipientAddress
            Subject = ConvertTo-CsvSafe $m.Subject
            FromIP = ConvertTo-CsvSafe $m.FromIP
            ToIP = ConvertTo-CsvSafe $m.ToIP
            Size = $m.Size
            TotalTransit = ConvertTo-CsvSafe $m.TotalTransit
            EventCount = @($m.Events).Count
            Critical = @($m.Findings | Where-Object Severity -eq 'Critical').Count
            Warning = @($m.Findings | Where-Object Severity -eq 'Warning').Count
            PrimaryCategory = if ($m.PrimaryCause) { ConvertTo-CsvSafe $m.PrimaryCause.Category } else { '' }
            PrimaryCause = if ($m.PrimaryCause) { ConvertTo-CsvSafe $m.PrimaryCause.Finding } else { '' }
            Recommendation = if ($m.PrimaryCause) { ConvertTo-CsvSafe $m.PrimaryCause.Recommendation } else { '' }
            MessageId = ConvertTo-CsvSafe $m.MessageId
            MessageTraceId = ConvertTo-CsvSafe $m.MessageTraceId
            Source = ConvertTo-CsvSafe $m.Source
        }
    })
    Export-RowsCsv -Rows $messageRows -Path (Join-Path $Folder 'Messages.csv')

    $eventRows = @(foreach ($m in @($Messages)) {
        foreach ($e in @($m.Events)) {
            [pscustomobject][ordered]@{
                MessageTraceId = ConvertTo-CsvSafe $m.MessageTraceId
                Recipient = ConvertTo-CsvSafe $m.RecipientAddress
                Subject = ConvertTo-CsvSafe $m.Subject
                DateUtc = $e.DateUtc
                Elapsed = ConvertTo-CsvSafe $e.Elapsed
                GapSeconds = $e.GapSeconds
                Event = ConvertTo-CsvSafe $e.Event
                Action = ConvertTo-CsvSafe $e.Action
                Detail = ConvertTo-CsvSafe $e.Detail
                Explanation = ConvertTo-CsvSafe $e.Explanation
                Codes = ConvertTo-CsvSafe (($e.Codes -join ', '))
                LastError = ConvertTo-CsvSafe $e.LastError
                Verdicts = ConvertTo-CsvSafe (($e.Verdicts.Keys | ForEach-Object { "$_=$($e.Verdicts[$_])" }) -join '; ')
                Agents = ConvertTo-CsvSafe (($e.Agents | ForEach-Object { $_.Raw }) -join ' ;; ')
                Data = ConvertTo-CsvSafe (($e.Data.Keys | ForEach-Object { "$_=$($e.Data[$_])" }) -join ' | ')
            }
        }
    })
    Export-RowsCsv -Rows $eventRows -Path (Join-Path $Folder 'Events.csv')

    $findingRows = @(foreach ($m in @($Messages)) {
        foreach ($f in @($m.Findings)) {
            [pscustomobject][ordered]@{
                MessageTraceId = ConvertTo-CsvSafe $f.MessageTraceId
                Recipient = ConvertTo-CsvSafe $f.Recipient
                Severity = ConvertTo-CsvSafe $f.Severity
                Category = ConvertTo-CsvSafe $f.Category
                Finding = ConvertTo-CsvSafe $f.Finding
                Evidence = ConvertTo-CsvSafe $f.Evidence
                Recommendation = ConvertTo-CsvSafe $f.Recommendation
            }
        }
    })
    Export-RowsCsv -Rows $findingRows -Path (Join-Path $Folder 'Findings.csv')
}

function ConvertTo-HtmlKeyValue {
    param($Object, [int]$Depth = 0)
    if ($null -eq $Object) { return '<span class="muted">none</span>' }
    if ($Depth -gt 6) { return '<span class="muted">nested value omitted</span>' }
    if ($Object -is [string]) { return '<span>' + (ConvertTo-HtmlSafe $Object) + '</span>' }
    $sb = New-Object System.Text.StringBuilder
    $items = @($Object)
    foreach ($item in $items) {
        if ($null -eq $item) { continue }
        if ($item -is [string]) {
            [void]$sb.Append('<div>' + (ConvertTo-HtmlSafe $item) + '</div>')
            continue
        }
        [void]$sb.Append('<table class="kv">')
        $pairs = if ($item -is [System.Collections.IDictionary]) {
            @($item.Keys | ForEach-Object { @{ K = $_; V = $item[$_] } })
        } else {
            @($item.PSObject.Properties | ForEach-Object { @{ K = $_.Name; V = $_.Value } })
        }
        foreach ($p in $pairs) {
            $v = $p.V
            if ($null -eq $v) { $vHtml = '<span class="muted">none</span>' }
            elseif ($v -is [System.Collections.IDictionary] -or ($v -is [System.Management.Automation.PSCustomObject])) { $vHtml = ConvertTo-HtmlKeyValue $v ($Depth + 1) }
            elseif ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
                $arr = @($v)
                if ($arr.Count -gt 0 -and ($null -ne $arr[0]) -and ($arr[0] -is [System.Management.Automation.PSCustomObject] -or $arr[0] -is [System.Collections.IDictionary])) {
                    $vHtml = ConvertTo-HtmlKeyValue $arr ($Depth + 1)
                } else { $vHtml = ConvertTo-HtmlSafe (($arr | ForEach-Object { [string]$_ }) -join ', ') }
            } else { $vHtml = ConvertTo-HtmlSafe ([string]$v) }
            [void]$sb.Append("<tr><th>$(ConvertTo-HtmlSafe $p.K)</th><td>$vHtml</td></tr>")
        }
        [void]$sb.Append('</table>')
    }
    if ($sb.Length -eq 0) { return '<span class="muted">none</span>' }
    return $sb.ToString()
}

function ConvertTo-FindingsTable {
    param([object[]]$Findings)
    if (-not $Findings -or @($Findings).Count -eq 0) { return '<p class="muted">No findings.</p>' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table class="grid"><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>')
    foreach ($f in ($Findings | Sort-Object @{ Expression = { $script:SeverityRank[$_.Severity] }; Descending = $true })) {
        [void]$sb.Append(('<tr class="sev-{0}"><td><span class="pill {0}">{0}</span></td><td>{1}</td><td>{2}</td><td class="mono small">{3}</td><td>{4}</td></tr>' -f
            $f.Severity, (ConvertTo-HtmlSafe $f.Category), (ConvertTo-HtmlSafe $f.Finding), (ConvertTo-HtmlSafe $f.Evidence), (ConvertTo-HtmlSafe $f.Recommendation)))
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function Export-HtmlReport {
    param([object[]]$Messages, $HeaderResult, [string]$Path, [string]$HistoricalJob)
    $latencySeconds = Get-LatencyThresholdSeconds
    $css = @'
:root{--bg:#f6f7f9;--card:#fff;--fg:#1f2328;--muted:#656d76;--line:#d0d7de;--crit:#b42318;--warn:#b54708;--info:#175cd3;--ok:#067647}
*{box-sizing:border-box}body{font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px;font-size:14px;line-height:1.45}
h1{margin:0 0 4px;font-size:22px}h2{font-size:17px;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}h4{margin:16px 0 6px;font-size:14px}
.muted{color:var(--muted)}.small{font-size:12px}.mono{font-family:Consolas,monospace}
.cards{display:flex;flex-wrap:wrap;gap:12px}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;min-width:140px}
.card .n{font-size:24px;font-weight:600}
table{border-collapse:collapse;width:100%;background:var(--card)}
table.grid th,table.grid td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
table.grid th{background:#eef1f4;font-weight:600}
table.kv{width:auto;margin:2px 0}table.kv th{text-align:left;color:var(--muted);font-weight:500;padding:2px 10px 2px 0;vertical-align:top;white-space:nowrap}table.kv td{padding:2px 0;word-break:break-word}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;color:#fff}
.Critical{background:var(--crit)}.Warning{background:var(--warn)}.Info{background:var(--info)}
.st{display:inline-block;padding:1px 8px;border-radius:4px;font-size:12px;font-weight:600;border:1px solid}
.st-Delivered{color:var(--ok);border-color:var(--ok)}.st-Failed{color:var(--crit);border-color:var(--crit)}
.st-Pending,.st-FilteredAsSpam,.st-Quarantined{color:var(--warn);border-color:var(--warn)}.st-Expanded,.st-GettingStatus,.st-Unknown{color:var(--info);border-color:var(--info)}
details.msg{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--info);border-radius:6px;margin:10px 0;padding:0 14px}
details.msg.sev-Critical{border-left-color:var(--crit)}details.msg.sev-Warning{border-left-color:var(--warn)}
details.msg>summary{cursor:pointer;padding:10px 0;list-style:none}details.msg>summary::-webkit-details-marker{display:none}
details.msg>summary .meta{color:var(--muted);font-size:12px;margin-top:2px}
.root{border:1px solid var(--line);border-radius:6px;padding:10px 12px;background:#fbfbfc}
.root.Critical{border-color:var(--crit);background:#fef3f2}.root.Warning{border-color:var(--warn);background:#fffaeb}
ol.timeline{list-style:none;margin:0;padding:0 0 0 18px;border-left:2px solid var(--line)}
ol.timeline li{position:relative;margin:0 0 12px;padding-left:12px}
ol.timeline li:before{content:"";position:absolute;left:-26px;top:5px;width:12px;height:12px;border-radius:50%;background:var(--info);border:2px solid #fff}
ol.timeline li.ev-Critical:before{background:var(--crit)}ol.timeline li.ev-Warning:before{background:var(--warn)}
.evh{font-weight:600}.gap{color:var(--warn);font-weight:600}.code{background:#eef1f4;border-radius:4px;padding:0 5px;font-family:Consolas,monospace;font-size:12px;margin-right:4px}
details.data summary{cursor:pointer;color:var(--info);font-size:12px}
input#q{padding:6px 10px;border:1px solid var(--line);border-radius:6px;width:320px;max-width:100%}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:8px 0}
'@
    $js = @'
function filt(){var q=document.getElementById("q").value.toLowerCase();var s=document.getElementById("sev").value;
document.querySelectorAll("details.msg").forEach(function(d){var t=d.textContent.toLowerCase();var okQ=!q||t.indexOf(q)>-1;var okS=!s||d.classList.contains("sev-"+s);d.style.display=(okQ&&okS)?"":"none";});}
function exp(o){document.querySelectorAll("details.msg").forEach(function(d){if(d.style.display!=="none"){d.open=o;}});}
'@
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<!DOCTYPE html><html lang=""en""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width,initial-scale=1""><title>Mail Flow Investigation</title><style>$css</style><script>$js</script></head><body>")
    [void]$sb.Append('<h1>Microsoft 365 Mail Flow Investigation</h1>')
    [void]$sb.Append("<div class=""muted"">Generated $(ConvertTo-HtmlSafe (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')) on $(ConvertTo-HtmlSafe $env:COMPUTERNAME) &middot; script v$script:ScriptVersion &middot; all times UTC</div>")

    $paramText = ($script:BoundParams.Keys | Where-Object { $_ -notmatch 'Certificate|Thumbprint' } | ForEach-Object { "-$_ $(@($script:BoundParams[$_]) -join ',')" }) -join '  '
    [void]$sb.Append("<p class=""small mono"">$(ConvertTo-HtmlSafe $paramText)</p>")

    $all = @($Messages)
    $findings = @($all | ForEach-Object { $_.Findings })
    [void]$sb.Append('<h2>Overview</h2><div class="cards">')
    [void]$sb.Append("<div class=""card""><div class=""n"">$($all.Count)</div><div class=""muted"">message/recipient rows</div></div>")
    foreach ($g in @($all | Group-Object Status | Sort-Object Count -Descending)) {
        [void]$sb.Append("<div class=""card""><div class=""n"">$($g.Count)</div><div><span class=""st st-$(ConvertTo-HtmlSafe $g.Name)"">$(ConvertTo-HtmlSafe $g.Name)</span></div></div>")
    }
    foreach ($s in @('Critical', 'Warning')) {
        $c = @($findings | Where-Object Severity -eq $s).Count
        [void]$sb.Append("<div class=""card""><div class=""n"">$c</div><div><span class=""pill $s"">$s findings</span></div></div>")
    }
    [void]$sb.Append('</div>')

    $codes = @($all | ForEach-Object { $_.Events } | ForEach-Object { $_.Codes } | Where-Object { $_ -match '^[45]' })
    $problemMsgs = @($all | Where-Object { $_.Status -notin @('Delivered', 'Expanded') })
    [void]$sb.Append('<h2>Patterns</h2><div class="cards">')
    [void]$sb.Append('<div class="card"><h4>Top status codes</h4>')
    if ($codes.Count) {
        foreach ($g in ($codes | Group-Object | Sort-Object Count -Descending | Select-Object -First 10)) {
            [void]$sb.Append("<div><span class=""code"">$(ConvertTo-HtmlSafe $g.Name)</span> x$($g.Count) <span class=""muted small"">$(ConvertTo-HtmlSafe (Get-DsnInfo $g.Name).Meaning)</span></div>")
        }
    } else { [void]$sb.Append('<div class="muted">none</div>') }
    [void]$sb.Append('</div><div class="card"><h4>Top root-cause categories</h4>')
    $cats = @($all | Where-Object { $_.PrimaryCause -and $_.PrimaryCause.Severity -ne 'Info' } | ForEach-Object { $_.PrimaryCause.Category })
    if ($cats.Count) {
        foreach ($g in ($cats | Group-Object | Sort-Object Count -Descending | Select-Object -First 10)) {
            [void]$sb.Append("<div>$(ConvertTo-HtmlSafe $g.Name) x$($g.Count)</div>")
        }
    } else { [void]$sb.Append('<div class="muted">none</div>') }
    [void]$sb.Append('</div><div class="card"><h4>Problem recipient domains</h4>')
    if ($problemMsgs.Count) {
        foreach ($g in ($problemMsgs | Group-Object { Get-DomainFromAddress $_.RecipientAddress } | Sort-Object Count -Descending | Select-Object -First 10)) {
            [void]$sb.Append("<div>$(ConvertTo-HtmlSafe $g.Name) x$($g.Count)</div>")
        }
    } else { [void]$sb.Append('<div class="muted">none</div>') }
    [void]$sb.Append('</div><div class="card"><h4>Problem source IPs</h4>')
    $ips = @($problemMsgs | Where-Object { $_.FromIP })
    if ($ips.Count) {
        foreach ($g in ($ips | Group-Object FromIP | Sort-Object Count -Descending | Select-Object -First 10)) {
            [void]$sb.Append("<div class=""mono"">$(ConvertTo-HtmlSafe $g.Name) x$($g.Count)</div>")
        }
    } else { [void]$sb.Append('<div class="muted">none</div>') }
    [void]$sb.Append('</div></div>')

    if ($HistoricalJob) {
        [void]$sb.Append("<h2>Historical search</h2><p>$(ConvertTo-HtmlSafe $HistoricalJob)</p>")
    }

    if ($HeaderResult) {
        [void]$sb.Append('<h2>Message header analysis</h2>')
        [void]$sb.Append('<div class="cards"><div class="card"><h4>Summary</h4>' + (ConvertTo-HtmlKeyValue $HeaderResult.Summary) + '</div>')
        [void]$sb.Append('<div class="card"><h4>Authentication</h4>' + (ConvertTo-HtmlKeyValue $HeaderResult.Auth) + '</div>')
        [void]$sb.Append('<div class="card"><h4>Anti-spam stamps</h4>' + (ConvertTo-HtmlKeyValue $HeaderResult.AntiSpam) + '</div></div>')
        [void]$sb.Append('<h4>Findings</h4>' + (ConvertTo-FindingsTable $HeaderResult.Findings))
        [void]$sb.Append('<h4>Received chain (oldest first)</h4><table class="grid"><thead><tr><th>#</th><th>Time (UTC)</th><th>Delay</th><th>From</th><th>By</th><th>With</th><th>TLS</th></tr></thead><tbody>')
        foreach ($h in @($HeaderResult.Hops)) {
            $delayCls = if ($h.DelaySeconds -gt $latencySeconds) { ' class="gap"' } else { '' }
            $t = if ($h.TimeUtc) { '{0:yyyy-MM-dd HH:mm:ss}' -f $h.TimeUtc } else { '?' }
            $tlsCell = if ($h.Encrypted) { 'yes' } else { '<span class="gap">no</span>' }
            [void]$sb.Append("<tr><td>$($h.Hop)</td><td class=""mono"">$t</td><td$delayCls>$(ConvertTo-HtmlSafe $h.Delay)</td><td class=""small"">$(ConvertTo-HtmlSafe $h.From)</td><td class=""small"">$(ConvertTo-HtmlSafe $h.By)</td><td class=""small"">$(ConvertTo-HtmlSafe $h.With)</td><td>$tlsCell</td></tr>")
        }
        [void]$sb.Append('</tbody></table>')
    }

    [void]$sb.Append('<h2>Messages</h2><div class="toolbar"><input id="q" type="search" placeholder="Filter by address, subject, code..." oninput="filt()" aria-label="Filter messages"><select id="sev" onchange="filt()" aria-label="Filter by severity"><option value="">All severities</option><option>Critical</option><option>Warning</option><option>Info</option></select><button type="button" onclick="exp(true)">Expand all</button><button type="button" onclick="exp(false)">Collapse all</button></div>')

    $sorted = @($all | Sort-Object @{ Expression = { if ($_.PrimaryCause) { $script:SeverityRank[$_.PrimaryCause.Severity] } else { 0 } }; Descending = $true }, @{ Expression = { $_.ReceivedUtc }; Descending = $true })
    foreach ($m in $sorted) {
        $topSev = if ($m.PrimaryCause) { $m.PrimaryCause.Severity } else { 'Info' }
        $open = if ($topSev -eq 'Critical' -and $all.Count -le 25) { ' open' } else { '' }
        $recv = if ($m.ReceivedUtc) { '{0:yyyy-MM-dd HH:mm:ss}' -f $m.ReceivedUtc } else { '?' }
        [void]$sb.Append("<details class=""msg sev-$topSev""$open><summary><span class=""st st-$(ConvertTo-HtmlSafe $m.Status)"">$(ConvertTo-HtmlSafe $m.Status)</span> <strong>$(ConvertTo-HtmlSafe $m.Subject)</strong>")
        [void]$sb.Append("<div class=""meta"">$recv UTC &middot; $(ConvertTo-HtmlSafe $m.SenderAddress) &rarr; $(ConvertTo-HtmlSafe $m.RecipientAddress) &middot; $(ConvertTo-HtmlSafe $m.Direction) &middot; $(@($m.Events).Count) events")
        if ($m.PrimaryCause -and $m.PrimaryCause.Severity -ne 'Info') { [void]$sb.Append(" &middot; <span class=""pill $topSev"">$(ConvertTo-HtmlSafe $m.PrimaryCause.Category)</span>") }
        [void]$sb.Append('</div></summary>')

        if ($m.PrimaryCause) {
            [void]$sb.Append("<h4>Most likely root cause</h4><div class=""root $topSev""><div><strong>$(ConvertTo-HtmlSafe $m.PrimaryCause.Finding)</strong></div>")
            if ($m.PrimaryCause.Evidence) { [void]$sb.Append("<div class=""small mono muted"">$(ConvertTo-HtmlSafe $m.PrimaryCause.Evidence)</div>") }
            if ($m.PrimaryCause.Recommendation) { [void]$sb.Append("<div style=""margin-top:6px""><strong>Action:</strong> $(ConvertTo-HtmlSafe $m.PrimaryCause.Recommendation)</div>") }
            [void]$sb.Append('</div>')
        }

        $props = [ordered]@{
            'Received (UTC)' = $recv; Sender = $m.SenderAddress; Recipient = $m.RecipientAddress; Subject = $m.Subject
            Status = $m.Status; Direction = $m.Direction; 'From IP' = $m.FromIP; 'To IP' = $m.ToIP; Size = $m.Size
            'Total transit' = $m.TotalTransit; 'Message-ID' = $m.MessageId; 'MessageTraceId (Network Message ID)' = $m.MessageTraceId; Source = $m.Source
        }
        [void]$sb.Append('<h4>Message</h4>' + (ConvertTo-HtmlKeyValue $props))
        [void]$sb.Append('<h4>Findings</h4>' + (ConvertTo-FindingsTable @($m.Findings)))

        [void]$sb.Append('<h4>Journey</h4>')
        if (@($m.Events).Count -eq 0) { [void]$sb.Append('<p class="muted">No journey events.</p>') }
        else {
            [void]$sb.Append('<ol class="timeline">')
            foreach ($e in @($m.Events)) {
                $t = if ($e.DateUtc) { '{0:yyyy-MM-dd HH:mm:ss}' -f $e.DateUtc } else { '?' }
                $gap = ''
                if ($e.GapSeconds -and $e.GapSeconds -gt $latencySeconds) { $gap = " <span class=""gap"">(+$(Format-Duration $e.GapSeconds) gap)</span>" }
                elseif ($e.GapSeconds) { $gap = " <span class=""muted small"">(+$(Format-Duration $e.GapSeconds))</span>" }
                [void]$sb.Append("<li class=""ev-$($e.EventSev)""><div><span class=""mono small"">$t</span> <span class=""muted small"">T+$(ConvertTo-HtmlSafe $e.Elapsed)</span>$gap</div>")
                $actionHtml = if ($e.Action) { ' <span class="muted">[' + (ConvertTo-HtmlSafe $e.Action) + ']</span>' } else { '' }
                [void]$sb.Append("<div class=""evh"">$(ConvertTo-HtmlSafe $e.Event)$actionHtml</div>")
                if ($e.Explanation) { [void]$sb.Append("<div class=""muted small"">$(ConvertTo-HtmlSafe $e.Explanation)</div>") }
                if ($e.Detail) { [void]$sb.Append("<div>$(ConvertTo-HtmlSafe $e.Detail)</div>") }
                if (@($e.Codes).Count -gt 0) {
                    $codeHtml = ($e.Codes | ForEach-Object { "<span class=""code"" title=""$(ConvertTo-HtmlSafe (Get-DsnInfo $_).Meaning)"">$(ConvertTo-HtmlSafe $_)</span>" }) -join ''
                    [void]$sb.Append("<div>$codeHtml</div>")
                }
                if ($e.LastError) { [void]$sb.Append("<div class=""small""><strong>Last error:</strong> <span class=""mono"">$(ConvertTo-HtmlSafe $e.LastError)</span></div>") }
                if ($e.Verdicts.Count -gt 0) { [void]$sb.Append("<div class=""small""><strong>Verdicts:</strong> <span class=""mono"">$(ConvertTo-HtmlSafe (($e.Verdicts.Keys | ForEach-Object { "$_=$($e.Verdicts[$_])" }) -join '  '))</span></div>") }
                if ($e.Data.Count -gt 0 -or @($e.Agents).Count -gt 0) {
                    [void]$sb.Append('<details class="data"><summary>Decoded event data</summary>')
                    foreach ($ag in @($e.Agents)) {
                        [void]$sb.Append("<div class=""small""><strong>Agent $(ConvertTo-HtmlSafe $ag.Agent)</strong> $(ConvertTo-HtmlSafe $ag.SubType)</div>" + (ConvertTo-HtmlKeyValue $ag.Values))
                    }
                    [void]$sb.Append((ConvertTo-HtmlKeyValue $e.Data) + '</details>')
                }
                [void]$sb.Append('</li>')
            }
            [void]$sb.Append('</ol>')
        }
        if ($m.Enrichment.Count -gt 0) {
            [void]$sb.Append('<h4>Enrichment</h4><details class="data"><summary>Show tenant / DNS lookups</summary>' + (ConvertTo-HtmlKeyValue $m.Enrichment) + '</details>')
        }
        [void]$sb.Append('<div style="height:10px"></div></details>')
    }
    [void]$sb.Append('</body></html>')
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding $false))
}

function Export-InvestigationBundle {
    param($Messages, $HeaderResult, [string]$Folder, [string]$HistoricalInfo)
    $msgArray = @($Messages)
    Export-InvestigationCsv -Messages $msgArray -Folder $Folder
    $reportPath = Join-Path $Folder 'Report.html'
    Export-HtmlReport -Messages $msgArray -HeaderResult $HeaderResult -Path $reportPath -HistoricalJob $HistoricalInfo
    try {
        $jsonObj = [ordered]@{
            Generated = (Get-Date).ToString('o')
            Version = $script:ScriptVersion
            Parameters = $script:BoundParams
            HeaderAnalysis = $HeaderResult
            HistoricalSearch = $HistoricalInfo
            Messages = $msgArray
        }
        $jsonObj | ConvertTo-Json -Depth 8 | Out-File -FilePath (Join-Path $Folder 'Investigation.json') -Encoding utf8
    } catch { Write-Log "JSON export failed: $($_.Exception.Message)" 'WARN' }
    return $reportPath
}
#endregion

#region Main
function Write-InvestigationSummary {
    param($Messages, $HeaderResult, [string]$ReportPath, [string]$Folder)
    $msgArray = @($Messages)
    Write-Host ''
    Write-Host '==================== INVESTIGATION SUMMARY ====================' -ForegroundColor Cyan
    Publish-UiEvent -Type 'Log' -Level 'INFO' -Message '==================== INVESTIGATION SUMMARY ===================='
    foreach ($g in @($msgArray | Group-Object Status | Sort-Object Count -Descending)) {
        $line = '  {0,-15} {1}' -f $g.Name, $g.Count
        Write-Host $line
        Publish-UiEvent -Type 'Log' -Level 'INFO' -Message $line
    }
    Write-Host ''
    $problemRows = @($msgArray | Where-Object { $_.PrimaryCause -and $_.PrimaryCause.Severity -ne 'Info' } |
        Sort-Object @{ Expression = { $script:SeverityRank[$_.PrimaryCause.Severity] }; Descending = $true } | Select-Object -First 25)
    foreach ($m in $problemRows) {
        $color = if ($m.PrimaryCause.Severity -eq 'Critical') { 'Red' } else { 'Yellow' }
        $head = '[{0}] {1:yyyy-MM-dd HH:mm} {2} -> {3} ({4})' -f $m.PrimaryCause.Severity.ToUpper(), $m.ReceivedUtc, $m.SenderAddress, $m.RecipientAddress, $m.Status
        Write-Host $head -ForegroundColor $color
        Write-Host ('      Subject : {0}' -f $m.Subject)
        Write-Host ('      Cause   : {0}' -f $m.PrimaryCause.Finding)
        Publish-UiEvent -Type 'Log' -Level $(if ($m.PrimaryCause.Severity -eq 'Critical') { 'ERROR' } else { 'WARN' }) -Message $head
        Publish-UiEvent -Type 'Log' -Level 'INFO' -Message ("      Cause   : {0}" -f $m.PrimaryCause.Finding)
        if ($m.PrimaryCause.Recommendation) {
            Write-Host ('      Action  : {0}' -f $m.PrimaryCause.Recommendation) -ForegroundColor DarkGray
        }
    }
    if ($HeaderResult) {
        foreach ($f in @($HeaderResult.Findings | Where-Object { $_.Severity -ne 'Info' })) {
            $line = '[HEADER {0}] {1}' -f $f.Severity.ToUpper(), $f.Finding
            Write-Host $line -ForegroundColor Yellow
            Publish-UiEvent -Type 'Log' -Level 'WARN' -Message $line
        }
    }
    if ($problemRows.Count -eq 0) {
        Write-Host '  No warnings or critical findings.' -ForegroundColor Green
        Publish-UiEvent -Type 'Log' -Level 'OK' -Message '  No warnings or critical findings.'
    }
    Write-Host ''
    Write-Host "Report : $ReportPath" -ForegroundColor Green
    Write-Host "CSV    : $(Join-Path $Folder 'Messages.csv'), Events.csv, Findings.csv" -ForegroundColor Green
    Write-Host '===============================================================' -ForegroundColor Cyan
    Publish-UiEvent -Type 'Log' -Level 'OK' -Message "Report : $ReportPath"
}

function Invoke-M365MailFlowInvestigation {
    <#
    .SYNOPSIS
        Deep-dive Exchange Online / Microsoft 365 mail flow investigation with root cause analysis.
    .DESCRIPTION
        Combines message trace, journey detail, tenant enrichment, DNS, header analysis, and an
        extended historical report into Report.html plus CSV/JSON. Does not exit the host.
    .EXAMPLE
        Invoke-M365MailFlowInvestigation -RecipientAddress user@contoso.com -StartDate (Get-Date).AddDays(-3)
    #>
    [CmdletBinding()]
    param(
        [string[]]$SenderAddress,
        [string[]]$RecipientAddress,
        [string[]]$MessageId,
        [guid]$MessageTraceId,
        [string]$Subject,
        [ValidateSet('Contains', 'StartsWith', 'EndsWith')]
        [string]$SubjectFilterType = 'Contains',
        [ValidateSet('Delivered', 'Expanded', 'Failed', 'FilteredAsSpam', 'GettingStatus', 'Pending', 'Quarantined')]
        [string[]]$Status,
        [string]$FromIP,
        [string]$ToIP,
        [datetime]$StartDate = (Get-Date).AddDays(-2),
        [datetime]$EndDate = (Get-Date),
        [ValidateRange(1, 50000)]
        [int]$MaxResults = 5000,
        [ValidateRange(0, 5000)]
        [int]$MaxDetailLookups = 250,
        [switch]$ProblemsOnly,
        [switch]$SkipDetail,
        [switch]$SkipEnrichment,
        [switch]$IncludeMailboxChecks,
        [switch]$SkipDnsChecks,
        [ValidateRange(1, 1440)]
        [int]$LatencyWarningMinutes = 10,
        [string]$HeaderFile,
        [string]$ExtendedReportCsv,
        [switch]$SubmitHistoricalSearch,
        [string[]]$NotifyAddress,
        [string]$OutputPath = (Join-Path -Path (Get-Location).Path -ChildPath ('MailInvestigation_{0}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
        [switch]$OpenReport,
        [string]$UserPrincipalName,
        [string]$AppId,
        [string]$CertificateThumbprint,
        [string]$Organization,
        [switch]$DisconnectWhenDone,
        [switch]$Offline,
        [switch]$UseDeviceCode,
        [switch]$DisableWAM,
        [switch]$StrictDateRange
    )

    $exitCode = 0
    $fatal = $null
    $headerResult = $null
    $historicalInfo = $null
    $resolvedOutput = $null
    $reportPath = $null
    $messages = New-Object 'System.Collections.Generic.List[psobject]'

    $script:Config = @{
        SenderAddress = Get-NormalizedAddressList $SenderAddress
        RecipientAddress = Get-NormalizedAddressList $RecipientAddress
        MessageId = Get-NormalizedMessageIdList $MessageId
        Status = Get-NormalizedStatusList $Status
        MessageTraceId = $null
        MessageTraceIdSpecified = $PSBoundParameters.ContainsKey('MessageTraceId')
        Subject = $Subject
        SubjectFilterType = $SubjectFilterType
        FromIP = $FromIP
        ToIP = $ToIP
        StartDate = $StartDate
        EndDate = $EndDate
        StartDateSpecified = $PSBoundParameters.ContainsKey('StartDate')
        EndDateSpecified = $PSBoundParameters.ContainsKey('EndDate')
        MaxResults = $MaxResults
        MaxDetailLookups = $MaxDetailLookups
        ProblemsOnly = [bool]$ProblemsOnly
        SkipDetail = [bool]$SkipDetail
        SkipEnrichment = [bool]$SkipEnrichment
        IncludeMailboxChecks = [bool]$IncludeMailboxChecks
        SkipDnsChecks = [bool]$SkipDnsChecks
        LatencyWarningMinutes = $LatencyWarningMinutes
        HeaderFile = $HeaderFile
        ExtendedReportCsv = $ExtendedReportCsv
        SubmitHistoricalSearch = [bool]$SubmitHistoricalSearch
        NotifyAddress = Get-NormalizedAddressList $NotifyAddress
        OutputPath = $OutputPath
        OpenReport = [bool]$OpenReport
        Offline = [bool]$Offline
        UserPrincipalName = $UserPrincipalName
        AppId = $AppId
        CertificateThumbprint = $CertificateThumbprint
        Organization = $Organization
        DisconnectWhenDone = [bool]$DisconnectWhenDone
        UseDeviceCode = [bool]$UseDeviceCode
        DisableWAM = [bool]$DisableWAM
        SearchBackForMessageId = -not [bool]$StrictDateRange
    }
    if ($PSBoundParameters.ContainsKey('MessageTraceId')) { $script:Config.MessageTraceId = $MessageTraceId }
    $script:DerivedTraceId = $null
    $script:Cache = @{
        Recipient = @{}; Mailbox = @{}; Dns = @{}; Quarantine = @{}
        Blocked = @{}; InboxRules = @{}; Junk = @{}; Group = @{}
    }
    $script:RequestTimes = New-Object 'System.Collections.Generic.Queue[datetime]'
    $script:BoundParams = @{}
    foreach ($k in @($PSBoundParameters.Keys)) {
        if ($k -match 'Certificate|Thumbprint') { continue }
        $script:BoundParams[$k] = $PSBoundParameters[$k]
    }

    try {
        if ([string]::IsNullOrWhiteSpace($OutputPath)) { throw 'OutputPath is empty.' }
        if (-not (Test-Path -LiteralPath $OutputPath)) {
            [void](New-Item -ItemType Directory -Path $OutputPath -Force)
        }
        $resolvedOutput = (Resolve-Path -LiteralPath $OutputPath).Path
        $script:LogFile = Join-Path $resolvedOutput 'Investigation.log'
        Write-Log "Microsoft 365 mail flow investigation v$script:ScriptVersion - output: $resolvedOutput"
        Write-Log ("PowerShell {0} on {1}" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition)

        if ($PSVersionTable.PSVersion.Major -lt 5) { throw 'Windows PowerShell 5.1 or later is required.' }
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
        Test-InvestigationCancel

        if ($HeaderFile) {
            Write-Log "Analysing message headers from $HeaderFile..."
            $headerResult = Get-HeaderAnalysis -Path $HeaderFile
            Write-Log ("Header analysis: {0} hops, {1} findings." -f @($headerResult.Hops).Count, @($headerResult.Findings).Count) 'OK'
            $noFilters = -not (
                @($script:Config.SenderAddress).Count -or @($script:Config.RecipientAddress).Count -or
                @($script:Config.MessageId).Count -or $script:Config.MessageTraceIdSpecified -or
                $script:Config.Subject -or $script:Config.FromIP -or $script:Config.ToIP
            )
            if ($noFilters -and -not $script:Config.Offline) {
                if ($headerResult.Summary.NetworkMessageId) {
                    $g = [guid]::Empty
                    if ([guid]::TryParse(([string]$headerResult.Summary.NetworkMessageId).Trim(), [ref]$g)) {
                        $script:DerivedTraceId = $g
                        Write-Log "Using Network-Message-Id from headers as MessageTraceId filter: $g" 'OK'
                    }
                }
                if (-not $script:DerivedTraceId -and $headerResult.Summary.MessageId) {
                    $script:Config.MessageId = @(ConvertTo-NormalizedMessageId ([string]$headerResult.Summary.MessageId))
                    Write-Log "Using Message-ID from headers as filter: $($script:Config.MessageId)" 'OK'
                }
                $hops = @($headerResult.Hops | Where-Object { $_.TimeUtc })
                if ($hops.Count -gt 0 -and -not $script:Config.StartDateSpecified) {
                    $script:Config.StartDate = $hops[0].TimeUtc.ToLocalTime().AddDays(-1)
                    $script:Config.EndDate = $hops[-1].TimeUtc.ToLocalTime().AddDays(2)
                    if ($script:Config.EndDate -gt (Get-Date)) { $script:Config.EndDate = Get-Date }
                    Write-Log ("Date range derived from headers: {0:g} -> {1:g}" -f $script:Config.StartDate, $script:Config.EndDate)
                }
            }
        }

        $oldest = (Get-Date).AddDays(-90)
        if ($script:Config.EndDate -gt (Get-Date).AddMinutes(5)) {
            Write-Log 'EndDate is in the future. Clamping to now.' 'WARN'
            $script:Config.EndDate = Get-Date
        }
        if ($script:Config.EndDate -le $script:Config.StartDate) {
            throw "EndDate ($($script:Config.EndDate)) must be after StartDate ($($script:Config.StartDate))."
        }
        if ($script:Config.StartDate -lt $oldest -and -not $script:Config.Offline -and -not $ExtendedReportCsv) {
            Write-Log "StartDate is older than 90 days. Message trace data does not exist beyond 90 days. Clamping to $oldest." 'WARN'
            $script:Config.StartDate = $oldest.AddMinutes(5)
        }

        $wantTrace = (-not $ExtendedReportCsv) -and (-not $script:Config.Offline)
        $wantEnrich = (-not $script:Config.SkipEnrichment) -and (-not $script:Config.Offline)
        $needExo = $wantTrace -or $wantEnrich -or ($script:Config.SubmitHistoricalSearch -and -not $script:Config.Offline)

        if ($needExo) {
            try {
                Connect-ExoSession
                Initialize-OrgContext
                if ($wantEnrich) { Connect-IppsSessionIfNeeded }
            } catch {
                if ($HeaderFile -or $ExtendedReportCsv) {
                    Write-Log "Continuing with offline data. Exchange connection failed: $($_.Exception.Message)" 'WARN'
                    $script:Connected = $false
                    $needExo = $false
                    $wantTrace = $false
                } else {
                    throw
                }
            }
        } elseif ($script:Config.Offline) {
            Write-Log 'Offline mode: Exchange Online will not be contacted.' 'WARN'
        }

        if ($ExtendedReportCsv) {
            foreach ($m in (Import-ExtendedReport -Path $ExtendedReportCsv)) { $messages.Add($m) }
        } elseif ($wantTrace) {
            $hasFilter = @($script:Config.SenderAddress).Count -or @($script:Config.RecipientAddress).Count -or @($script:Config.MessageId).Count -or $script:Config.MessageTraceIdSpecified -or $script:DerivedTraceId -or $script:Config.Subject -or $script:Config.FromIP -or $script:Config.ToIP -or @($script:Config.Status).Count
            if (-not $hasFilter) { Write-Log 'No filters specified. This returns all mail in the date range, capped by -MaxResults.' 'WARN' }
            Write-InvestigationProgress -Activity 'Message trace' -Status 'Querying message trace' -Percent 5
            $summary = Get-TraceSummary -Start $script:Config.StartDate -End $script:Config.EndDate
            $hasLocator = @($script:Config.MessageId).Count -gt 0 -or $script:Config.MessageTraceIdSpecified -or $script:DerivedTraceId
            if ($summary.Count -eq 0 -and $script:Config.SearchBackForMessageId -and $hasLocator) {
                $oldest = (Get-Date).AddDays(-90).AddMinutes(10)
                $backWindows = Get-SearchBackWindows -RequestedStart $script:Config.StartDate -RequestedEnd $script:Config.EndDate -Now (Get-Date) -Oldest $oldest
                $wIndex = 0
                Write-Log 'The message ID was not in the selected dates. Searching the rest of the 90-day message trace history.' 'WARN'
                foreach ($bw in $backWindows) {
                    Test-InvestigationCancel
                    if ($summary.Count -gt 0) { break }
                    $wIndex++
                    $pct = [int](5 + (($wIndex / [math]::Max(1, $backWindows.Count)) * 8))
                    Write-InvestigationProgress -Activity 'Message trace' -Status ("Looking further: {0:g} to {1:g}" -f $bw.Start, $bw.End) -Percent $pct
                    Write-Log ("Message ID search {0}/{1}: {2:u} -> {3:u}" -f $wIndex, $backWindows.Count, $bw.Start, $bw.End)
                    $summary = Get-TraceSummary -Start $bw.Start -End $bw.End
                }
            }
            foreach ($row in $summary) { $messages.Add((New-MessageRecord -Summary $row)) }
            if ($messages.Count -eq 0) {
                if ($hasLocator -and $script:Config.SearchBackForMessageId) {
                    Write-Log 'No message with that ID exists in the last 90 days of message trace. Check the ID was copied completely (it usually contains @ and ends with >). Very recent mail can lag 5-30 minutes.' 'WARN'
                } else {
                    Write-Log 'No messages matched. Check the address (primary SMTP / exact sender), Message-ID angle brackets, the date range in local time, and that very recent mail can lag 5-30 minutes.' 'WARN'
                }
            }
            if (-not $script:Config.SkipDetail -and $messages.Count -gt 0) {
                $candidates = @($messages | Sort-Object @{ Expression = { if ($_.Status -in @('Delivered', 'Expanded')) { 1 } else { 0 } } }, @{ Expression = { $_.ReceivedUtc }; Descending = $true })
                if ($script:Config.ProblemsOnly) { $candidates = @($candidates | Where-Object { $_.Status -notin @('Delivered', 'Expanded') }) }
                if ($candidates.Count -gt $script:Config.MaxDetailLookups) {
                    Write-Log "$($candidates.Count) rows eligible for detail; limiting to -MaxDetailLookups $($script:Config.MaxDetailLookups) (problem messages first)." 'WARN'
                    if ($script:Config.MaxDetailLookups -gt 0) { $candidates = @($candidates | Select-Object -First $script:Config.MaxDetailLookups) }
                    else { $candidates = @() }
                }
                $i = 0
                foreach ($m in $candidates) {
                    Test-InvestigationCancel
                    $i++
                    $pct = [int](10 + (($i / [math]::Max(1, $candidates.Count)) * 60))
                    Write-InvestigationProgress -Activity 'Journey detail' -Status "$i / $($candidates.Count): $($m.RecipientAddress)" -Percent $pct
                    try {
                        foreach ($e in (Get-TraceDetailEvents -Msg $m)) { $m.Events.Add($e) }
                        $m.DetailRetrieved = $true
                    } catch {
                        if (Test-IsCancelError $_) { throw }
                        $m.DetailError = $_.Exception.Message
                        Write-Log "Detail failed for $($m.MessageTraceId) / $($m.RecipientAddress): $($m.DetailError)" 'WARN'
                    }
                }
                Write-Log "Journey detail retrieved for $(@($messages | Where-Object DetailRetrieved).Count) row(s)." 'OK'
            }
        }

        $i = 0
        foreach ($m in @($messages)) {
            Test-InvestigationCancel
            $i++
            $pct = [int](75 + (($i / [math]::Max(1, $messages.Count)) * 20))
            Write-InvestigationProgress -Activity 'Analysing' -Status "$i / $($messages.Count)" -Percent $pct
            try {
                Invoke-RootCauseAnalysis -Msg $m
                if ($script:Connected -and -not $script:Config.SkipEnrichment -and -not $script:Config.Offline) {
                    Invoke-MessageEnrichment -Msg $m
                }
                Set-PrimaryCause -Msg $m
            } catch {
                if (Test-IsCancelError $_) { throw }
                Write-Log "Analysis error for $($m.MessageTraceId): $($_.Exception.Message)" 'WARN'
                Add-Finding $m 'Info' 'Data' 'Analysis error.' $_.Exception.Message ''
                Set-PrimaryCause -Msg $m
            }
        }

        if ($script:Config.SubmitHistoricalSearch -and $script:Connected) {
            if (@($script:Config.NotifyAddress).Count -eq 0) {
                Write-Log '-SubmitHistoricalSearch requires -NotifyAddress (where the completion email goes).' 'WARN'
            } else {
                try {
                    $hp = @{
                        ReportTitle   = 'MailInvestigation_{0}' -f (Get-Date -Format 'yyyyMMdd_HHmmss')
                        StartDate     = $script:Config.StartDate
                        EndDate       = $script:Config.EndDate
                        ReportType    = 'MessageTraceDetail'
                        NotifyAddress = @($script:Config.NotifyAddress)
                    }
                    if (@($script:Config.SenderAddress).Count) { $hp.SenderAddress = @($script:Config.SenderAddress) }
                    if (@($script:Config.RecipientAddress).Count) { $hp.RecipientAddress = @($script:Config.RecipientAddress) }
                    if (@($script:Config.MessageId).Count -gt 1) {
                        Write-Log 'Historical search accepts one MessageId. Using the first.' 'WARN'
                    }
                    if (@($script:Config.MessageId).Count) { $hp.MessageID = [string]@($script:Config.MessageId)[0] }
                    if (-not (@($script:Config.SenderAddress).Count -or @($script:Config.RecipientAddress).Count -or @($script:Config.MessageId).Count)) {
                        throw 'Historical search needs SenderAddress, RecipientAddress, or MessageId.'
                    }
                    $hp = Select-SupportedParameters -Command 'Start-HistoricalSearch' -Parameters $hp
                    $job = Invoke-ExoCommand -Command 'Start-HistoricalSearch' -Parameters $hp | Select-Object -First 1
                    $jobId = [string](Get-PropValue $job 'JobId')
                    $historicalInfo = "Extended historical search submitted. JobId: $jobId. Track with: Get-HistoricalSearch -JobId $jobId. Download it from Exchange admin center > Mail flow > Message trace, then analyse it with -ExtendedReportCsv."
                    Write-Log $historicalInfo 'OK'
                } catch {
                    Write-Log "Historical search submission failed: $($_.Exception.Message)" 'WARN'
                }
            }
        }

        Write-InvestigationProgress -Activity 'Report' -Status 'Writing report' -Percent 98
        $reportPath = Export-InvestigationBundle -Messages $messages.ToArray() -HeaderResult $headerResult -Folder $resolvedOutput -HistoricalInfo $historicalInfo
        Write-InvestigationSummary -Messages $messages.ToArray() -HeaderResult $headerResult -ReportPath $reportPath -Folder $resolvedOutput
        Write-InvestigationProgress -Activity 'Report' -Status 'Complete' -Percent 100
        if ($script:Config.OpenReport -and $reportPath) {
            try { Start-Process $reportPath } catch { Write-Log "Could not open the report: $($_.Exception.Message)" 'WARN' }
        }
    } catch {
        if (Test-IsCancelError $_) {
            $exitCode = 2
            $fatal = 'Investigation cancelled.'
            Write-Log $fatal 'WARN'
        } else {
            $exitCode = 1
            $fatal = $_.Exception.Message
            Write-Log "FATAL: $fatal" 'ERROR'
            Write-Log $_.ScriptStackTrace 'DEBUG'
        }
        if ($resolvedOutput -and ($headerResult -or $messages.Count -gt 0)) {
            try {
                $reportPath = Export-InvestigationBundle -Messages $messages.ToArray() -HeaderResult $headerResult -Folder $resolvedOutput -HistoricalInfo $historicalInfo
                Write-Log "Partial results written to $reportPath" 'WARN'
            } catch {
                Write-Log "Could not write partial results: $($_.Exception.Message)" 'WARN'
            }
        }
    } finally {
        if ($script:Config.DisconnectWhenDone) {
            Disconnect-M365MailFlowSession -Force
        }
        try { Write-Progress -Activity 'Report' -Completed } catch { }
    }

    [pscustomobject]@{
        ExitCode          = $exitCode
        OutputPath        = $resolvedOutput
        ReportPath        = $reportPath
        MessageCount      = $messages.Count
        FatalError        = $fatal
        HistoricalSearch  = $historicalInfo
        Version           = $script:ScriptVersion
    }
}
#endregion




