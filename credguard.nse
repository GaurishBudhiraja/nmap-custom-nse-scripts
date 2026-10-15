description = [[
CredGuard is an Nmap NSE script that identifies network services
commonly associated with default or weak credentials.

The script does NOT attempt authentication.
Instead, it performs a rule-based security assessment and
provides common default credentials, risk level, confidence,
category, and hardening recommendations.
]]

---
-- @usage
-- nmap --script credguard <target>
-- nmap --script credguard --script-args credguard.summary=true <target>
-- nmap --script credguard --script-args credguard.verbose=true <target>
-- nmap --script credguard --script-args credguard.minrisk=High <target>

author = "Gaurish Budhiraja"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe","discovery"}

local stdnse = require "stdnse"

-------------------------------------------------
-- Credential Knowledge Base
-------------------------------------------------

local credential_database = {

    ftp = {
        risk="High", confidence=95, category="File Transfer",
        accounts={"anonymous","ftp:ftp","admin:admin"},
        reason="FTP servers often allow anonymous or weak default credentials.",
        recommendation="Disable anonymous login and migrate to SFTP."
    },

    ssh = {
        risk="Medium", confidence=85, category="Remote Administration",
        accounts={"root:root","admin:admin","pi:raspberry"},
        reason="SSH may be exposed with weak administrative credentials.",
        recommendation="Disable password authentication and use SSH keys."
    },

    telnet = {
        risk="High", confidence=95, category="Remote Administration",
        accounts={"admin:admin","root:root"},
        reason="Telnet sends credentials in plaintext.",
        recommendation="Replace Telnet with SSH."
    },

    http = {
        risk="Medium", confidence=80, category="Web Service",
        accounts={"admin:admin","administrator:password","guest:guest"},
        reason="Web administration interfaces often retain vendor default credentials.",
        recommendation="Change default credentials and enable MFA."
    },

    https = {
        risk="Low", confidence=75, category="Web Service",
        accounts={"admin:admin","administrator:password"},
        reason="HTTPS encrypts traffic but default accounts may still exist.",
        recommendation="Remove default accounts and enforce strong authentication."
    },

    smtp = {
        risk="Medium", confidence=80, category="Email Service",
        accounts={"admin:admin"},
        reason="Mail administration interfaces may use weak credentials.",
        recommendation="Restrict administrative access and enable strong authentication."
    },

    pop3 = {
        risk="Medium", confidence=75, category="Email Service",
        accounts={"user:password"},
        reason="POP3 services often rely on weak passwords.",
        recommendation="Use POP3S and enforce strong passwords."
    },

    imap = {
        risk="Medium", confidence=75, category="Email Service",
        accounts={"user:password"},
        reason="IMAP accounts may be protected by weak credentials.",
        recommendation="Use IMAPS and enforce strong passwords."
    },

    mysql = {
        risk="High", confidence=90, category="Database",
        accounts={"root:","root:root"},
        reason="Databases are common targets when default accounts remain enabled.",
        recommendation="Restrict exposure and secure administrator accounts."
    },

    ["microsoft-ds"] = {
        risk="High", confidence=90, category="File Sharing",
        accounts={"Administrator:password"},
        reason="SMB services often expose privileged accounts.",
        recommendation="Disable SMBv1 and enforce strong passwords."
    },

    domain = {
        risk="Low", confidence=70, category="Infrastructure Service",
        accounts={"administrator:password"},
        reason="DNS services may expose administrative interfaces with default credentials.",
        recommendation="Restrict DNS administration and disable unnecessary recursion."
    },

    sip = {
        risk="Medium", confidence=75, category="VoIP Service",
        accounts={"admin:admin"},
        reason="VoIP servers frequently expose administrative interfaces.",
        recommendation="Restrict SIP administration and change default credentials."
    },

    xmpp = {
        risk="Low", confidence=70, category="Messaging Service",
        accounts={"admin:admin"},
        reason="Messaging servers may expose default administrative accounts.",
        recommendation="Disable default accounts and enforce strong authentication."
    },

    ["cisco-sccp"] = {
        risk="Medium", confidence=75, category="VoIP Service",
        accounts={"admin:admin"},
        reason="Cisco voice services may expose default administrative credentials.",
        recommendation="Secure management interfaces and remove vendor defaults."
    }
}

local function get_service_info(service) return credential_database[service] end
local function get_risk(info) return info.risk end
local function get_confidence(info) return info.confidence end
local function get_category(info) return info.category end
local function get_reason(info) return info.reason end
local function get_accounts(info) return info.accounts end
local function get_recommendation(info) return info.recommendation end

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)

    local service = port.service or "unknown"

    local summary = stdnse.get_script_args("credguard.summary")
    local verbose = stdnse.get_script_args("credguard.verbose")
    local minimum_risk = stdnse.get_script_args("credguard.minrisk")

    local info = get_service_info(service)

    if not info then
        return nil
    end

    if minimum_risk then
        local risk = get_risk(info)
        if minimum_risk == "High" and risk ~= "High" then return nil end
        if minimum_risk == "Medium" and risk == "Low" then return nil end
    end

    if summary then
        return string.format("%s | %s | %d%%", service, get_risk(info), get_confidence(info))
    end

    local output = {}

    output[#output+1] = "========== CredGuard Security Assessment =========="
    output[#output+1] = ""
    output[#output+1] = "Service      : "..service
    output[#output+1] = "Category     : "..get_category(info)
    output[#output+1] = "Risk         : "..get_risk(info)
    output[#output+1] = "Confidence   : "..get_confidence(info).."%"
    output[#output+1] = ""
    output[#output+1] = "Reason"
    output[#output+1] = "  "..get_reason(info)
    output[#output+1] = ""
    output[#output+1] = "Common Default Credentials"

    for _, account in ipairs(get_accounts(info)) do
        output[#output+1] = "  - "..account
    end

    output[#output+1] = ""
    output[#output+1] = "Recommendation"
    output[#output+1] = "  "..get_recommendation(info)

    if verbose then
        output[#output+1] = ""
        output[#output+1] = "Host Information"
        output[#output+1] = "  IP       : "..host.ip
        output[#output+1] = "  Port     : "..port.number
        output[#output+1] = "  Protocol : "..port.protocol
    end

    output[#output+1] = ""
    output[#output+1] = "Assessment completed by CredGuard."

    return stdnse.format_output(true, output)
end
