description = [[
Identifies the probable infrastructure role of a target host by
comparing detected network services against a predefined knowledge base.

The script infers likely infrastructure roles and reports a confidence
score, risk level, supporting evidence, and security recommendations.
]]

---
-- @usage
-- nmap --script infra-role-fingerprint <target>
-- nmap --script infra-role-fingerprint --script-args infra.verbose=true <target>
-- nmap --script infra-role-fingerprint --script-args infra.minconfidence=80 <target>
-- nmap --script infra-role-fingerprint --script-args infra.summary=true <target>

author = "Gaurish Budhiraja"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe","discovery"}

local stdnse = require "stdnse"

-------------------------------------------------
-- Infrastructure Knowledge Base
-------------------------------------------------

local infrastructure_roles = {

    Web_Server = {
        required = {"http"},
        optional = {"https","mysql","postgresql","apache","nginx"},
        description = "Hosts web applications or websites."
    },

    Mail_Server = {
        required = {"smtp"},
        optional = {"imap","imaps","pop3","pop3s"},
        description = "Handles email services."
    },

    DNS_Server = {
        required = {"domain"},
        optional = {"domain-s"},
        description = "Provides DNS name resolution."
    },

    File_Server = {
        required = {"microsoft-ds"},
        optional = {"ftp","nfs","netbios-ssn"},
        description = "Provides centralized file sharing."
    },

    Database_Server = {
        required = {"mysql"},
        optional = {"postgresql","ms-sql-s","oracle","mongodb"},
        description = "Hosts database services."
    },

    SSH_Server = {
        required = {"ssh"},
        optional = {"telnet"},
        description = "Provides remote administration."
    },

    Proxy_Server = {
        required = {"http-proxy"},
        optional = {"socks","squid-http"},
        description = "Acts as a proxy or gateway."
    },

    LDAP_Server = {
        required = {"ldap"},
        optional = {"ldaps","kerberos"},
        description = "Provides centralized directory services."
    },

    VoIP_Server = {
        required = {"sip"},
        optional = {"h323","iax2"},
        description = "Provides Voice over IP services."
    }

}

-------------------------------------------------
-- Recommendations
-------------------------------------------------

local recommendations = {

    Web_Server = "Verify HTTP headers, TLS configuration and exposed web applications.",
    Mail_Server = "Check for open relay, STARTTLS configuration and authentication.",
    DNS_Server = "Check for zone transfers and recursion.",
    File_Server = "Review SMB permissions and anonymous access.",
    Database_Server = "Restrict database exposure and enforce authentication.",
    SSH_Server = "Disable password authentication and enforce key-based login.",
    Proxy_Server = "Ensure proxy authentication is enabled.",
    LDAP_Server = "Require LDAPS and disable anonymous binds.",
    VoIP_Server = "Restrict SIP access and secure signaling."

}

-------------------------------------------------
-- Helper Functions
-------------------------------------------------

local function infer_role(service)

    local best_role = "Unknown"
    local highest_score = 0
    local evidence = {}

    for role, info in pairs(infrastructure_roles) do

        local score = 0
        local matched = {}

        for _, required in ipairs(info.required) do
            if service == required then
                score = score + 80
                matched[#matched+1] = "Required Service : "..required
                matched[#matched+1] = "Matched "..role.." profile"
            end
        end

        for _, optional in ipairs(info.optional) do
            if service == optional then
                score = score + 20
                matched[#matched+1] = "Optional Service : "..optional
            end
        end

        if score > highest_score then
            highest_score = score
            best_role = role
            evidence = matched
        end
    end

    return best_role, highest_score, evidence
end

local function get_risk(role)

    if role == "Database_Server" or role == "LDAP_Server" then
        return "High"
    elseif role == "Mail_Server" or role == "Proxy_Server" or role == "VoIP_Server" then
        return "Medium"
    else
        return "Low"
    end

end

local function get_recommendation(role)
    return recommendations[role] or "No recommendation available."
end

-------------------------------------------------
-- Run on every open TCP port
-------------------------------------------------

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open"
end

-------------------------------------------------
-- Main Function
-------------------------------------------------

action = function(host, port)

    local service = port.service or "unknown"

    local role, score, evidence = infer_role(service)

    if score == 0 then
        return nil
    end

    local minimum_confidence =
        tonumber(stdnse.get_script_args("infra.minconfidence")) or 0

    if score < minimum_confidence then
        return nil
    end

    local verbose = stdnse.get_script_args("infra.verbose")
    local summary = stdnse.get_script_args("infra.summary")

    if summary then
        return string.format("Role: %s (%d%%)", role, score)
    end

    local risk = get_risk(role)
    local recommendation = get_recommendation(role)

    local output = {}

    output[#output+1] = "Role           : "..role
    output[#output+1] = "Confidence     : "..score.."%"
    output[#output+1] = "Risk           : "..risk
    output[#output+1] = "Evidence"

    for _, item in ipairs(evidence) do
        output[#output+1] = "  - "..item
    end

    output[#output+1] = "Recommendation"
    output[#output+1] = "  "..recommendation

    if verbose then
        output[#output+1] = "Description"
        output[#output+1] = "  "..infrastructure_roles[role].description
    end

    return stdnse.format_output(true, output)

end
