import re
from termcolor import colored

def check_360wzws(response_headers, response_body):
    pattern = re.compile(
        r"(.wzws.waf.cgi|wangzhan.360.cn|qianxin.waf|360wzws/|transfer.is.blocked)"
    )
    if (
        "Server" in response_headers
        and "X-Powered-By-360wzb" in response_headers
        and (pattern.search(response_headers["Server"]) or pattern.search(response_headers["X-Powered-By-360wzb"]))
        or pattern.search(response_body)
    ):
        return True
    return False

def check_aesecure(response_headers, response_body):
    pattern = re.compile(
        r"/aesecure.denied.png"
    )
    if (
        "AeSecure-Code" in response_headers
        and pattern.search(response_headers["AeSecure-Code"])
        or pattern.search(response_body)
    ):
        return True
    return False

def check_airlock(response_headers, response_body):
    pattern = re.compile(r"\Aal[.-]?(sess|lb)=?")
    if "Set-Cookie" in response_headers and pattern.search(response_headers["Set-Cookie"]):
        return True
    return False

def check_akamaighost(response_headers, response_body):
    pattern = re.compile(
        r"(.>access.denied<.|akamaighost|ak.bmsc.)"
    )
    if (
        "Server" in response_headers
        and "Set-Cookie" in response_headers
        and "X-Cache" in response_headers
        and "X-Cache-Remote" in response_headers
        and (pattern.search(response_headers["Server"]) or pattern.search(response_headers["Set-Cookie"]) or pattern.search(response_headers["X-Cache"]) or pattern.search(response_headers["X-Cache-Remote"]))
        or pattern.search(response_body)
    ):
        return True
    return False

def check_alert_logic(response_headers, response_body):
    pattern = re.compile(
        r"(.>requested.url.cannot.be.found<.|proceed.to.homepage|back.to.previous.page|we(?:'re|.are)?sorry.{1,2}but.the.page.you.are.looking.for.cannot|reference.id.?|page.has.either.been.removed.{1,2}renamed)",
        re.IGNORECASE
    )

    if pattern.search(response_body):
        return True
    return False

def check_aliyundun(response_headers, response_body):
    pattern = re.compile(
        r"(error(s)?.aliyun(dun)?.(com|net)|http(s)?:\/\/(www.)?aliyun.(com|net))", re.IGNORECASE
    )

    def builder(headers, body):
        if pattern.search(body):
            return True
        return False

    if builder(response_headers.values(), response_body):
        return True
    return False

def check_anquanbao(response_headers, response_body):
    pattern = re.compile(r'.aqb_cc.error.', re.IGNORECASE)
    def matches_body(body, pattern):
        return pattern.search(body)

    def matches_any_header_value(headers, pattern):
        for header in headers.values():
            if pattern.search(header):
                return True
        return False

    if matches_body(response_body, pattern) or matches_any_header_value(response_headers, pattern):
        return True
    return False

def check_anyu(response_headers, response_body):
    pattern = re.compile(r'(sorry.{1,2}your.access.has.been.intercept(ed)?.by.anyu|anyu|anyu-?.the.green.channel)', re.IGNORECASE)
    
    if pattern.search(response_body):
        return True
    
    event_id = response_headers.get("WZWS-RAY")
    if event_id and pattern.search(response_body):
        return True
    
    return False

def check_apache(response_headers, response_body):
    pattern = re.compile(r"(apache|.>you.don.t.have.permission.to.access+|was.not.found.on.this.server|<address>apache/([\d+{1,2}](.[\d+]{1,2}(.[\d+]{1,3})?)?)?|<title>403 Forbidden</title>)", re.IGNORECASE)
    
    def matches_header(headers, pattern):
        if "Server" in headers and pattern.search(headers["Server"]):
            return True
        return False
    
    def matches_body(body, pattern):
        return pattern.search(body)

    if matches_header(response_headers, pattern) or matches_body(response_body, pattern):
        return True
    return False

def check_armor(response_headers, response_body):
    pattern = re.compile(r'\barmor\b|blocked.by.website.protection.from.armour', re.IGNORECASE)

    def matches_body(body, pattern):
        return pattern.search(body)

    if matches_body(response_body, pattern):
        return True
    return False

def check_ASPNET(response_headers, response_body):
    pattern = re.compile(
        r'(?:this\.generic\.403\.error\.means\.that\.the\.authenticated)|'
        r'(?:request\.could\.not\.be\.understood)|'
        r'(?:<.+>a\.potentially\.dangerous\.request(?:.querystring)?.+)|'
        r'(?:runtime\.error)|'
        r'(?:\.>a\.potentially\.dangerous\.request\.path\.value\.was\.detected\.from\.the\.client+)|'
        r'(?:asp\.net\.sessionid)|'
        r'(?:errordocument\.to\.handle\.the\.request)|'
        r'(?:an\.application\.error\.occurred\.on\.the\.server)|'
        r'(?:error\.log\.record\.number)|'
        r'(?:error\.page\.might\.contain\.sensitive\.information)|'
        r'(?:<.+>server\.error\.in\.'
        r'\/'
        r'.application.+)|'
        r'(?:\basp\.net\b)', re.IGNORECASE)

    if (
        "X-ASPNET-Version" in response_headers
        or "ASP-ID" in response_headers
        or ("Set-Cookie" in response_headers and re.search(pattern, response_headers["Set-Cookie"]))
        or "X-Powered-By" in response_headers and response_headers["X-Powered-By"] == "ASP.NET"
        or pattern.search(response_body)
    ):
        return True
    return False


def check_application_security_manager(response_headers, response_body):
    pattern = re.compile(r'the.requested.url.was.rejected..please.consult.with.your.administrator.', re.IGNORECASE)

    def matches_body(body, pattern):
        return pattern.search(body)

    if matches_body(response_body, pattern):
        return True
    return False

def check_ApacheTrafficServer(response_headers, response_body):
    PATTERN = re.compile(
        r'(?:\(\)?apachetrafficserver((\/)?\d+(.\d+(.\d+)?)?))|'
        r'(?:ats((\/)?(\d+(.\d+(.\d+)?)?))?)|'
        r'(?:ats)', re.IGNORECASE)

    def check(response_headers):
        for header in ["Via", "Server"]:
            if header in response_headers and PATTERN.search(response_headers[header]):
                return True
        return False

    return check(response_headers)


def check_AmazonWebServices(response_headers, response_body):
    PATTERN = re.compile(
        r'(?:<RequestId>[0-9a-zA-Z]{16,25}</RequestId>)|'
        r'(?:<Error><Code>AccessDenied</Code>)', re.IGNORECASE)

    AMAZON_PATTERN = re.compile(r'(?:x\.amz\.(?:id\.\d+|request\.id))', re.IGNORECASE)

    def check(response_headers, response_body):
        for header in ["Server", "X-Powered-By", "Set-Cookie"]:
            if header in response_headers and AMAZON_PATTERN.search(response_headers[header]):
                return True
        if PATTERN.search(response_body):
            return True
        return False

def check_Baidu(response_headers, response_body):
    PATTERN = re.compile(r'fh(l)?|yunjiasu.nginx', re.IGNORECASE)

    def check(response_headers, response_body):
        for header in ["X-Server", "Server"]:
            if header in response_headers and PATTERN.search(response_headers[header]):
                return True
        return False

    return check(response_headers, response_body)

def check_Bekchy(response_headers, response_body):
    PATTERN = re.compile(r'bekchy.(-.)?access.denied|(http(s)?:\/\/)(www.)?bekchy.com(\/report)?', re.IGNORECASE)

    def check(response_headers, response_body):
        if PATTERN.search(response_body):
            return True
        return False

    return check(response_headers, response_body)

def check_BIGIP(response_headers, response_body):
    PATTERN = re.compile(r'\ATS\w{4,}=|bigipserver(.i)?|bigipserverinternal|\AF5\Z|^TS[a-zA-Z0-9]{3,8}=|BigIP|BIG-IP|BIGIP|bigipserver', re.IGNORECASE)

    def check(response_headers, response_body):
        for header in ["Server", "Set-Cookie", "Cookie"]:
            if header in response_headers and PATTERN.search(response_headers[header]):
                return True
        return False

    return check(response_headers, response_body)

def check_BinarySEC(response_headers, response_body):
    PATTERN = re.compile(r'x.binarysec.(via|nocache)|binarysec|\bbinarysec\b', re.IGNORECASE)

    def check(response_headers, response_body):
        for header_value in response_headers.values():
            if PATTERN.search(header_value):
                return True
        return False

    return check(response_headers, response_body)

def check_BitNinja(response_headers, response_body):
    PATTERN = re.compile(r'bitninja|security.check.by.bitninja|.>visitor.anti(\S)?robot.validation<.', re.IGNORECASE)

    def check(response_headers, response_body):
        return PATTERN.search(response_body)

    return check(response_headers, response_body)

def check_BlockDos(response_headers, response_body):
    PATTERN = re.compile(r'blockdos\.net', re.IGNORECASE)

    def check(response_headers, response_body):
        if "Server" in response_headers and PATTERN.search(response_headers["Server"]):
            return True
        return False

    return check(response_headers, response_body)

def check_Cerber(response_headers, response_body):
    PATTERN = re.compile(
        r"We're sorry, you are not allowed to proceed</h1>|"
        r"<p>Your request looks suspiciously similar to automated requests from spam posting software or it has been denied by a security policy configured by the website administrator.</p>",
        re.IGNORECASE)

    def check(response_headers, response_body):
        return PATTERN.search(response_body)

    return check(response_headers, response_body)

def check_Chuangyu(response_headers, response_body):
    PATTERN = re.compile(
        r"(http(s)?://(www.)?)?365cyd.(com|net)",
        re.IGNORECASE)

    def check(response_headers, response_body):
        return PATTERN.search(response_body)

    return check(response_headers, response_body)

def check_CiscoACE(response_headers, response_body):
    PATTERN = re.compile(r"ace.xml.gateway", re.IGNORECASE)

    def check(response_headers, response_body):
        return "Server" in response_headers and PATTERN.search(response_headers["Server"])

    return check(response_headers, response_body)

def check_cloudflare(response_headers, response_body):
    pattern = re.compile(
        r"(cloudflare\.ray\.id\.|var\.cloudflare\.|cloudflare\.nginx|\.\.cfduid\=([a-z0-9]{43})?|cf[-|_]ray(\.\.)?([0-9a-f]{16})?[-|_]?(dfw|iad)?|\.\>attention\.required!\.\|\.cloudflare\<\.\+|http(s)?://report(\.uri\.)?cloudflare\.com(/cdn\.cgi(\.beacon/expect\.ct)?)?|ray\.id)",
        re.IGNORECASE
    )
    if (
        "CF-Cache-Status" in response_headers
        or "CF-Ray" in response_headers
        or "CF-Request-ID" in response_headers
        or ("Set-Cookie" in response_headers and re.search(r"__cfduid", response_headers["Set-Cookie"]))
        or ("Expect-CT" in response_headers and re.search(r"cloudflare", response_headers["Expect-CT"]))
        or any(pattern.search(header) for header in response_headers.values())
        or pattern.search(response_body)
    ):
        return True
    return False

def check_CloudFront(response_headers, response_body):
    PATTERN = re.compile(
        r'(?:[a-zA-Z0-9]{,60}\.cloudfront\.net)|'
        r'(?:cloudfront)|'
        r'(?:x\.amz\.cf\.id)|(?:nguardx)',
        re.IGNORECASE)
    
    if (
        "x-amz-cf-id" in response_headers
        or "x-amz-cf-pop" in response_headers
    ):
        return True
    return False

def check_CodeIgniter(response_headers, response_body):
    PATTERN = re.compile(r'the\.uri\.you\.submitted\.has\.disallowed\.characters', re.IGNORECASE)
    if response_headers.get("status", "") in ["400"] and PATTERN.search(response_body):
        return True
    return False

def check_comodo(response_headers, response_body):
    pattern = re.compile(r"protected.by.comodo.waf")

    if "Server" in response_headers and pattern.search(response_headers["Server"]):
        return True
    return False


def check_CSF(response_headers, response_body):
    PATTERN = re.compile(r'.>the.firewall.on.this.server.is.blocking.your.connection.<+', re.IGNORECASE)
    def check(response_headers, response_body):
        if PATTERN.search(response_body):
            return True
        return False

def check_IBMWebsphereDataPowerFirewall(response_headers, response_body):
    PATTERN = re.compile(r'\A(ok|fail)', re.IGNORECASE)
    if "X-Backside-Trans" in response_headers and PATTERN.search(response_headers["X-Backside-Trans"]):
        return True
    return False

def check_DenyAll(response_headers, response_body):
    if "Set-Cookie" in response_headers and re.search(r'\Asessioncookie=', response_headers["Set-Cookie"], re.IGNORECASE):
        return True
    if re.search(r'\Acondition.intercepted', response_body, re.IGNORECASE):
        return True
    return False

def check_DiDiYunWAF(response_headers, response_body):
    PATTERN = re.compile(
        r'((http(s)?:\/\/)(sec-waf.|www.)?didi(static|yun)?.com(\/static\/cloudwafstatic)?|'
        r'didiyun',
        re.IGNORECASE
    )

    if response_headers.get("Server", "") == "DiDi-SLB" and PATTERN.search(response_body):
        return True
    return False

def check_DoDEnterpriseLevelProtectionSystem(response_headers, response_body):
    PATTERN = re.compile(r'dod.enterprise.level.protection.system', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_DOSarrest(response_headers, response_body):
    PATTERN = re.compile(r'(dosarrest|x.dis.request.id)', re.IGNORECASE)
    for header, value in response_headers.items():
        if PATTERN.search(value):
            return True
        return False

def check_dotDefender(response_headers, response_body):
    PATTERN = re.compile(r'dotdefender.blocked.your.request', re.IGNORECASE)
    if "X-dotDefender-Denied" in response_headers and PATTERN.search(response_body):
        return True
    return False

def check_DynamicWebInjectionCheck(response_headers, response_body):
    PATTERN = re.compile(r'dw.inj.check', re.IGNORECASE)
    if response_headers.get("status", "") == "403" and "X-403-Status-By" in response_headers and PATTERN.search(response_headers["X-403-Status-By"]):
        return True
    return False

def check_EdgeCast(response_headers, response_body):
    PATTERN = re.compile(r'\Aecdf', re.IGNORECASE)
    if "Server" in response_headers and PATTERN.search(response_headers["Server"]):
        return True
    return False

def check_ExpressionEngine(response_headers, response_body):
    PATTERN = re.compile(r'(.>error.-.expressionengine<.)|(>:.the.uri.you.submitted.has.disallowed.characters.<.)|(invalid.get.data)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False


def check_FortiWeb(response_headers, response_body):
    PATTERN = re.compile(r'(.>powered.by.fortinet<.|.>fortigate.ips.sensor<.|fortigate|.fgd_icon|\AFORTIWAFSID=|application.blocked.|.fortiGate.application.control|(http(s)?)?:\/\/\w+.fortinet(.\w+:)?|fortigate.hostname|the.page.cannot.be.displayed..please.contact.[^@]+@[^@]+\.[^@]+.for.additional.information)', re.IGNORECASE)
    for header, value in response_headers.items():
        if header == "Set-Cookie" and PATTERN.search(value):
            return True
    if PATTERN.search(response_body):
        return True
    return False

def check_Gladius(response_headers, response_body):
    if "gladius_blockchain_driven_cyber_protection_network_session" in response_headers:
        return True
    return False

def check_GoogleWebServices(response_headers, response_body):
    PATTERN = re.compile(r'(your.client.has.issued.a.malformed.or.illegal.request|your.systems.have.detected.unusual.traffic|block(ed)?.by.g.cloud.security.policy.+)', re.IGNORECASE)
    if response_headers.get("status", "") in ["400", "429", "500"] and PATTERN.search(response_body):
        return True
    return False

def check_GreyWizardProtection(response_headers, response_body):
    PATTERN = re.compile(
        r'(greywizard(\.\d\.\d(\.\d)?)?|grey\.wizard\.block|(http(s)?://)?(\w+.)?greywizard\.com|grey\.wizard)',
        re.IGNORECASE
    )
    for header, value in response_headers.items():
        if header in ["GW-Server", "Server"] and PATTERN.search(value):
            return True
    if PATTERN.search(response_body):
        return True
    return False

def check_IncapsulaWebApplicationFirewall(response_headers, response_body):
    PATTERN = re.compile(r'(incap_ses|visid_incap|incapsula|incapsula.incident.id)', re.IGNORECASE)
    for header, value in response_headers.items():
        if header in ["Set-Cookie", "X-CDN"] and PATTERN.search(value):
            return True
    if PATTERN.search(response_body):
        return True
    return False

def check_INFOSAFE(response_headers, response_body):
    PATTERN = re.compile(r'(infosafe|by.(http(s)?(.\/\/)?)?7i24.(com|net)|infosafe.\d.\d|var.infosafekey=)', re.IGNORECASE)
    for header, value in response_headers.items():
        if header == "Server" and PATTERN.search(value):
            return True
    if PATTERN.search(response_body):
        return True
    return False

def check_Instart(response_headers, response_body):
    PATTERN = re.compile(r'instartrequestid', re.IGNORECASE)
    if ('X-Instart-Request-ID' in response_headers or 'X-Instart-CacheKeyMod' in response_headers) and PATTERN.search(response_body):
        return True
    return False

def check_JanusecApplicationGateway(response_headers, response_body):
    PATTERN = re.compile(r'(janusec|(http(s)?\W+(www.)?)?janusec.(com|net|org))', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_Jiasule(response_headers, response_body):
    PATTERN = re.compile(r'(^jsl(_)?tracking|(__)?jsluid(=)?|notice.jiasule|(static|www|dynamic).jiasule.(com|net))', re.IGNORECASE)
    for header, value in response_headers.items():
        if header in ["Server", "Set-Cookie"] and PATTERN.search(value):
            return True
    return PATTERN.search(response_body) is not None

def check_LiteSpeedGenericProtection(response_headers, response_body):
    PATTERN = re.compile(r'litespeed.web.server', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_MalCare(response_headers, response_body):
    PATTERN = re.compile(r'(?:malcare|(?:.>login.protection<.+.><.+>powered.by<.+.>(?:<.+.>)?(?:.?malcare.-.pro|blogvault)?|.>firewall<.+.><.+>powered.by<.+(?:<.+.>)?(?:.?malcare.-.pro|blogvault)?))', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_ModSecurity(response_headers, response_body):
    PATTERN = re.compile(r'(ModSecurity|NYOB|mod_security|this.error.was.generated.by.mod.security|web.server at|page.you.are.(accessing|trying)?.(to|is)?.(access)?.(is|to)?.(restricted)?|blocked.by.mod.security)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_ModSecurityOWASP(response_headers, response_body):
    PATTERN = re.compile(r'(not.acceptable|additionally\S.a.406.not.acceptable)', re.IGNORECASE)
    if response_headers.get("status", "") == "406" and PATTERN.search(response_body):
        return True
    return False

def check_NexusGuardSecurity(response_headers, response_body):
    PATTERN = re.compile(r'(nexus.?guard|((http(s)?:\/\/)?speresources.)?nexusguard.com.wafpage)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_NginxGenericProtection(response_headers, response_body):
    PATTERN = re.compile(r'(nginx|you.do(not|n.t)?.have.permission.to.access.this.document/)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_PaloAltoFirewall(response_headers, response_body):
    PATTERN = re.compile(r'(has.been.blocked.in.accordance.with.company.policy|.>Virus.Spyware.Download.Blocked<.)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_PerimeterX(response_headers, response_body):
    PATTERN = re.compile(r'(access.to.this.page.has.been.denied.because.we.believe.you.are.using.automation.tool|http(s)?:\/\/(www.)?perimeterx.\w+.whywasiblocked|perimeterx|(..)?client.perimeterx.*\/[a-zA-Z]{8,15}\/*.*.js)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_pkSecurityModule(response_headers, response_body):
    PATTERN = re.compile(r'(.>pkSecurityModule\W..\WSecurity.Alert<.|.http(s)?.\/\/([w]{3})?.kitnetwork.\w|.>A.safety.critical.request.was.discovered.and.blocked.<.)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_PowerfulFirewall(response_headers, response_body):
    PATTERN = re.compile(r'(Powerful Firewall|http(s)?...tiny.cc.powerful.firewall)', re.IGNORECASE)
    if response_headers.get("status", "") == 403 and PATTERN.search(response_body):
        return True
    return False

def check_Radware(response_headers, response_body):
    PATTERN = re.compile(r'(\bcloudwebsec.radware.com\b|>unauthorized.activity.has.been.detected<|with.the.following.case.number.in.its.subject:.\d+)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_Reblaze(response_headers, response_body):
    pattern = re.compile(r'rhino-core-shield', re.IGNORECASE)

    def matches_header(headers, pattern):
        for header in headers:
            if pattern.search(header):
                return True
        return False

    def matches_body(body, pattern):
        return pattern.search(body)

    def builder(headers, body):
        if matches_header(headers, pattern) or matches_body(body, pattern):
            return True
        return False

    if builder(response_headers.values(), response_body):
        return True
    return False

def check_RSFirewall(response_headers, response_body):
    PATTERN = re.compile(r'(com.rsfirewall.403.forbidden|com.rsfirewall.event|(\b)?rsfirewall(\b)?|rsfirewall)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_SabreFirewall(response_headers, response_body):
    PATTERN = re.compile(r'dxsupport@sabre.com', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_SafeDogWAF(response_headers, response_body):
    PATTERN = re.compile(r'((http(s)?)?(:\/\/)?(www|404|bbs|\w+)?.safedog.\w|waf(.?\d+.?\d+))', re.IGNORECASE)
    for header, value in response_headers.items():
        if header == "X-Powered-By" and PATTERN.search(value):
            return True
    if PATTERN.search(response_body):
        return True
    return False

def check_SecuPress(response_headers, response_body):
    PATTERN = re.compile(r'(<h\d*>secupress<.|block.id.{1,2}bad.url.contents.<.)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_ImpervaSecureSphere(response_headers, response_body):
    PATTERN = re.compile(r'(<h2>error<.h2>|<title>error<.title>|<b>error<.b>|<td.class="(?:errormessage|error)".height="[0-9]{1,3}".width="[0-9]{1,3}">|the.incident.id.(?:is|number.is).|page.cannot.be.displayed|contact.support.for.additional.information)', re.IGNORECASE)
    FALLBACK_PATTERN = re.compile(r'the.destination.of.your.request.has.not.been.configured', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    if FALLBACK_PATTERN.search(response_body):
        return True
    return False

def check_ShadowDaemonOpensource(response_headers, response_body):
    PATTERN = re.compile(r'(<h\d>\d{3}.forbidden<.h\d>|request.forbidden.by.administrative.rules.)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_ShieldSecurity(response_headers, response_body):
    PATTERN = re.compile(r'(blocked.by.the.shield|transgression(\(s\))?.against.this|url.{1,2}form.or.cookie.data.wasn.t.appropriate)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_SiteGuardLite(response_headers, response_body):
    PATTERN = re.compile(r'(>Powered.by.SiteGuard.Lite<|refuse.to.browse)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_SonicWALLFirewall(response_headers, response_body):
    PATTERN = re.compile(r'(This.request.is.blocked.by.the.SonicWALL|Dell.SonicWALL|Web.Site.Blocked.+\bnsa.banner|SonicWALL|.>policy.this.site.is.blocked<.)', re.IGNORECASE)
    if "Server" in response_headers:
        if PATTERN.search(response_headers["Server"]):
            return True
    if PATTERN.search(response_body):
        return True
    return False

def check_SquidProxy(response_headers, response_body):
    PATTERN = re.compile(r'(access control configuration prevents|X.Squid.Error)', re.IGNORECASE)
    if "eventsquid-id" in response_headers:
        return True
    for header in response_headers:
        if re.search(r'squid', header, re.IGNORECASE):
            return True
        if PATTERN.search(header):
            return True
    if PATTERN.search(response_body):
        return True
    return False

def check_StackpathWAF(response_headers, response_body):
    PATTERN = re.compile(r'(action.that.triggered.the.service.and.blocked|<h2>sorry,.you.have.been.blocked.?<.h2>)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

def check_StingrayApplicationFirewall(response_headers, response_body):
    PATTERN = re.compile(r'\AX-Mapping-', re.IGNORECASE)
    if "Set-Cookie" in response_headers:
        if PATTERN.search(response_headers["Set-Cookie"]):
            return True
    return False

def check_StrictHttpFirewall(response_headers, response_body):
    PATTERN = re.compile(r'the.request.was.rejected.because.the.url.contained.a.potentially.malicious.string', re.IGNORECASE)
    if response_body:
        if PATTERN.search(response_body):
            return True
    return False

def check_SucuriFirewall(response_headers, response_body):
    PATTERN = re.compile(r'(access.denied.-.sucuri.website.firewall|sucuri.webSite.firewall.-.cloudProxy.-.access.denied|questions\?.+cloudproxy@sucuri\.net|http(s)?.\/\/(cdn|supportx.)?sucuri(.net|com)?)', re.IGNORECASE)
    if "X-Sucuri-Block" in response_headers:
        return True
    if "Server" in response_headers:
        if "Sucuri/Cloudproxy" in response_headers["Server"]:
            return True
    if PATTERN.search(response_body):
        return True
    return False

def check_Teros(response_headers, response_body):
    PATTERN = re.compile(r'st8(id|.wa|.wf)?.?(\d+|\w+)?', re.IGNORECASE)
    for key, value in response_headers.items():
        if PATTERN.search(value):
            return True
    return False

def check_UEWaf(response_headers, response_body):
    PATTERN = re.compile(r'(http(s)?://ucloud|uewaf(.deny.pages))', re.IGNORECASE)
    if response_body:
        if PATTERN.search(response_body):
            return True
    return False

def check_URLScan(response_headers, response_body):
    PATTERN = re.compile(r'rejected.by.url.scan', re.IGNORECASE)
    if "Location" in response_headers:
        if PATTERN.search(response_headers["Location"]):
            return True
        if PATTERN.search(response_body):
            return True
    return False

def check_ViettelWAF(response_headers, response_body):
    PATTERN = re.compile(r'(<title>access.denied(...)?viettel.waf</title>|viettel.waf.system|(http(s).//)?cloudrity.com(.vn)?)', re.IGNORECASE)
    if response_body:
        if PATTERN.search(response_body):
            return True
    return False

def check_WallarmWAF(response_headers, response_body):
    PATTERN = re.compile(r'nginix.wallarm', re.IGNORECASE)
    if "Server" in response_headers:
        if PATTERN.search(response_headers["Server"]):
            return True
    return False

def check_WatchGuardWAF(response_headers, response_body):
    PATTERN = re.compile(r'(request.denied.by.)?watchguard.firewall|watchguard(.technologies(.inc)?)?', re.IGNORECASE)
    if "Server" in response_headers:
        if "watchguard" in response_headers["Server"]:
            return True
    if PATTERN.search(response_body):
        return True
    return False

def check_WebKnightApplicationFirewall(response_headers, response_body):
    PATTERN = re.compile(r'webknight', re.IGNORECASE)
    if "Server" in response_headers:
        if PATTERN.search(response_headers["Server"]):
            return True
    return False

def check_West236Firewall(response_headers, response_body):
    PATTERN = re.compile(r'wt\d*cdn', re.IGNORECASE)
    if "X-Cache" in response_headers:
        if PATTERN.search(response_headers["X-Cache"]):
            return True
    return False

def check_IBMSecurityAccessManager(response_headers, response_body):
    PATTERN = re.compile(r'(webseal.error.message.template|webseal.server.received.an.invalid.http.request)', re.IGNORECASE)
    if "Server" in response_headers:
        if response_headers["Server"] == "WebSEAL":
            return True
    if PATTERN.search(response_body):
        return True
    return False

def check_Wordfence(response_headers, response_body):
    pattern = re.compile(r'(generated.by.wordfence|your.access.to.this.site.has.been.limited|.>wordfence<.)', re.IGNORECASE)
    if pattern.search(response_body):
        return True
    return False

def check_Xuanwudun(response_headers, response_body):
    pattern = re.compile(r'class=.(db)?waf.?(-row.)?>', re.IGNORECASE)
    if response_headers.get("status", "") == "403":
        if pattern.search(response_body):
            return True
    return False

def check_WTSWAF(response_headers, response_body):
    pattern = re.compile(r'(<title>)?wts.wa(f)?(\w+(\w+(\w+)?)?)?', re.IGNORECASE)
    if pattern.search(response_body):
        return True
    return False

def check_Yundun(response_headers, response_body):
    PATTERN = re.compile(r'(YUNDUN|^yd.cookie=|http(s)?:\/\/(www\.)?(\w+.)?yundun(.com)?|<title>403 Forbidden: access is denied[\s\S]*<\/title>)', re.IGNORECASE)
    if any(PATTERN.search(header) for header in response_headers.values()):
        return True
    if response_headers.get("status", "") == 461 and PATTERN.search(response_body):
        return True
    return False

def check_Yunsuo(response_headers, response_body):
    PATTERN = re.compile(r'(<img.class=.yunsuologo.|yunsuo.session)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    for header_value in response_headers.values():
        if PATTERN.search(header_value):
            return True
    return False

def check_ZscalerCloudFirewall(response_headers, response_body):
    PATTERN = re.compile(r'(zscaler|zscaler(\.(\d+(\.(\d+)?)?)?)?)', re.IGNORECASE)
    if "Server" in response_headers:
        if re.search(PATTERN, response_headers["Server"]):
            return True
    if re.search(PATTERN, response_body):
        return True
    return False


wafs = [
    {
        "name": "360WZWS ",
        "check_function": check_360wzws
    },
    {
        "name": "AeScure ",
        "check_function": check_aesecure
    },
    {
        "name": "AirLock ",
        "check_function": check_airlock
    },
    {
        "name": "Akamai ",
        "check_function": check_akamaighost
    },
    {
        "name": "Alert Logic ",
        "check_function": check_alert_logic
    },        
    {
        "name": "Aliyundun ",
        "check_function": check_aliyundun
    },
    {
        "name": "Anquanbao ",
        "check_function": check_anquanbao
    },
    {
        "name": "AnYu ",
        "check_function": check_anyu
    },
    {
        "name": "Apache ",
        "check_function": check_apache
    },
    {
        "name": "Armor ",
        "check_function": check_armor
    },
    {
        "name": "ASP .NET ",
        "check_function": check_ASPNET
    },
    {
        "name": "ASM ",
        "check_function": check_application_security_manager
    },
    {
        "name": "Apache Traffic Server ",
        "check_function": check_ApacheTrafficServer
    },
    {
        "name": "Amazon AWS ",
        "check_function": check_AmazonWebServices 
    },
    {
        "name": "Baidu ",
        "check_function": check_Baidu
    },
    {
        "name": "Bekchy ",
        "check_function": check_Bekchy
    },
    {
        "name": "BIG-IP ",
        "check_function": check_BIGIP
    },     
    {
        "name": "BinarySEC ",
        "check_function": check_BinarySEC
    },
    {
        "name": "BitNinja ",
        "check_function": check_BitNinja
    },
    {
        "name": "BlockDos ",
        "check_function": check_BlockDos
    },
    {
        "name": "Cerber ",
        "check_function": check_Cerber
    },
    {
        "name": "Chuangyu ",
        "check_function": check_Chuangyu
    },
    {
        "name": "Cisco ACE ",
        "check_function": check_CiscoACE
    },
    {
        "name": "Cloudflare ",
        "check_function": check_cloudflare
    },
    {
        "name": "CloudFront ",
        "check_function": check_CloudFront
    },
    {
        "name": "CodeIgniter ",
        "check_function": check_CodeIgniter
    },
    {
        "name": "Comodo ",
        "check_function": check_comodo
    },
    {
        "name": "ConfigServer ",
        "check_function": check_CSF
    },
    {
        "name": "DotDefender ",
        "check_function": check_dotDefender
    },
    {
        "name": "DenyAll ",
        "check_function": check_DenyAll
    },
    {
        "name": "DoD ",
        "check_function": check_DoDEnterpriseLevelProtectionSystem
    },
    {
        "name": "DOSarrest ",
        "check_function": check_DOSarrest
    },
    {
        "name": "dotDefender ",
        "check_function": check_dotDefender
    },
    {
        "name": "Dynamic Web Injection Check ",
        "check_function": check_DynamicWebInjectionCheck
    },
    {
        "name": "EdgeCast ",
        "check_function": check_EdgeCast
    },
    {
        "name": "ExpressionEngine ",
        "check_function": check_ExpressionEngine
    },        
    {
        "name": "FortiWeb ",
        "check_function": check_FortiWeb
    },
    {
        "name": "Gladius ",
        "check_function": check_Gladius
    },
    {
        "name": "Google Web Services ",
        "check_function": check_GoogleWebServices
    },
    {
        "name": "Grey Wizard Protection ",
        "check_function": check_GreyWizardProtection
    },
    {
        "name": "IBM Security Access Manager",
        "check_function": check_IBMSecurityAccessManager
    },
    {
        "name": "IBM Websphere DataPower Firewall ",
        "check_function": check_IBMWebsphereDataPowerFirewall
    }, 
    {
        "name": "Imperva SecureSphere ",
        "check_function": check_ImpervaSecureSphere
    },
    {
        "name": "Incapsula ",
        "check_function": check_IncapsulaWebApplicationFirewall
    },
    {
        "name": "INFOSAFE ",
        "check_function": check_INFOSAFE
    },
    {
        "name": "Instart ",
        "check_function": check_Instart
    },
    {
        "name": "Janusec ",
        "check_function": check_JanusecApplicationGateway
    },
    {
        "name": "JetShield ",
        "check_function": check_Jiasule
    },
    {
        "name": "Joomla RSFirewall ",
        "check_function": check_RSFirewall
    },
    {
        "name": "LiteSpeed ",
        "check_function": check_LiteSpeedGenericProtection
    },
    {
        "name": "MalCare ",
        "check_function": check_MalCare
    },
    {
        "name": "ModSecurity ",
        "check_function": check_ModSecurity
    },
    {
        "name": "ModSecurity OWASP ",
        "check_function": check_ModSecurityOWASP
    },
    {
        "name": "Nexus Guard Security ",
        "check_function": check_NexusGuardSecurity
    },
    {
        "name": "Nginx Generic Protection ",
        "check_function": check_NginxGenericProtection
    },
    {
        "name": "Palo Alto ",
        "check_function": check_PaloAltoFirewall
    },
    {
        "name": "PerimeterX ",
        "check_function": check_PerimeterX
    },
    {
        "name": "pkSecurityModule ",
        "check_function": check_pkSecurityModule
    },
    {
        "name": "Powerful ",
        "check_function": check_PowerfulFirewall
    },
    {
        "name": "Radware ",
        "check_function": check_Radware
    },
    {
        "name": "Reblaze ",
        "check_function": check_Reblaze
    },
    {
        "name": "Sabre ",
        "check_function": check_SabreFirewall
    },
    {
        "name": "SafeDog ",
        "check_function": check_SafeDogWAF
    },
    {
        "name": "SecuPress ",
        "check_function": check_SecuPress
    },
    {
        "name": "ShadowDaemon ",
        "check_function": check_ShadowDaemonOpensource
    },
    {
        "name": "ShieldSecurity ",
        "check_function": check_ShieldSecurity
    },
    {
        "name": "Site Guard Lite ",
        "check_function": check_SiteGuardLite
    },
    {
        "name": "SonicWALL ",
        "check_function": check_SonicWALLFirewall
    },
    {
        "name": "Squid Proxy ",
        "check_function": check_SquidProxy
    },
    {
        "name": "Stackpath ",
        "check_function": check_StackpathWAF
    },
    {
        "name": "Stingray ",
        "check_function": check_StingrayApplicationFirewall
    },
    {
        "name": "Strict ",
        "check_function": check_StrictHttpFirewall
    },
    {
        "name": "Sucuri ",
        "check_function": check_SucuriFirewall
    },
    {
        "name": "Teros ",
        "check_function": check_Teros
    },
    {
        "name": "UEWaf ",
        "check_function": check_UEWaf
    },
    {
        "name": "URLScan ",
        "check_function": check_URLScan
    },
    {
        "name": "Viettel ",
        "check_function": check_ViettelWAF
    },
    {
        "name": "Wallarm ",
        "check_function": check_WallarmWAF
    },
    {
        "name": "WatchGuard ",
        "check_function": check_WatchGuardWAF
    },
    {
        "name": "WebKnight ",
        "check_function": check_WebKnightApplicationFirewall
    },
    {
        "name": "West236 ",
        "check_function": check_West236Firewall
    },
    {
        "name": "Wordfence ",
        "check_function": check_Wordfence
    },
    {
        "name": "Xuanwudun ",
        "check_function": check_Xuanwudun
    },
    {
        "name": "WTSWAF ",
        "check_function": check_WTSWAF
    },
    {
        "name": "Yundun ",
        "check_function": check_Yundun
    },    
    {
        "name": "Yunsuo ",
        "check_function": check_Yunsuo
    },
    {
        "name": "Zscaler ",
        "check_function": check_ZscalerCloudFirewall
    },

]

waf_detected = False
waf_message_printed = False
def check_waf(response_headers, response_body):
    global waf_detected
    global waf_message_printed
    for waf in wafs:
        if waf["check_function"](response_headers, response_body):
            if not waf_detected:
                waf_detected = True
                print(colored("[+] Detected WAF: " + waf["name"], 'green', attrs=['bold']))
                break
    if not waf_detected and not waf_message_printed:
        waf_message_printed = True
        print(colored("[+] No WAF detected", 'yellow', attrs=['bold']))



       	
