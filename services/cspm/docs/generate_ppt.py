"""Generate a feature showcase PPT for the multi-cloud CSPM platform."""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR

# ---------- color palette ----------
NAVY      = RGBColor(0x0B, 0x1F, 0x3A)
DEEP_BLUE = RGBColor(0x13, 0x2C, 0x55)
ACCENT    = RGBColor(0x2D, 0x9C, 0xDB)
TEAL      = RGBColor(0x1A, 0xBC, 0x9C)
ORANGE    = RGBColor(0xE6, 0x7E, 0x22)
RED       = RGBColor(0xC0, 0x39, 0x2B)
YELLOW    = RGBColor(0xF1, 0xC4, 0x0F)
GRAY_BG   = RGBColor(0xF4, 0xF6, 0xF8)
GRAY_DARK = RGBColor(0x34, 0x49, 0x5E)
WHITE     = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT_GRY = RGBColor(0xDC, 0xE0, 0xE6)

prs = Presentation()
prs.slide_width  = Inches(13.333)
prs.slide_height = Inches(7.5)
SW, SH = prs.slide_width, prs.slide_height

# ---------- helpers ----------
def add_blank_slide():
    return prs.slides.add_slide(prs.slide_layouts[6])

def add_rect(slide, x, y, w, h, fill, line=None):
    shp = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, w, h)
    shp.fill.solid()
    shp.fill.fore_color.rgb = fill
    if line is None:
        shp.line.fill.background()
    else:
        shp.line.color.rgb = line
    shp.shadow.inherit = False
    return shp

def add_rounded(slide, x, y, w, h, fill, line=None):
    shp = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, w, h)
    shp.fill.solid()
    shp.fill.fore_color.rgb = fill
    if line is None:
        shp.line.fill.background()
    else:
        shp.line.color.rgb = line
    shp.shadow.inherit = False
    return shp

def add_text(slide, x, y, w, h, text, *, size=14, bold=False, color=GRAY_DARK,
             align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP, font="Calibri"):
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.05)
    tf.margin_top = tf.margin_bottom = Inches(0.02)
    tf.vertical_anchor = anchor
    lines = text.split("\n") if isinstance(text, str) else text
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        r = p.add_run()
        r.text = line
        r.font.size = Pt(size)
        r.font.bold = bold
        r.font.color.rgb = color
        r.font.name = font
    return tb

def page_header(slide, title, subtitle=None):
    # top navy band
    add_rect(slide, 0, 0, SW, Inches(0.9), NAVY)
    # left accent stripe
    add_rect(slide, 0, Inches(0.9), Inches(0.18), SH - Inches(0.9), ACCENT)
    add_text(slide, Inches(0.45), Inches(0.18), Inches(11.5), Inches(0.5),
             title, size=26, bold=True, color=WHITE)
    if subtitle:
        add_text(slide, Inches(0.45), Inches(0.55), Inches(11.5), Inches(0.35),
                 subtitle, size=12, color=RGBColor(0xCB, 0xD7, 0xE3))
    # footer
    add_text(slide, Inches(0.4), SH - Inches(0.32), Inches(12), Inches(0.25),
             "Multi-Cloud CSPM Platform  |  AWS • Azure • GCP",
             size=9, color=GRAY_DARK, align=PP_ALIGN.LEFT)
    add_text(slide, SW - Inches(0.9), SH - Inches(0.32), Inches(0.5), Inches(0.25),
             f"{len(prs.slides.__iter__.__self__._sldIdLst) }",
             size=9, color=GRAY_DARK, align=PP_ALIGN.RIGHT)

def section_divider(title, subtitle=""):
    s = add_blank_slide()
    add_rect(s, 0, 0, SW, SH, NAVY)
    add_rect(s, Inches(0.6), Inches(3.0), Inches(0.6), Inches(0.08), ACCENT)
    add_text(s, Inches(0.6), Inches(3.1), Inches(12), Inches(1.0),
             title, size=44, bold=True, color=WHITE)
    if subtitle:
        add_text(s, Inches(0.6), Inches(4.2), Inches(12), Inches(0.6),
                 subtitle, size=18, color=RGBColor(0xB7, 0xC5, 0xD8))
    add_text(s, Inches(0.6), SH - Inches(0.55), Inches(12), Inches(0.3),
             "PROACTIVE CLOUD SECURITY POSTURE MANAGEMENT", size=10,
             color=ACCENT)

def feature_card(slide, x, y, w, h, title, body, accent=ACCENT):
    add_rounded(slide, x, y, w, h, WHITE, line=LIGHT_GRY)
    add_rect(slide, x, y, Inches(0.08), h, accent)
    add_text(slide, x + Inches(0.18), y + Inches(0.1), w - Inches(0.25), Inches(0.4),
             title, size=13, bold=True, color=NAVY)
    add_text(slide, x + Inches(0.18), y + Inches(0.5), w - Inches(0.25), h - Inches(0.55),
             body, size=10, color=GRAY_DARK)

def stat_card(slide, x, y, w, h, number, label, color):
    add_rounded(slide, x, y, w, h, color, line=None)
    add_text(slide, x, y + Inches(0.18), w, Inches(0.7),
             number, size=36, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    add_text(slide, x, y + Inches(0.95), w, Inches(0.4),
             label, size=11, color=WHITE, align=PP_ALIGN.CENTER)

# ============================================================
# SLIDE 1 — TITLE
# ============================================================
s = add_blank_slide()
add_rect(s, 0, 0, SW, SH, NAVY)
# diagonal accent
acc = s.shapes.add_shape(MSO_SHAPE.RIGHT_TRIANGLE, Inches(8.3), Inches(0), Inches(5.0), SH)
acc.fill.solid(); acc.fill.fore_color.rgb = DEEP_BLUE; acc.line.fill.background()
add_rect(s, 0, Inches(3.05), Inches(0.5), Inches(0.08), ACCENT)
add_text(s, Inches(0.7), Inches(2.2), Inches(11), Inches(0.5),
         "MULTI-CLOUD CSPM PLATFORM", size=14, bold=True, color=ACCENT)
add_text(s, Inches(0.7), Inches(2.6), Inches(11), Inches(1.4),
         "Unified Cloud Security &\nCompliance, Reinvented.",
         size=44, bold=True, color=WHITE)
add_text(s, Inches(0.7), Inches(4.4), Inches(10), Inches(0.6),
         "AWS • Azure • GCP  —  Vulnerability scanning, threat detection,",
         size=15, color=RGBColor(0xCB, 0xD7, 0xE3))
add_text(s, Inches(0.7), Inches(4.7), Inches(10), Inches(0.6),
         "compliance, drift control, and auto-remediation in one platform.",
         size=15, color=RGBColor(0xCB, 0xD7, 0xE3))
add_rounded(s, Inches(0.7), Inches(5.7), Inches(3.3), Inches(0.5), ACCENT)
add_text(s, Inches(0.7), Inches(5.78), Inches(3.3), Inches(0.4),
         "SELF-HOSTED  •  NO PER-RESOURCE COST",
         size=11, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
add_text(s, Inches(0.7), SH - Inches(0.6), Inches(11), Inches(0.3),
         "Feature Showcase  •  Product Overview", size=11, color=RGBColor(0xB7, 0xC5, 0xD8))

# ============================================================
# SLIDE 2 — THE PROBLEM / WHY
# ============================================================
s = add_blank_slide()
page_header(s, "The Cloud Security Problem", "Why most teams are still flying blind")
y0 = Inches(1.2)
problems = [
    ("Fragmented Tooling", "Separate vendors for vuln scan, CSPM, threat detection, compliance — each charging per-asset.", RED),
    ("Per-Resource Pricing", "Wiz, Orca, Prisma Cloud cost ramps non-linearly as cloud footprint grows.", ORANGE),
    ("AWS Service Lock-in", "GuardDuty + Inspector + Macie + Config + Security Hub bills add up; data leaves your account.", YELLOW),
    ("Reactive, Not Proactive", "Findings arrive — but who fixed it, when, and against which baseline? Nobody knows.", DEEP_BLUE),
]
col_w = Inches(2.95); gap = Inches(0.15)
for i, (t, b, c) in enumerate(problems):
    x = Inches(0.45) + (col_w + gap) * i
    add_rounded(s, x, y0, col_w, Inches(2.2), WHITE, line=LIGHT_GRY)
    add_rect(s, x, y0, col_w, Inches(0.5), c)
    add_text(s, x, y0 + Inches(0.08), col_w, Inches(0.4),
             t, size=13, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    add_text(s, x + Inches(0.2), y0 + Inches(0.65), col_w - Inches(0.4), Inches(1.5),
             b, size=11, color=GRAY_DARK)

# our answer
add_rounded(s, Inches(0.45), Inches(3.7), Inches(12.5), Inches(2.5), GRAY_BG, line=LIGHT_GRY)
add_text(s, Inches(0.7), Inches(3.85), Inches(12), Inches(0.5),
         "Our Answer — One Platform, Three Clouds, Zero Lock-in",
         size=18, bold=True, color=NAVY)
add_text(s, Inches(0.7), Inches(4.35), Inches(12), Inches(1.8),
         "• 70+ purpose-built scanners across AWS, Azure & GCP — no third-party AWS services required\n"
         "• GuardDuty-equivalent threat detection built on free CloudTrail APIs\n"
         "• Container CVE scanning without AWS Inspector — uses OSV.dev directly\n"
         "• ML anomaly detection, drift baselines, auto-remediation with approval gating\n"
         "• Self-hosted: your data, your infrastructure, predictable cost",
         size=13, color=GRAY_DARK)

# ============================================================
# SLIDE 3 — PLATFORM AT A GLANCE (stats)
# ============================================================
s = add_blank_slide()
page_header(s, "Platform at a Glance", "What you get out of the box")
stats = [
    ("70+", "Cloud Scanners",     ACCENT),
    ("3",   "Cloud Providers",    TEAL),
    ("31",  "UI Pages",           DEEP_BLUE),
    ("41",  "Data Models",        ORANGE),
    ("7",   "Async Workers",      RED),
    ("6",   "Compliance Frameworks", GRAY_DARK),
]
y = Inches(1.4); w = Inches(1.95); h = Inches(1.5); gap = Inches(0.12)
for i, (n, l, c) in enumerate(stats):
    x = Inches(0.55) + (w + gap) * i
    stat_card(s, x, y, w, h, n, l, c)

# bottom feature pillars
pillars = [
    ("Multi-Cloud Coverage", "AWS · Azure · GCP scanners share one engine, one schema, one UI.", ACCENT),
    ("Detect → Decide → Remediate", "Findings flow into anomaly engine, approvals, auto-revert.", TEAL),
    ("Compliance Built-in", "PCI-DSS, SOC2, ISO27001, HIPAA, CIS, GDPR mapped automatically.", ORANGE),
    ("Self-Hosted by Design", "PostgreSQL + Redis + BullMQ — runs on a single VM or Kubernetes.", DEEP_BLUE),
]
y2 = Inches(3.2); cw = Inches(3.05); gap = Inches(0.12)
for i, (t, b, c) in enumerate(pillars):
    x = Inches(0.55) + (cw + gap) * i
    feature_card(s, x, y2, cw, Inches(1.7), t, b, accent=c)

# tagline
add_rounded(s, Inches(0.55), Inches(5.3), Inches(12.3), Inches(1.4), NAVY)
add_text(s, Inches(0.55), Inches(5.5), Inches(12.3), Inches(0.5),
         "One platform.  Three clouds.  Zero per-resource pricing.",
         size=22, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
add_text(s, Inches(0.55), Inches(6.05), Inches(12.3), Inches(0.5),
         "Replaces Wiz / Orca / Prisma + GuardDuty + Inspector + Macie at a fraction of the cost.",
         size=13, color=RGBColor(0xCB, 0xD7, 0xE3), align=PP_ALIGN.CENTER)

# ============================================================
# SLIDE 4 — ARCHITECTURE
# ============================================================
s = add_blank_slide()
page_header(s, "Architecture", "Monorepo: api  ·  web  ·  scanner engine  ·  workers")

# 5 column layers
layers = [
    ("UI Layer",   "React 18\nTanStack Query v5\nTailwind + lucide", TEAL),
    ("API Layer",  "Express + Prisma\nJWT auth\n26 REST routes",      ACCENT),
    ("Workers",    "BullMQ + Redis\n7 async workers\nScan · Threat · Drift", ORANGE),
    ("Scanner Engine", "src/scanners/*\nPer-region orchestration\n70+ scanners",  DEEP_BLUE),
    ("Data Layer", "PostgreSQL\nPrisma ORM\n41 models", GRAY_DARK),
]
y = Inches(1.2); w = Inches(2.45); gap = Inches(0.15); h = Inches(2.5)
for i, (t, b, c) in enumerate(layers):
    x = Inches(0.45) + (w + gap) * i
    add_rounded(s, x, y, w, h, WHITE, line=LIGHT_GRY)
    add_rect(s, x, y, w, Inches(0.6), c)
    add_text(s, x, y + Inches(0.12), w, Inches(0.4),
             t, size=14, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    add_text(s, x + Inches(0.2), y + Inches(0.75), w - Inches(0.4), h - Inches(0.85),
             b, size=11, color=GRAY_DARK)

# flow strip
add_rounded(s, Inches(0.45), Inches(4.0), Inches(12.5), Inches(0.55), GRAY_BG)
add_text(s, Inches(0.55), Inches(4.07), Inches(12.3), Inches(0.4),
         "User triggers scan  →  Job queued  →  Scanner engine fans out per region  "
         " →  Findings deduplicated  →  Compliance + anomaly engines  →  Dashboard + alerts",
         size=11, bold=True, color=NAVY, align=PP_ALIGN.CENTER)

# integrations row
add_text(s, Inches(0.45), Inches(4.75), Inches(12), Inches(0.4),
         "Integrations & Outputs", size=15, bold=True, color=NAVY)
integ = ["Slack", "Email", "Jira / ServiceNow", "Splunk / DataDog", "PDF Reports",
         "Scheduled Reports", "Webhooks", "S3 Export"]
ix = Inches(0.45)
for label in integ:
    cw = Inches(1.55)
    add_rounded(s, ix, Inches(5.2), cw, Inches(0.55), WHITE, line=ACCENT)
    add_text(s, ix, Inches(5.27), cw, Inches(0.4),
             label, size=11, bold=True, color=ACCENT, align=PP_ALIGN.CENTER)
    ix += cw + Inches(0.07)

add_text(s, Inches(0.45), Inches(6.0), Inches(12.5), Inches(0.4),
         "Tech Stack", size=15, bold=True, color=NAVY)
add_text(s, Inches(0.45), Inches(6.35), Inches(12.5), Inches(0.7),
         "Node.js 18+ · TypeScript · Express · Prisma · PostgreSQL · Redis · BullMQ · React 18 · "
         "TanStack Query v5 · Tailwind · AWS SDK v3 · Azure ARM · GCP REST APIs · OSV.dev",
         size=12, color=GRAY_DARK)

# ============================================================
# SLIDE 5 — AWS SCANNERS
# ============================================================
s = add_blank_slide()
page_header(s, "AWS Coverage — 25+ Native Scanners",
            "Built on AWS SDK v3 — no AWS Inspector / GuardDuty / Macie license required")
aws_groups = [
    ("Identity & Access", "IAM · Secrets Manager · KMS · SSM · ACM", TEAL),
    ("Compute & Containers", "EC2 · Lambda · ECS · ECR · EBS", ACCENT),
    ("Networking & Edge",   "VPC · ELB/ALB · CloudFront · API Gateway · WAF", DEEP_BLUE),
    ("Storage & Data",      "S3 · DynamoDB · RDS · Redshift · ElastiCache", ORANGE),
    ("Logging & Audit",     "CloudTrail · CloudWatch · SNS · SQS", GRAY_DARK),
    ("Threat Detection",    "Threat Scanner (GuardDuty-equivalent, free)", RED),
]
y = Inches(1.2); cw = Inches(4.05); ch = Inches(1.3); gap = Inches(0.1)
for i, (t, b, c) in enumerate(aws_groups):
    col = i % 3; row = i // 3
    x = Inches(0.45) + (cw + gap) * col
    yy = y + (ch + gap) * row
    add_rounded(s, x, yy, cw, ch, WHITE, line=LIGHT_GRY)
    add_rect(s, x, yy, Inches(0.08), ch, c)
    add_text(s, x + Inches(0.2), yy + Inches(0.1), cw - Inches(0.3), Inches(0.4),
             t, size=13, bold=True, color=NAVY)
    add_text(s, x + Inches(0.2), yy + Inches(0.5), cw - Inches(0.3), ch - Inches(0.55),
             b, size=11, color=GRAY_DARK)

# highlights
add_rounded(s, Inches(0.45), Inches(4.45), Inches(12.5), Inches(2.55), GRAY_BG, line=LIGHT_GRY)
add_text(s, Inches(0.65), Inches(4.55), Inches(12), Inches(0.4),
         "AWS Highlights", size=15, bold=True, color=NAVY)
highlights = [
    ("ECR Container CVE", "Pulls layers via Docker Registry v2 → parses Debian/Alpine/npm/PyPI/Ruby/Go packages → OSV.dev API. Smart-skip on unchanged images."),
    ("EC2 Network Reachability", "3-layer correlation: public IP + IGW route + SG open to 0.0.0.0/0 — eliminates false positives."),
    ("Lambda Runtime + CVEs", "EOL runtime detection + CVE fingerprinting per vuln (no collisions)."),
    ("SG / NACL Aggregation", "One finding per Security Group aggregating all dangerous ports — clean signal, no noise."),
]
yy = Inches(4.95)
for t, b in highlights:
    add_text(s, Inches(0.75), yy, Inches(3.2), Inches(0.45),
             "▸ " + t, size=12, bold=True, color=ACCENT)
    add_text(s, Inches(3.95), yy, Inches(8.9), Inches(0.45),
             b, size=11, color=GRAY_DARK)
    yy += Inches(0.5)

# ============================================================
# SLIDE 6 — AZURE SCANNERS
# ============================================================
s = add_blank_slide()
page_header(s, "Azure Coverage — 32 Scanners",
            "Subscription-wide via ARM + Azure Identity SDK")
azure_groups = [
    ("Identity & Governance", "Entra ID · IAM · Key Vault", TEAL),
    ("Compute & Containers",   "VM · AKS · ACR · App Service · Container Apps · Functions", ACCENT),
    ("Data & Storage",         "Storage · Cosmos DB · SQL · PostgreSQL · MySQL · Redis · Synapse", ORANGE),
    ("Networking",             "Network · NSG · App Gateway · APIM", DEEP_BLUE),
    ("AI / ML / Analytics",    "Cognitive · AML · ADF · Search", GRAY_DARK),
    ("Messaging & IoT",        "Service Bus · Event Hub · Event Grid · IoT Hub", RED),
    ("Ops & Monitoring",       "Log Analytics · Automation · Backup", YELLOW),
    ("Threat Detection",       "Azure threat scanner + activity logs monitor", RED),
]
y = Inches(1.2); cw = Inches(3.05); ch = Inches(1.2); gap = Inches(0.1)
for i, (t, b, c) in enumerate(azure_groups):
    col = i % 4; row = i // 4
    x = Inches(0.45) + (cw + gap) * col
    yy = y + (ch + gap) * row
    add_rounded(s, x, yy, cw, ch, WHITE, line=LIGHT_GRY)
    add_rect(s, x, yy, Inches(0.08), ch, c)
    add_text(s, x + Inches(0.2), yy + Inches(0.08), cw - Inches(0.3), Inches(0.4),
             t, size=12, bold=True, color=NAVY)
    add_text(s, x + Inches(0.2), yy + Inches(0.45), cw - Inches(0.3), ch - Inches(0.5),
             b, size=10, color=GRAY_DARK)

add_rounded(s, Inches(0.45), Inches(4.5), Inches(12.5), Inches(2.5), GRAY_BG, line=LIGHT_GRY)
add_text(s, Inches(0.65), Inches(4.6), Inches(12), Inches(0.4),
         "Azure Highlights", size=15, bold=True, color=NAVY)
hl = [
    "Activity Log streaming — feeds threat monitor for sign-in & role-assignment anomalies",
    "Entra ID checks — privileged role assignments, guest user audit, conditional access gaps",
    "Key Vault — soft-delete, purge protection, RBAC vs Access Policy, network isolation",
    "Storage — anonymous blob access, secure-transfer, infrastructure encryption, firewall rules",
    "AKS — RBAC, network policy, private cluster, control plane logs, image pull policy",
]
yy = Inches(5.05)
for line in hl:
    add_text(s, Inches(0.75), yy, Inches(12), Inches(0.32),
             "•  " + line, size=11, color=GRAY_DARK)
    yy += Inches(0.32)

# ============================================================
# SLIDE 7 — GCP SCANNERS
# ============================================================
s = add_blank_slide()
page_header(s, "GCP Coverage — 13 Scanners",
            "Project-scoped via GCP REST APIs + service accounts")
gcp_items = [
    ("IAM",                "Roles, bindings, primitive role usage, service-account keys", TEAL),
    ("Storage",            "Public buckets, uniform bucket-level access, retention", ACCENT),
    ("Compute Engine",     "Public IPs, OS Login, shielded VM, metadata", DEEP_BLUE),
    ("Cloud SQL",          "Public IP, SSL, automated backups, IAM auth", ORANGE),
    ("GKE",                "Private cluster, workload identity, control plane logs", RED),
    ("Cloud Run",          "Public invocation, secret env vars, ingress controls", GRAY_DARK),
    ("BigQuery",           "Public datasets, CMEK, access policies", TEAL),
    ("KMS",                "Key rotation, location, IAM bindings", ACCENT),
    ("Secret Manager",     "Rotation, replication, IAM exposure", DEEP_BLUE),
    ("Cloud Functions",    "Ingress, runtime EOL, public invocation", ORANGE),
    ("Pub/Sub",            "Topic/sub IAM, allUsers exposure", RED),
    ("Artifact Registry",  "Public repos, vulnerability scan enabled", GRAY_DARK),
    ("Cloud Logging",      "Sinks, retention, log-based metrics", YELLOW),
]
y = Inches(1.2); cw = Inches(2.45); ch = Inches(1.05); gap = Inches(0.1)
for i, (t, b, c) in enumerate(gcp_items):
    col = i % 5; row = i // 5
    if row > 2: break
    x = Inches(0.45) + (cw + gap) * col
    yy = y + (ch + gap) * row
    add_rounded(s, x, yy, cw, ch, WHITE, line=LIGHT_GRY)
    add_rect(s, x, yy, Inches(0.08), ch, c)
    add_text(s, x + Inches(0.18), yy + Inches(0.08), cw - Inches(0.25), Inches(0.4),
             t, size=12, bold=True, color=NAVY)
    add_text(s, x + Inches(0.18), yy + Inches(0.4), cw - Inches(0.25), ch - Inches(0.45),
             b, size=9, color=GRAY_DARK)

add_rounded(s, Inches(0.45), Inches(4.7), Inches(12.5), Inches(2.3), GRAY_BG, line=LIGHT_GRY)
add_text(s, Inches(0.65), Inches(4.8), Inches(12), Inches(0.4),
         "GCP Highlights", size=15, bold=True, color=NAVY)
hl = [
    "Anomaly worker dedicated to GCP — actor baselines, off-hours, geo, volume spikes",
    "CIS GCP benchmark mapped — Foundation / Networking / Logging / IAM categories",
    "Resource fetch service caches inventory — dependency graph across projects",
    "Project-level scoping — same UX as AWS accounts / Azure subscriptions",
]
yy = Inches(5.2)
for line in hl:
    add_text(s, Inches(0.75), yy, Inches(12), Inches(0.32),
             "•  " + line, size=11, color=GRAY_DARK)
    yy += Inches(0.32)

# ============================================================
# SLIDE 8 — THREAT DETECTION
# ============================================================
s = add_blank_slide()
page_header(s, "Threat Detection — GuardDuty Without the License",
            "Active-threat scanner powered by CloudTrail + IAM + resource APIs")
y = Inches(1.2)
cats = [
    ("Defense Evasion",       "CloudTrail logging disabled · Config recorder stopped · SG opened-then-closed", RED),
    ("Unauthorized Access",   "Root API activity · Console login w/o MFA · Brute-force · Dormant key revived", RED),
    ("Persistence / Backdoor","New admin user · New access keys · Admin policy attached · Cross-account trust", ORANGE),
    ("Privilege Escalation",  "iam:* / *:* policy attached · Admin role assumed by unexpected principal", ORANGE),
    ("Reconnaissance",        "IAM enumeration · Mass Describe*/List* calls · Bucket enumeration", YELLOW),
    ("Data Exfiltration",     "Mass S3 delete · EBS/RDS snapshot made public · High-volume GetObject", RED),
]
cw = Inches(4.05); ch = Inches(1.3); gap = Inches(0.1)
for i, (t, b, c) in enumerate(cats):
    col = i % 3; row = i // 3
    x = Inches(0.45) + (cw + gap) * col
    yy = y + (ch + gap) * row
    add_rounded(s, x, yy, cw, ch, WHITE, line=LIGHT_GRY)
    add_rect(s, x, yy, cw, Inches(0.4), c)
    add_text(s, x, yy + Inches(0.06), cw, Inches(0.3),
             t, size=12, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    add_text(s, x + Inches(0.2), yy + Inches(0.5), cw - Inches(0.3), ch - Inches(0.55),
             b, size=10, color=GRAY_DARK)

# bottom bar
add_rounded(s, Inches(0.45), Inches(4.45), Inches(6.15), Inches(2.55), NAVY)
add_text(s, Inches(0.65), Inches(4.55), Inches(5.9), Inches(0.4),
         "How It Works", size=15, bold=True, color=WHITE)
hl = [
    "Targeted CloudTrail LookupEvents calls (~15-20 event filters)",
    "Rate-limited at 2 rps with delays between event types",
    "Time-windowed by severity: 24h critical · 7d high · 24h medium",
    "Evidence object with actor ARN, source IP, raw events",
    "Per-account, not per-region — one efficient pass",
]
yy = Inches(4.95)
for line in hl:
    add_text(s, Inches(0.65), yy, Inches(5.9), Inches(0.32),
             "▸  " + line, size=11, color=WHITE)
    yy += Inches(0.34)

add_rounded(s, Inches(6.78), Inches(4.45), Inches(6.15), Inches(2.55), GRAY_BG, line=LIGHT_GRY)
add_text(s, Inches(6.98), Inches(4.55), Inches(5.8), Inches(0.4),
         "Dedicated UI: /threats", size=15, bold=True, color=NAVY)
ui = [
    "Severity summary bar (CRITICAL/HIGH/MEDIUM counts)",
    "Category filter tabs — Persistence, Recon, Exfil, etc.",
    "Per-row expansion: actor + source IP + raw CloudTrail JSON",
    "Inline remediation guidance per threat type",
    "Time-range picker — 24h / 7d / 30d windows",
    "Wired into PCI 10.6, SOC2 CC7.2, HIPAA 164.312(b)",
]
yy = Inches(4.95)
for line in ui:
    add_text(s, Inches(6.98), yy, Inches(5.8), Inches(0.32),
             "•  " + line, size=11, color=GRAY_DARK)
    yy += Inches(0.32)

# ============================================================
# SLIDE 9 — CONTAINER & CVE SCANNING
# ============================================================
s = add_blank_slide()
page_header(s, "Container & Workload CVE Scanning",
            "Inspector-free image vulnerability detection with OSV.dev")

add_rounded(s, Inches(0.45), Inches(1.2), Inches(6.15), Inches(5.8), WHITE, line=LIGHT_GRY)
add_rect(s, Inches(0.45), Inches(1.2), Inches(6.15), Inches(0.55), ACCENT)
add_text(s, Inches(0.45), Inches(1.27), Inches(6.15), Inches(0.4),
         "ECR Layer Scanning", size=15, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
ecr_body = [
    "▸ ECR auth token → Docker Registry v2 API",
    "▸ Downloads image layers directly (no Inspector)",
    "▸ Parses 7 package manifests:",
    "    Debian dpkg · Alpine apk · npm · PyPI (3 formats)",
    "    Ruby gems · Go modules",
    "▸ Batch query to OSV.dev — 40 pkgs / batch, 200ms delay",
    "▸ Smart-skip — re-scan only newest image since last scan",
    "▸ Hard limits: 80 MB layer · 5 MB file · 300 pkgs/image",
    "▸ Findings split — CVE in main table, config in banner",
    "▸ Resource fingerprint: function::vulnId  (no collisions)",
]
yy = Inches(1.95)
for line in ecr_body:
    add_text(s, Inches(0.65), yy, Inches(5.7), Inches(0.4),
             line, size=11, color=GRAY_DARK)
    yy += Inches(0.36)

# right: Lambda + dedicated UI
add_rounded(s, Inches(6.78), Inches(1.2), Inches(6.15), Inches(2.85), WHITE, line=LIGHT_GRY)
add_rect(s, Inches(6.78), Inches(1.2), Inches(6.15), Inches(0.5), ORANGE)
add_text(s, Inches(6.78), Inches(1.27), Inches(6.15), Inches(0.4),
         "Lambda Runtime & CVE", size=15, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
lb = [
    "▸ EOL runtime detection (Node 14, Python 3.7, etc.)",
    "▸ Per-function CVE fingerprint (no merge collisions)",
    "▸ Direct linkage between function and triggered policies",
    "▸ Surfaced in Container Security & Findings pages",
]
yy = Inches(1.85)
for line in lb:
    add_text(s, Inches(6.98), yy, Inches(5.7), Inches(0.4),
             line, size=11, color=GRAY_DARK); yy += Inches(0.36)

add_rounded(s, Inches(6.78), Inches(4.2), Inches(6.15), Inches(2.8), WHITE, line=LIGHT_GRY)
add_rect(s, Inches(6.78), Inches(4.2), Inches(6.15), Inches(0.5), DEEP_BLUE)
add_text(s, Inches(6.78), Inches(4.27), Inches(6.15), Inches(0.4),
         "Dedicated Container Security Page", size=15, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
cs = [
    "▸ Repos grouped with image-level accordion expand",
    "▸ Severity-aware columns (CRITICAL → INFO)",
    "▸ Inline status dropdown (Open / In-Progress / Fixed)",
    "▸ Config issues isolated in orange banner — no noise",
]
yy = Inches(4.85)
for line in cs:
    add_text(s, Inches(6.98), yy, Inches(5.7), Inches(0.4),
             line, size=11, color=GRAY_DARK); yy += Inches(0.36)

# ============================================================
# SLIDE 10 — COMPLIANCE
# ============================================================
s = add_blank_slide()
page_header(s, "Compliance — Continuous, Multi-Framework",
            "Real-time score, evidence-backed, auditor-ready")
frameworks = [
    ("PCI-DSS",   "Card-holder data protection",        RED),
    ("SOC 2",     "Trust services criteria",            ACCENT),
    ("ISO 27001", "Information security mgmt",          TEAL),
    ("HIPAA",     "Health information protection",      ORANGE),
    ("CIS",       "Cloud foundations benchmark",        DEEP_BLUE),
    ("GDPR",      "EU data privacy",                    GRAY_DARK),
]
y = Inches(1.2); cw = Inches(2.0); ch = Inches(1.3); gap = Inches(0.12)
for i, (t, b, c) in enumerate(frameworks):
    x = Inches(0.45) + (cw + gap) * i
    add_rounded(s, x, y, cw, ch, WHITE, line=LIGHT_GRY)
    add_rect(s, x, y, cw, Inches(0.45), c)
    add_text(s, x, y + Inches(0.07), cw, Inches(0.35),
             t, size=14, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    add_text(s, x + Inches(0.15), y + Inches(0.55), cw - Inches(0.3), Inches(0.7),
             b, size=10, color=GRAY_DARK, align=PP_ALIGN.CENTER)

# features
features = [
    ("Posture Score Engine",
     "Weighted scoring per framework. Per-account history, trend chart, drill-down to control level."),
    ("Compliance Evidence Collector",
     "Auto-captures evidence object from each finding (with 90-day TTL) — satisfies audit retention."),
    ("Control-to-Finding Mapping",
     "Each scanner finding tagged to one or more controls — 'show me everything failing PCI 10.6'."),
    ("Per-Framework Reports",
     "On-demand and scheduled — PDF/HTML/CSV, branded, exportable to auditors."),
]
y2 = Inches(2.85); cw = Inches(6.15); ch = Inches(1.95); gap = Inches(0.15)
for i, (t, b) in enumerate(features):
    col = i % 2; row = i // 2
    x = Inches(0.45) + (cw + gap) * col
    yy = y2 + (ch + gap) * row
    add_rounded(s, x, yy, cw, ch, WHITE, line=LIGHT_GRY)
    add_rect(s, x, yy, Inches(0.08), ch, ACCENT)
    add_text(s, x + Inches(0.2), yy + Inches(0.12), cw - Inches(0.3), Inches(0.5),
             t, size=14, bold=True, color=NAVY)
    add_text(s, x + Inches(0.2), yy + Inches(0.6), cw - Inches(0.3), ch - Inches(0.7),
             b, size=11, color=GRAY_DARK)

# ============================================================
# SLIDE 11 — REMEDIATION & APPROVALS
# ============================================================
s = add_blank_slide()
page_header(s, "Auto-Remediation with Approval Gating",
            "Detect → Approve → Revert — one workflow, one audit trail")

# steps
steps = [
    ("1. Detect",   "Scanner emits finding\n(e.g. S3 public ACL)",   RED),
    ("2. Classify", "Severity, framework,\nresource fingerprint",     ORANGE),
    ("3. Approve",  "Approval request created\n— reviewer sign-off",  YELLOW),
    ("4. Revert",   "revertService.ts executes\nAWS / Azure / GCP API", TEAL),
    ("5. Evidence", "Action logged → Evidence,\nposture score updates", ACCENT),
]
y = Inches(1.3); cw = Inches(2.45); ch = Inches(1.7); gap = Inches(0.1)
for i, (t, b, c) in enumerate(steps):
    x = Inches(0.45) + (cw + gap) * i
    add_rounded(s, x, y, cw, ch, WHITE, line=LIGHT_GRY)
    add_rect(s, x, y, cw, Inches(0.55), c)
    add_text(s, x, y + Inches(0.1), cw, Inches(0.4),
             t, size=14, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    add_text(s, x + Inches(0.2), y + Inches(0.75), cw - Inches(0.3), ch - Inches(0.85),
             b, size=10, color=GRAY_DARK, align=PP_ALIGN.CENTER)
    # arrow
    if i < 4:
        arr = s.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW,
                                 x + cw, y + Inches(0.6),
                                 Inches(0.1), Inches(0.4))
        arr.fill.solid(); arr.fill.fore_color.rgb = ACCENT
        arr.line.fill.background()

# what gets remediated
add_rounded(s, Inches(0.45), Inches(3.4), Inches(6.15), Inches(3.6), WHITE, line=LIGHT_GRY)
add_rect(s, Inches(0.45), Inches(3.4), Inches(6.15), Inches(0.5), DEEP_BLUE)
add_text(s, Inches(0.45), Inches(3.47), Inches(6.15), Inches(0.4),
         "Supported Auto-Reverts", size=15, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
revs = [
    "AWS  → S3 (block public, encryption), CloudTrail (enable logging),",
    "         KMS (rotation), IAM (detach risky policies, deactivate keys)",
    "Azure → ARM PUT — Storage public access, NSG rules, Key Vault flags,",
    "         App Service TLS, SQL public access toggle",
    "GCP  → setIamPolicy — remove allUsers / allAuthenticatedUsers,",
    "         disable public access on Cloud Run / Storage / Pub/Sub",
]
yy = Inches(4.0)
for line in revs:
    add_text(s, Inches(0.65), yy, Inches(5.85), Inches(0.4),
             line, size=11, color=GRAY_DARK); yy += Inches(0.42)

# guardrails
add_rounded(s, Inches(6.78), Inches(3.4), Inches(6.15), Inches(3.6), NAVY)
add_text(s, Inches(6.98), Inches(3.5), Inches(5.9), Inches(0.4),
         "Guardrails & Safety", size=15, bold=True, color=WHITE)
g = [
    "Every revert is approval-gated — no silent changes",
    "Freeze Windows — block remediation during release weeks",
    "Dry-run preview before execution",
    "Approval log + evidence object for every reverted finding",
    "Roll-back-ready: original state captured before mutation",
    "RBAC: only privileged roles can approve",
]
yy = Inches(4.05)
for line in g:
    add_text(s, Inches(6.98), yy, Inches(5.85), Inches(0.4),
             "•  " + line, size=11, color=WHITE); yy += Inches(0.4)

# ============================================================
# SLIDE 12 — ML ANOMALY DETECTION
# ============================================================
s = add_blank_slide()
page_header(s, "ML Anomaly Detection",
            "Behavioural baselines per actor — catches what rule-based misses")

# left: how it works
add_rounded(s, Inches(0.45), Inches(1.2), Inches(6.15), Inches(5.8), WHITE, line=LIGHT_GRY)
add_rect(s, Inches(0.45), Inches(1.2), Inches(6.15), Inches(0.55), TEAL)
add_text(s, Inches(0.45), Inches(1.27), Inches(6.15), Inches(0.4),
         "Detection Engine (anomalyEngine.ts)", size=15, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
hw = [
    "Online statistics — no batch ML training",
    "▸ EWMA (exponentially weighted moving avg)",
    "▸ Welford's variance for stable Z-score",
    "▸ Per-actor baseline persisted in AnomalyBaseline",
    "▸ 8 detection types out of the box:",
    "    • Volume spike     • Geo deviation",
    "    • Off-hours        • New API surface",
    "    • New region       • New resource type",
    "    • Failure burst    • Privilege drift",
    "▸ Per-cloud worker — gcpAnomalyWorker, AWS, Azure",
]
yy = Inches(1.95)
for line in hw:
    add_text(s, Inches(0.65), yy, Inches(5.85), Inches(0.4),
             line, size=11, color=GRAY_DARK); yy += Inches(0.42)

# right: outcomes + integration
add_rounded(s, Inches(6.78), Inches(1.2), Inches(6.15), Inches(2.8), WHITE, line=LIGHT_GRY)
add_rect(s, Inches(6.78), Inches(1.2), Inches(6.15), Inches(0.5), ACCENT)
add_text(s, Inches(6.78), Inches(1.27), Inches(6.15), Inches(0.4),
         "What It Catches", size=15, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
catches = [
    "Credentialed account suddenly active in new region",
    "Service account making 5× normal API call volume",
    "User performing actions outside normal working hours",
    "Burst of access-denied errors → credential probing",
]
yy = Inches(1.85)
for line in catches:
    add_text(s, Inches(6.98), yy, Inches(5.85), Inches(0.4),
             "▸  " + line, size=11, color=GRAY_DARK); yy += Inches(0.42)

add_rounded(s, Inches(6.78), Inches(4.15), Inches(6.15), Inches(2.85), GRAY_BG, line=LIGHT_GRY)
add_text(s, Inches(6.98), Inches(4.25), Inches(5.85), Inches(0.4),
         "Built-In, Stays Tuned", size=15, bold=True, color=NAVY)
bi = [
    "No external ML platform / managed service needed",
    "Baselines self-heal as user behaviour shifts",
    "Anomaly events feed Findings + Alerts pipelines",
    "Configurable sensitivity per actor / per service",
    "Designed to run inside same workers — no extra infra",
]
yy = Inches(4.7)
for line in bi:
    add_text(s, Inches(6.98), yy, Inches(5.85), Inches(0.4),
             "•  " + line, size=11, color=GRAY_DARK); yy += Inches(0.42)

# ============================================================
# SLIDE 13 — DRIFT, BASELINES & CONFIG SYNC
# ============================================================
s = add_blank_slide()
page_header(s, "Drift Control, Baselines & Config Sync",
            "Know exactly what changed, by whom, and against which baseline")

# 3 columns
cols = [
    ("Configuration Baselines",
     "Capture a known-good state per account/subscription/project.\n\n"
     "▸ Versioned snapshots (BaselineVersion, BaselineSnapshot)\n"
     "▸ Per-resource fingerprint diffing\n"
     "▸ Compare any two versions, side-by-side\n"
     "▸ DriftResult model captures category, severity, delta",
     ACCENT),
    ("Config Change Monitor",
     "Streaming detection of resource changes.\n\n"
     "▸ configSyncMonitorService classifies each delta\n"
     "▸ ConfigChange model retains who/what/when\n"
     "▸ Tags by classification (security-impacting vs. cosmetic)\n"
     "▸ Replayable timeline per resource",
     ORANGE),
    ("Freeze Windows",
     "Block dangerous activity in release-critical windows.\n\n"
     "▸ Per-account / cloud / global freezes\n"
     "▸ Suppresses auto-revert, scheduled scans\n"
     "▸ Audit trail of who declared the freeze\n"
     "▸ Surface live in dashboard banner",
     TEAL),
]
y = Inches(1.2); cw = Inches(4.1); ch = Inches(5.6); gap = Inches(0.1)
for i, (t, b, c) in enumerate(cols):
    x = Inches(0.45) + (cw + gap) * i
    add_rounded(s, x, y, cw, ch, WHITE, line=LIGHT_GRY)
    add_rect(s, x, y, cw, Inches(0.55), c)
    add_text(s, x, y + Inches(0.12), cw, Inches(0.4),
             t, size=14, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    add_text(s, x + Inches(0.2), y + Inches(0.75), cw - Inches(0.3), ch - Inches(0.85),
             b, size=11, color=GRAY_DARK)

# ============================================================
# SLIDE 14 — RESOURCE INVENTORY & GRAPH
# ============================================================
s = add_blank_slide()
page_header(s, "Resource Inventory & Dependency Graph",
            "One source of truth — every asset, every relationship, every cloud")

# stat
stats = [
    ("Every Asset Discovered",    "ResourceInventory model captures cloud, region, type, tags, owner — synced by inventoryPipeline."),
    ("Dependency Mapping",        "ResourceDependency tracks who-talks-to-whom across SG, IAM, VPC, IGW, routes, peering."),
    ("Historical Snapshots",      "ResourceSnapshot stores point-in-time state — replay 'how did this look 2 weeks ago?'"),
    ("Resource Detail View",      "Dedicated UI page per asset — config, findings, lineage, related dependencies."),
    ("Cross-Cloud Search",        "Filter by cloud/account/region/tag/service in one inventory page."),
]
y = Inches(1.2); cw = Inches(6.15); ch = Inches(1.05); gap = Inches(0.12)
for i, (t, b) in enumerate(stats):
    col = i % 2; row = i // 2
    x = Inches(0.45) + (cw + gap) * col
    yy = y + (ch + gap) * row
    if row > 2: break
    add_rounded(s, x, yy, cw, ch, WHITE, line=LIGHT_GRY)
    add_rect(s, x, yy, Inches(0.08), ch, DEEP_BLUE)
    add_text(s, x + Inches(0.2), yy + Inches(0.1), cw - Inches(0.3), Inches(0.4),
             t, size=13, bold=True, color=NAVY)
    add_text(s, x + Inches(0.2), yy + Inches(0.45), cw - Inches(0.3), ch - Inches(0.5),
             b, size=11, color=GRAY_DARK)

# bottom hi
add_rounded(s, Inches(0.45), Inches(4.9), Inches(12.5), Inches(2.1), NAVY)
add_text(s, Inches(0.65), Inches(5.05), Inches(12), Inches(0.4),
         "Why It Matters", size=15, bold=True, color=WHITE)
add_text(s, Inches(0.65), Inches(5.5), Inches(12), Inches(1.5),
         "Most CSPM tools list findings.  We connect findings to the asset graph.\n\n"
         "▸  When EC2 instance is reachable from the internet, the graph shows "
         "which subnet/IGW/route/SG enables it — one click to remediate the actual hole.\n"
         "▸  Lambda CVE? Trace to caller API Gateway, downstream RDS, IAM role permissions.",
         size=12, color=WHITE)

# ============================================================
# SLIDE 15 — UI / UX
# ============================================================
s = add_blank_slide()
page_header(s, "Operator Experience — 31 Purpose-Built UI Pages",
            "React 18 · TanStack Query · Tailwind · lucide icons")
pages = [
    ("Dashboard",            "At-a-glance posture across all clouds"),
    ("Cloud Subscriptions",  "Unified AWS accounts + Azure subs + GCP projects"),
    ("Scan Detail",          "Per-scan timeline, regions, services, error trace"),
    ("Findings",             "Master finding feed — filter, group, status update"),
    ("Reports",              "Per-account / per-cloud, JSON / HTML / CSV / PDF"),
    ("Compliance",           "Live score, control drill-down, framework filter"),
    ("Threat Detection",     "Active threats — actor, IP, raw event JSON"),
    ("Container Security",   "ECR repos + CVEs with severity-aware accordion"),
    ("CloudTrail Logs",      "Native log viewer, filters, anomaly overlay"),
    ("Resource Inventory",   "Cross-cloud asset table + per-resource graph"),
    ("Config Changes",       "Replayable timeline + classification"),
    ("Baseline Drift",       "Version compare side-by-side"),
    ("Posture Score",        "Trend chart, history, per-framework breakdown"),
    ("Risk Register",        "Tracked items with owner / status / target date"),
    ("IAM Escalation",       "Path detection — which user can reach admin?"),
    ("Alert Configuration",  "Slack / Email / webhook routing"),
    ("Freeze Windows",       "Active and scheduled freezes"),
    ("Scheduled Reports",    "Cron-style report runs"),
    ("Integrations",         "Slack, Jira, ServiceNow, SIEM"),
]
y = Inches(1.2); cw = Inches(4.05); ch = Inches(0.45); gap_x = Inches(0.1); gap_y = Inches(0.1)
for i, (t, b) in enumerate(pages):
    col = i % 3; row = i // 3
    x = Inches(0.45) + (cw + gap_x) * col
    yy = y + (ch + gap_y) * row
    add_rounded(s, x, yy, cw, ch, WHITE, line=LIGHT_GRY)
    add_rect(s, x, yy, Inches(0.08), ch, ACCENT)
    add_text(s, x + Inches(0.2), yy + Inches(0.06), Inches(1.4), Inches(0.35),
             t, size=11, bold=True, color=NAVY)
    add_text(s, x + Inches(1.65), yy + Inches(0.07), cw - Inches(1.75), Inches(0.35),
             b, size=9, color=GRAY_DARK)

add_text(s, Inches(0.45), Inches(6.7), Inches(12.5), Inches(0.4),
         "Design system: consistent severity colors · status inline · config in banner · CVEs in accordion · grouping by resource.",
         size=10, color=GRAY_DARK, align=PP_ALIGN.CENTER)

# ============================================================
# SLIDE 16 — REPORTING & ALERTS
# ============================================================
s = add_blank_slide()
page_header(s, "Reporting, Alerting & Integrations",
            "Get the right finding to the right team — at the right time")

# left: reports
add_rounded(s, Inches(0.45), Inches(1.2), Inches(6.15), Inches(5.8), WHITE, line=LIGHT_GRY)
add_rect(s, Inches(0.45), Inches(1.2), Inches(6.15), Inches(0.55), DEEP_BLUE)
add_text(s, Inches(0.45), Inches(1.27), Inches(6.15), Inches(0.4),
         "Reporting Engine", size=15, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
rb = [
    "▸ Reports page — every finding, filterable & exportable",
    "▸ Per-account / per-cloud / per-framework outputs",
    "▸ Formats: PDF (branded), HTML, CSV, JSON",
    "▸ ScheduledReports — cron-style, recurring",
    "▸ ReportSchedule + ReportRun models — full audit trail",
    "▸ Posture score history exported for board reporting",
    "▸ Evidence bundles for audit (90-day TTL)",
    "▸ S3 / file-store delivery (configurable)",
    "▸ Per-recipient routing — exec, sec-ops, compliance",
]
yy = Inches(1.95)
for line in rb:
    add_text(s, Inches(0.65), yy, Inches(5.85), Inches(0.4),
             line, size=11, color=GRAY_DARK); yy += Inches(0.42)

# right top: alerts
add_rounded(s, Inches(6.78), Inches(1.2), Inches(6.15), Inches(2.8), WHITE, line=LIGHT_GRY)
add_rect(s, Inches(6.78), Inches(1.2), Inches(6.15), Inches(0.5), RED)
add_text(s, Inches(6.78), Inches(1.27), Inches(6.15), Inches(0.4),
         "Real-Time Alerting", size=15, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
al = [
    "Slack channel routing per severity / cloud / framework",
    "Email digest or per-event modes",
    "AlertLog model — every alert tracked & deduplicated",
    "Throttle / quiet-hours / freeze-aware",
]
yy = Inches(1.85)
for line in al:
    add_text(s, Inches(6.98), yy, Inches(5.85), Inches(0.4),
             "▸  " + line, size=11, color=GRAY_DARK); yy += Inches(0.42)

# right bottom: integrations
add_rounded(s, Inches(6.78), Inches(4.15), Inches(6.15), Inches(2.85), WHITE, line=LIGHT_GRY)
add_rect(s, Inches(6.78), Inches(4.15), Inches(6.15), Inches(0.5), TEAL)
add_text(s, Inches(6.78), Inches(4.22), Inches(6.15), Inches(0.4),
         "Integrations", size=15, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
ig = [
    "Jira / ServiceNow ticket auto-creation",
    "Splunk / DataDog / SIEM webhook export",
    "Slack / Email / generic webhook",
    "IntegrationConfig + IntegrationLog for audit",
    "Per-finding routing rules",
]
yy = Inches(4.8)
for line in ig:
    add_text(s, Inches(6.98), yy, Inches(5.85), Inches(0.4),
             "▸  " + line, size=11, color=GRAY_DARK); yy += Inches(0.42)

# ============================================================
# SLIDE 17 — COMPETITIVE / DIFFERENTIATORS
# ============================================================
s = add_blank_slide()
page_header(s, "Why This Beats Wiz / Orca / Prisma Cloud",
            "Built for teams who want CSPM-grade coverage without CSPM-grade pricing")

rows = [
    ("Coverage",            "70+ scanners across 3 clouds", "Comparable",         TEAL),
    ("GuardDuty / Threat",  "Built-in, free, account-wide", "Add-on or license",  TEAL),
    ("Container CVE",       "Inspector-free, OSV-based",    "Inspector required", TEAL),
    ("Auto-Remediation",    "AWS / Azure / GCP — approval-gated", "Limited / paid", TEAL),
    ("Anomaly Detection",   "Built-in ML, per-actor",       "Often separate SKU", TEAL),
    ("Pricing",             "Self-hosted, predictable, no per-resource", "Per-asset, scales painfully", TEAL),
    ("Data Locality",       "Stays in your VPC / VNet",     "Vendor SaaS only",   TEAL),
    ("Time to Deploy",      "Hours — docker-compose up",    "Weeks / months",     TEAL),
]
y = Inches(1.25); rh = Inches(0.5); gap = Inches(0.05)
# header row
header_y = y
add_rounded(s, Inches(0.45), header_y, Inches(3.5), rh, NAVY)
add_rounded(s, Inches(4.0), header_y, Inches(4.5), rh, NAVY)
add_rounded(s, Inches(8.55), header_y, Inches(4.4), rh, NAVY)
add_text(s, Inches(0.45), header_y + Inches(0.1), Inches(3.5), Inches(0.35),
         "Capability",   size=12, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
add_text(s, Inches(4.0),  header_y + Inches(0.1), Inches(4.5), Inches(0.35),
         "Our Platform", size=12, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
add_text(s, Inches(8.55), header_y + Inches(0.1), Inches(4.4), Inches(0.35),
         "Wiz / Orca / Prisma", size=12, bold=True, color=WHITE, align=PP_ALIGN.CENTER)

ry = header_y + rh + gap
for i, (cap, ours, theirs, _c) in enumerate(rows):
    bg = WHITE if i % 2 == 0 else GRAY_BG
    add_rounded(s, Inches(0.45), ry, Inches(3.5), rh, bg, line=LIGHT_GRY)
    add_rounded(s, Inches(4.0),  ry, Inches(4.5), rh, bg, line=LIGHT_GRY)
    add_rounded(s, Inches(8.55), ry, Inches(4.4), rh, bg, line=LIGHT_GRY)
    add_text(s, Inches(0.6), ry + Inches(0.12), Inches(3.3), Inches(0.35),
             cap, size=11, bold=True, color=NAVY)
    add_text(s, Inches(4.15), ry + Inches(0.12), Inches(4.3), Inches(0.35),
             "✓  " + ours, size=11, color=TEAL, bold=True)
    add_text(s, Inches(8.7), ry + Inches(0.12), Inches(4.2), Inches(0.35),
             theirs, size=11, color=GRAY_DARK)
    ry += rh + gap

# ============================================================
# SLIDE 18 — DEPLOYMENT
# ============================================================
s = add_blank_slide()
page_header(s, "Deployment & Operations",
            "Up and running in an afternoon")
steps = [
    ("1. Pull repo",  "git clone · npm install · docker-compose up\nPostgres + Redis included.", ACCENT),
    ("2. Configure",  "Add cloud credentials in UI:\nAWS access key, Azure SP, GCP service account.", TEAL),
    ("3. First Scan", "Trigger scan from CloudSubscriptions page.\nFindings populate within minutes.", ORANGE),
    ("4. Wire Alerts","Configure Slack / email / Jira from Integrations page.\nSet schedules from Reports page.", DEEP_BLUE),
]
y = Inches(1.2); cw = Inches(3.05); ch = Inches(2.0); gap = Inches(0.1)
for i, (t, b, c) in enumerate(steps):
    x = Inches(0.45) + (cw + gap) * i
    add_rounded(s, x, y, cw, ch, WHITE, line=LIGHT_GRY)
    add_rect(s, x, y, cw, Inches(0.55), c)
    add_text(s, x, y + Inches(0.1), cw, Inches(0.4),
             t, size=14, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    add_text(s, x + Inches(0.2), y + Inches(0.7), cw - Inches(0.3), ch - Inches(0.8),
             b, size=11, color=GRAY_DARK)

# req / ops
add_rounded(s, Inches(0.45), Inches(3.45), Inches(6.15), Inches(3.55), WHITE, line=LIGHT_GRY)
add_rect(s, Inches(0.45), Inches(3.45), Inches(6.15), Inches(0.5), NAVY)
add_text(s, Inches(0.45), Inches(3.52), Inches(6.15), Inches(0.4),
         "Infrastructure Requirements", size=15, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
req = [
    "▸ One VM — 4 vCPU / 8 GB RAM is comfortable",
    "▸ PostgreSQL 14+ (managed or local)",
    "▸ Redis 6+ for BullMQ queues",
    "▸ Node.js 18+ runtime",
    "▸ Outbound HTTPS to cloud control planes + OSV.dev",
    "▸ Docker Compose recipe included",
]
yy = Inches(4.05)
for line in req:
    add_text(s, Inches(0.65), yy, Inches(5.85), Inches(0.4),
             line, size=11, color=GRAY_DARK); yy += Inches(0.42)

add_rounded(s, Inches(6.78), Inches(3.45), Inches(6.15), Inches(3.55), GRAY_BG, line=LIGHT_GRY)
add_text(s, Inches(6.98), Inches(3.55), Inches(5.85), Inches(0.4),
         "Operational Properties", size=15, bold=True, color=NAVY)
ops = [
    "▸ Read-only by default — write only when remediating",
    "▸ Idempotent — safe to re-run scans",
    "▸ Async / queued — no blocking calls",
    "▸ Dedup logic prevents duplicate findings across runs",
    "▸ Smart-skip on container scans (unchanged images)",
    "▸ Resilient to per-region API failures",
]
yy = Inches(4.05)
for line in ops:
    add_text(s, Inches(6.98), yy, Inches(5.85), Inches(0.4),
             line, size=11, color=GRAY_DARK); yy += Inches(0.42)

# ============================================================
# SLIDE 19 — ROADMAP
# ============================================================
s = add_blank_slide()
page_header(s, "Roadmap", "What's next on the build queue")

now = [
    ("Now — Shipped",
     "AWS 25+, Azure 32, GCP 13 scanners · Threat Detection · ECR/Lambda CVE · "
     "Compliance · Baselines · Drift · Approvals · Auto-revert · Anomaly engine · "
     "31 UI pages · Slack/Jira/SIEM integrations",
     TEAL),
    ("Next — In Build",
     "GCP compliance service (CIS GCP) · GCP threat monitor · Azure compliance expansion "
     "for newer scanners (Containers, AI, IoT) · Macie-equivalent S3 data classification",
     ORANGE),
    ("Future",
     "EKS scanner · K8s admission webhooks · Just-in-time access · Multi-tenant SaaS mode · "
     "Cost-anomaly detection · AI-generated remediation PRs",
     ACCENT),
]
y = Inches(1.3); cw = Inches(4.1); ch = Inches(5.6); gap = Inches(0.1)
for i, (t, b, c) in enumerate(now):
    x = Inches(0.45) + (cw + gap) * i
    add_rounded(s, x, y, cw, ch, WHITE, line=LIGHT_GRY)
    add_rect(s, x, y, cw, Inches(0.6), c)
    add_text(s, x, y + Inches(0.12), cw, Inches(0.4),
             t, size=14, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    add_text(s, x + Inches(0.25), y + Inches(0.85), cw - Inches(0.4), ch - Inches(0.95),
             b, size=12, color=GRAY_DARK)

# ============================================================
# SLIDE 20 — CLOSING
# ============================================================
s = add_blank_slide()
add_rect(s, 0, 0, SW, SH, NAVY)
# accent triangles
acc = s.shapes.add_shape(MSO_SHAPE.RIGHT_TRIANGLE, Inches(8.3), Inches(0), Inches(5.0), SH)
acc.fill.solid(); acc.fill.fore_color.rgb = DEEP_BLUE; acc.line.fill.background()
add_rect(s, 0, Inches(2.4), Inches(0.5), Inches(0.08), ACCENT)
add_text(s, Inches(0.7), Inches(1.7), Inches(11), Inches(0.5),
         "READY TO DEPLOY", size=14, bold=True, color=ACCENT)
add_text(s, Inches(0.7), Inches(2.1), Inches(11), Inches(2.2),
         "Replace 5 vendors\nwith one platform.",
         size=44, bold=True, color=WHITE)
add_text(s, Inches(0.7), Inches(4.45), Inches(11), Inches(1.2),
         "Multi-cloud scanning · threat detection · compliance · remediation\n"
         "70+ scanners · 6 frameworks · 31 UI pages · zero per-asset cost.",
         size=15, color=RGBColor(0xCB, 0xD7, 0xE3))
add_rounded(s, Inches(0.7), Inches(5.7), Inches(3.0), Inches(0.55), ACCENT)
add_text(s, Inches(0.7), Inches(5.8), Inches(3.0), Inches(0.4),
         "REQUEST DEMO", size=12, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
add_rounded(s, Inches(3.85), Inches(5.7), Inches(3.0), Inches(0.55), WHITE)
add_text(s, Inches(3.85), Inches(5.8), Inches(3.0), Inches(0.4),
         "VIEW DOCUMENTATION", size=12, bold=True, color=NAVY, align=PP_ALIGN.CENTER)
add_text(s, Inches(0.7), SH - Inches(0.5), Inches(11), Inches(0.3),
         "Thank you.", size=14, color=ACCENT)

# ---------- save ----------
out = "/mnt/d/Data/Linux-Data/IML/vul-scanner/aws-scanner/docs/CSPM_Platform_Showcase.pptx"
prs.save(out)
print("Saved:", out)
print("Slides:", len(prs.slides.__iter__.__self__._sldIdLst))
