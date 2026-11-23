"""
Generate the official 7-slide TINYVERSE Hackathon PowerPoint presentation for TRACE-Verified.
Widescreen 16:9, dark cybersecurity aesthetic, fully editable native shapes, text, and architecture diagrams.
"""

import sys
from pathlib import Path
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

# Slide Dimensions (16:9 Widescreen)
SLIDE_WIDTH = Inches(13.333)
SLIDE_HEIGHT = Inches(7.5)

# Visual Theme Color Palette (Dark SOC / Apple Restraint)
C_BG = RGBColor(7, 10, 18)             # #070A12 Deep Canvas
C_SURFACE = RGBColor(15, 23, 42)        # #0F172A Elevated Card
C_SURFACE_SUBTLE = RGBColor(20, 30, 54) # #141E36 Subtle Card
C_SURFACE_DARK = RGBColor(10, 15, 28)   # #0A0F1C Inset Box
C_SURFACE_HIGHLIGHT = RGBColor(24, 38, 68) # #182644 Hover/Active Card
C_BORDER = RGBColor(30, 41, 59)         # #1E293B Card Border
C_BORDER_LIGHT = RGBColor(51, 65, 85)   # #334155 Hairline Border
C_CYAN = RGBColor(56, 189, 248)         # #38BDF8 Primary Accent
C_BLUE = RGBColor(14, 165, 233)         # #0EA5E9 Deep Accent Blue
C_WHITE = RGBColor(255, 255, 255)       # #FFFFFF High-Contrast Primary Text
C_TEXT_SEC = RGBColor(203, 213, 225)    # #CBD5E1 Secondary Text
C_MUTED = RGBColor(148, 163, 184)       # #94A3B8 Captions & Subtle Labels

# Semantic Severity & Status Accents
C_GREEN = RGBColor(16, 185, 129)        # #10B981 Low / Success / Verified
C_GREEN_BG = RGBColor(6, 44, 33)        # Dark Green Card
C_AMBER = RGBColor(245, 158, 11)        # #F59E0B Medium / Warning / Advisory
C_AMBER_BG = RGBColor(46, 32, 8)        # Dark Amber Card
C_RED = RGBColor(239, 68, 68)           # #EF4444 Critical / Alert / Rejection
C_RED_BG = RGBColor(45, 16, 16)         # Dark Red Card
C_PURPLE = RGBColor(168, 85, 247)       # #A855F7 Privilege / Special
C_INDIGO_BG = RGBColor(30, 27, 75)      # Deep Indigo for AI Sandbox

FONT_TITLE = "Segoe UI"
FONT_BODY = "Segoe UI"
FONT_MONO = "Consolas"

def create_presentation():
    prs = Presentation()
    prs.slide_width = SLIDE_WIDTH
    prs.slide_height = SLIDE_HEIGHT
    blank_layout = prs.slide_layouts[6] # Blank slide layout

    def set_slide_background(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), SLIDE_WIDTH, SLIDE_HEIGHT)
        bg.fill.solid()
        bg.fill.fore_color.rgb = C_BG
        bg.line.fill.background()
        return bg

    def add_header(slide, slide_num_str, category_str, title_str, subtitle_str):
        # Header banner text frame
        header_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.42), Inches(11.733), Inches(1.15))
        tf = header_box.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

        # Category Eyebrow
        p_cat = tf.paragraphs[0]
        p_cat.text = f"TINYVERSE HACKATHON 2026  •  {category_str.upper()}"
        p_cat.font.name = FONT_TITLE
        p_cat.font.size = Pt(9.5)
        p_cat.font.bold = True
        p_cat.font.color.rgb = C_CYAN
        p_cat.space_after = Pt(2)

        # Slide Main Title
        p_title = tf.add_paragraph()
        p_title.text = title_str
        p_title.font.name = FONT_TITLE
        p_title.font.size = Pt(21)
        p_title.font.bold = True
        p_title.font.color.rgb = C_WHITE
        p_title.space_after = Pt(2)

        # Slide Subtitle
        p_sub = tf.add_paragraph()
        p_sub.text = subtitle_str
        p_sub.font.name = FONT_BODY
        p_sub.font.size = Pt(11)
        p_sub.font.color.rgb = C_TEXT_SEC

        # Top Right Slide Numbering
        num_box = slide.shapes.add_textbox(Inches(11.2), Inches(0.42), Inches(1.333), Inches(0.4))
        ntf = num_box.text_frame
        ntf.margin_left = ntf.margin_top = ntf.margin_right = ntf.margin_bottom = 0
        np = ntf.paragraphs[0]
        np.text = slide_num_str
        np.font.name = FONT_MONO
        np.font.size = Pt(11)
        np.font.bold = True
        np.font.color.rgb = C_CYAN
        np.alignment = PP_ALIGN.RIGHT

    def add_card(slide, left, top, width, height, bg_color=C_SURFACE, border_color=C_BORDER):
        shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        shape.fill.solid()
        shape.fill.fore_color.rgb = bg_color
        shape.line.color.rgb = border_color
        shape.line.width = Pt(1)
        return shape

    # =========================================================================
    # SLIDE 0: TITLE SLIDE — Project Identity
    # =========================================================================
    s0 = prs.slides.add_slide(blank_layout)
    set_slide_background(s0)

    # Ambient Card Frame
    add_card(s0, Inches(0.8), Inches(0.65), Inches(11.733), Inches(6.2), bg_color=C_SURFACE, border_color=C_BORDER_LIGHT)

    # Title Text Frame
    t_box = s0.shapes.add_textbox(Inches(1.25), Inches(1.0), Inches(10.833), Inches(2.3))
    ttf = t_box.text_frame
    ttf.word_wrap = True
    ttf.margin_left = ttf.margin_top = ttf.margin_right = ttf.margin_bottom = 0

    p_hack = ttf.paragraphs[0]
    p_hack.text = "TINYVERSE 2026 — DRILLATHON + HACKATHON  |  PROBLEM STATEMENT 02"
    p_hack.font.name = FONT_TITLE
    p_hack.font.size = Pt(10.5)
    p_hack.font.bold = True
    p_hack.font.color.rgb = C_CYAN
    p_hack.space_after = Pt(6)

    p_brand = ttf.add_paragraph()
    p_brand.text = "TRACE-Verified"
    p_brand.font.name = FONT_TITLE
    p_brand.font.size = Pt(46)
    p_brand.font.bold = True
    p_brand.font.color.rgb = C_WHITE
    p_brand.space_after = Pt(2)

    p_tag = ttf.add_paragraph()
    p_tag.text = "Offline Security Incident Triage Assistant"
    p_tag.font.name = FONT_TITLE
    p_tag.font.size = Pt(20)
    p_tag.font.bold = True
    p_tag.font.color.rgb = C_CYAN
    p_tag.space_after = Pt(8)

    p_desc = ttf.add_paragraph()
    p_desc.text = "Turning fragmented Windows authentication, security, and process logs into correlated, evidence-backed incidents — with verified local SLM explanations and zero cloud data egress."
    p_desc.font.name = FONT_BODY
    p_desc.font.size = Pt(12)
    p_desc.font.color.rgb = C_TEXT_SEC

    # 3 Info Cards at bottom of Title Slide
    col_w = Inches(3.4)
    gap = Inches(0.316)
    y_cards = Inches(3.55)
    card_h = Inches(2.25)

    # Card 1: Presenter Info (Editable Placeholders)
    add_card(s0, Inches(1.25), y_cards, col_w, card_h, bg_color=C_SURFACE_SUBTLE, border_color=C_BORDER_LIGHT)
    tb1 = s0.shapes.add_textbox(Inches(1.45), y_cards + Inches(0.18), col_w - Inches(0.4), card_h - Inches(0.36))
    tf1 = tb1.text_frame
    tf1.word_wrap = True
    tf1.margin_left = tf1.margin_top = tf1.margin_right = tf1.margin_bottom = 0

    p = tf1.paragraphs[0]
    p.text = "SUBMISSION METADATA"
    p.font.name = FONT_TITLE
    p.font.size = Pt(9.5)
    p.font.bold = True
    p.font.color.rgb = C_CYAN
    p.space_after = Pt(8)

    p = tf1.add_paragraph()
    p.text = "PRESENTER:  [FULL NAME]"
    p.font.name = FONT_TITLE
    p.font.size = Pt(11.5)
    p.font.bold = True
    p.font.color.rgb = C_WHITE
    p.space_after = Pt(3)

    p = tf1.add_paragraph()
    p.text = "USN:  [USN]"
    p.font.name = FONT_MONO
    p.font.size = Pt(10.5)
    p.font.bold = True
    p.font.color.rgb = C_TEXT_SEC
    p.space_after = Pt(3)

    p = tf1.add_paragraph()
    p.text = "BRANCH:  [BRANCH]"
    p.font.name = FONT_TITLE
    p.font.size = Pt(10.5)
    p.font.bold = True
    p.font.color.rgb = C_TEXT_SEC
    p.space_after = Pt(3)

    p = tf1.add_paragraph()
    p.text = "TRACK:  PS02 — Incident Triage Assistant"
    p.font.name = FONT_BODY
    p.font.size = Pt(9.5)
    p.font.color.rgb = C_MUTED
    p.space_after = Pt(2)

    p = tf1.add_paragraph()
    p.text = "TYPE:  Solo / Individual Participant"
    p.font.name = FONT_BODY
    p.font.size = Pt(9.5)
    p.font.color.rgb = C_MUTED

    # Card 2: Core Engineering Capabilities
    add_card(s0, Inches(1.25) + col_w + gap, y_cards, col_w, card_h, bg_color=C_SURFACE_SUBTLE, border_color=C_BORDER_LIGHT)
    tb2 = s0.shapes.add_textbox(Inches(1.45) + col_w + gap, y_cards + Inches(0.18), col_w - Inches(0.4), card_h - Inches(0.36))
    tf2 = tb2.text_frame
    tf2.word_wrap = True
    tf2.margin_left = tf2.margin_top = tf2.margin_right = tf2.margin_bottom = 0

    p = tf2.paragraphs[0]
    p.text = "KEY CAPABILITIES"
    p.font.name = FONT_TITLE
    p.font.size = Pt(9.5)
    p.font.bold = True
    p.font.color.rgb = C_CYAN
    p.space_after = Pt(8)

    bullets2 = [
        "Deterministic Detectors (Auth, Priv, Process)",
        "Identity + Host Multi-Stage Incident Correlation",
        "Additive Heuristic Scoring & Severity Mapping",
        "Canonical Evidence Provenance (SHA-256 Hashes)",
        "Verified Advisory SLM Explanations (phi4-mini)"
    ]
    for b in bullets2:
        p = tf2.add_paragraph()
        p.text = f"•  {b}"
        p.font.name = FONT_BODY
        p.font.size = Pt(9.8)
        p.font.color.rgb = C_TEXT_SEC
        p.space_after = Pt(2.5)

    # Card 3: Execution Guarantees
    add_card(s0, Inches(1.25) + (col_w + gap) * 2, y_cards, col_w, card_h, bg_color=C_SURFACE_SUBTLE, border_color=C_BORDER_LIGHT)
    tb3 = s0.shapes.add_textbox(Inches(1.45) + (col_w + gap) * 2, y_cards + Inches(0.18), col_w - Inches(0.4), card_h - Inches(0.36))
    tf3 = tb3.text_frame
    tf3.word_wrap = True
    tf3.margin_left = tf3.margin_top = tf3.margin_right = tf3.margin_bottom = 0

    p = tf3.paragraphs[0]
    p.text = "OFFLINE TRUST GUARANTEES"
    p.font.name = FONT_TITLE
    p.font.size = Pt(9.5)
    p.font.bold = True
    p.font.color.rgb = C_GREEN
    p.space_after = Pt(8)

    bullets3 = [
        "100% Offline Loopback Server (127.0.0.1:8000)",
        "Zero Cloud Ingestion & Zero External APIs",
        "Deterministic Engine Is Strictly Authoritative",
        "Model Cannot Mutate Findings, Scores or Severity",
        "150 Automated Pytest Suite Tests Passed"
    ]
    for b in bullets3:
        p = tf3.add_paragraph()
        p.text = f"✔  {b}"
        p.font.name = FONT_BODY
        p.font.size = Pt(9.8)
        p.font.color.rgb = C_TEXT_SEC
        p.space_after = Pt(2.5)

    # Bottom Pill Badges Strip
    p_bar = add_card(s0, Inches(1.25), Inches(6.0), Inches(10.833), Inches(0.55), bg_color=C_SURFACE_DARK, border_color=C_BORDER)
    pbtb = s0.shapes.add_textbox(Inches(1.4), Inches(6.05), Inches(10.5), Inches(0.4))
    pbtf = pbtb.text_frame
    pbtf.word_wrap = True
    pbtf.margin_left = pbtf.margin_top = pbtf.margin_right = pbtf.margin_bottom = 0
    pb_p = pbtf.paragraphs[0]
    pb_p.text = "CORE PILLARS:   [OFFLINE-FIRST]   •   [DETERMINISTIC RULES]   •   [EVIDENCE TRACEABILITY]   •   [BOUNDED SLM VERIFIER]   •   [150 AUTOMATED TESTS]"
    pb_p.font.name = FONT_MONO
    pb_p.font.size = Pt(9)
    pb_p.font.bold = True
    pb_p.font.color.rgb = C_CYAN
    pb_p.alignment = PP_ALIGN.CENTER

    print("[✔] Generated Slide 0: Title Slide")

    # =========================================================================
    # SLIDE 1: Problem Statement & Existing Solutions
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)
    add_header(s1, "01 / 06", "Problem Statement & Existing Solutions",
               "Security Logs Are Disconnected, Noisy, and Sensitive",
               "Analysts face overwhelming log volume while compliance prohibits sending sensitive internal telemetry to the cloud.")

    col1_w = Inches(5.6)
    col2_w = Inches(5.75)
    gap_cols = Inches(0.38)
    top_body = Inches(1.8)
    h_body = Inches(4.5)

    # Left Column: Problem Breakdown
    add_card(s1, Inches(0.8), top_body, col1_w, h_body, bg_color=C_SURFACE, border_color=C_BORDER_LIGHT)
    tb_prob = s1.shapes.add_textbox(Inches(1.05), top_body + Inches(0.2), col1_w - Inches(0.5), h_body - Inches(0.4))
    tf_prob = tb_prob.text_frame
    tf_prob.word_wrap = True
    tf_prob.margin_left = tf_prob.margin_top = tf_prob.margin_right = tf_prob.margin_bottom = 0

    p = tf_prob.paragraphs[0]
    p.text = "THE PROBLEM & WHO IT AFFECTS"
    p.font.name = FONT_TITLE
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = C_CYAN
    p.space_after = Pt(10)

    sections_p1 = [
        ("The Triage Bottleneck", "High-volume security logs (auth failures 4625, successful logins 4624, privilege escalation 4728, script execution 4688) are dispersed across disparate files. Sifting through noise to identify multi-stage attack patterns is slow and manual."),
        ("Who Is Affected", "• Tier-1/Tier-2 SOC analysts suffering from alert fatigue.\n• Small/mid-sized security teams without dedicated automation engineering.\n• Privacy-sensitive organizations (defense, healthcare, finance) where internal logs cannot leave local environments."),
        ("Why It Matters", "Manual triage delays incident identification. Disconnected single-event alerts make it challenging to detect coordinated credential attacks, privilege changes, or suspicious execution before impact occurs.")
    ]

    for title, desc in sections_p1:
        p = tf_prob.add_paragraph()
        p.text = title
        p.font.name = FONT_TITLE
        p.font.size = Pt(10.5)
        p.font.bold = True
        p.font.color.rgb = C_WHITE
        p.space_after = Pt(2)

        p = tf_prob.add_paragraph()
        p.text = desc
        p.font.name = FONT_BODY
        p.font.size = Pt(9.5)
        p.font.color.rgb = C_TEXT_SEC
        p.space_after = Pt(10)

    # Right Column: Existing Solutions & Their Specific Limitations
    add_card(s1, Inches(0.8) + col1_w + gap_cols, top_body, col2_w, h_body, bg_color=C_SURFACE, border_color=C_BORDER_LIGHT)
    tb_sol = s1.shapes.add_textbox(Inches(1.05) + col1_w + gap_cols, top_body + Inches(0.2), col2_w - Inches(0.5), h_body - Inches(0.4))
    tf_sol = tb_sol.text_frame
    tf_sol.word_wrap = True
    tf_sol.margin_left = tf_sol.margin_top = tf_sol.margin_right = tf_sol.margin_bottom = 0

    p = tf_sol.paragraphs[0]
    p.text = "EXISTING APPROACHES & CRITICAL GAPS"
    p.font.name = FONT_TITLE
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = C_CYAN
    p.space_after = Pt(10)

    existing_approaches = [
        ("Enterprise SIEM / EDR Platforms (Splunk, Microsoft Sentinel)",
         "Provide comprehensive log aggregation and alerting, but require complex configuration, dedicated administration, and substantial storage and licensing investment. Alerts often remain siloed, requiring manual analyst synthesis."),
        ("Commercial Cloud AI Copilots & Remote LLM APIs",
         "Introduce data privacy and policy concerns: internal usernames, machine names, and network IPs are transmitted to third-party cloud servers. Unbounded language models also risk hallucinating forensic details without audit trails."),
        ("Ad-Hoc Static Scripts & Manual Spreadsheet Review",
         "Grep commands, Excel spreadsheets, and basic regex filters are fragile, unstandardized, and lack structured, evidence-backed heuristic incident scoring or timeline correlation.")
    ]

    for title, desc in existing_approaches:
        p = tf_sol.add_paragraph()
        p.text = title
        p.font.name = FONT_TITLE
        p.font.size = Pt(10.5)
        p.font.bold = True
        p.font.color.rgb = C_AMBER
        p.space_after = Pt(2)

        p = tf_sol.add_paragraph()
        p.text = desc
        p.font.name = FONT_BODY
        p.font.size = Pt(9.5)
        p.font.color.rgb = C_TEXT_SEC
        p.space_after = Pt(10)

    # Bottom Gap Banner
    add_card(s1, Inches(0.8), Inches(6.45), Inches(11.733), Inches(0.65), bg_color=C_SURFACE_DARK, border_color=C_CYAN)
    tb_gap = s1.shapes.add_textbox(Inches(1.0), Inches(6.52), Inches(11.333), Inches(0.5))
    tf_gap = tb_gap.text_frame
    tf_gap.word_wrap = True
    tf_gap.margin_left = tf_gap.margin_top = tf_gap.margin_right = tf_gap.margin_bottom = 0
    p = tf_gap.paragraphs[0]
    p.text = "THE SPECIFIC GAP WE ADDRESS: An offline-first, zero-cloud triage assistant that couples deterministic, evidence-backed rule correlation with a local, bounded SLM for advisory explanations — guaranteeing zero data egress."
    p.font.name = FONT_TITLE
    p.font.size = Pt(10)
    p.font.bold = True
    p.font.color.rgb = C_WHITE

    print("[✔] Generated Slide 1: Problem Statement & Existing Solutions")

    # =========================================================================
    # SLIDE 2: Proposed Solution & Workflow
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "02 / 06", "Proposed Solution",
               "TRACE-Verified: Deterministic Core + Verified Local SLM",
               "An offline triage assistant coupling deterministic, evidence-backed rule correlation with verified local SLM explanations.")

    # 7-Step Workflow Process Bar (Horizontal layout across top)
    flow_top = Inches(1.8)
    flow_h = Inches(1.0)
    step_w = Inches(1.58)
    step_gap = Inches(0.11)

    steps_data = [
        ("01. INGEST", "CSV, JSON, JSONL", C_SURFACE_SUBTLE, C_BORDER_LIGHT),
        ("02. NORMALIZE", "Canonical Events", C_SURFACE_SUBTLE, C_BORDER_LIGHT),
        ("03. DETECT", "4 Rule Detectors", C_SURFACE_SUBTLE, C_BORDER_LIGHT),
        ("04. CORRELATE", "Identity & Time Graph", C_SURFACE_SUBTLE, C_BORDER_LIGHT),
        ("05. PRIORITIZE", "Heuristic Score 0-100", C_SURFACE_SUBTLE, C_BORDER_LIGHT),
        ("06. EVIDENCE", "Dossier & Provenance", C_SURFACE_SUBTLE, C_BORDER_LIGHT),
        ("07. EXPLAIN", "Verified Local SLM", C_INDIGO_BG, C_CYAN),
    ]

    for idx, (step_title, step_sub, bg_c, border_c) in enumerate(steps_data):
        x = Inches(0.8) + idx * (step_w + step_gap)
        add_card(s2, x, flow_top, step_w, flow_h, bg_color=bg_c, border_color=border_c)
        tb_step = s2.shapes.add_textbox(x + Inches(0.08), flow_top + Inches(0.12), step_w - Inches(0.16), flow_h - Inches(0.24))
        tf_step = tb_step.text_frame
        tf_step.word_wrap = True
        tf_step.margin_left = tf_step.margin_top = tf_step.margin_right = tf_step.margin_bottom = 0

        p = tf_step.paragraphs[0]
        p.text = step_title
        p.font.name = FONT_TITLE
        p.font.size = Pt(9.5)
        p.font.bold = True
        p.font.color.rgb = C_CYAN if idx < 6 else C_WHITE
        p.alignment = PP_ALIGN.CENTER

        p = tf_step.add_paragraph()
        p.text = step_sub
        p.font.name = FONT_BODY
        p.font.size = Pt(8.5)
        p.font.color.rgb = C_TEXT_SEC
        p.alignment = PP_ALIGN.CENTER

    # 3 Distinct Core Pillar Cards
    pillars_top = Inches(3.0)
    pillar_w = Inches(3.75)
    pillar_gap = Inches(0.24)
    pillar_h = Inches(3.4)

    pillars = [
        ("DETERMINISTIC ANALYSIS CORE", C_BLUE, [
            ("Multi-File Ingestion", "Parses CSV, JSON, and JSONL/NDJSON simultaneously. Maps aliases, tallies malformed rows, and preserves original raw records."),
            ("Four Built-in Detectors", "Detects repeated auth failures, success-after-failures, privilege/group modifications, and suspicious script hosts (mshta, powershell)."),
            ("Identity Correlation", "Connects findings across normalized User+Host or User+Source-IP keys over time windows. IP-only matches never create false incidents.")
        ]),
        ("EVIDENCE TRACEABILITY & SCORING", C_CYAN, [
            ("Additive Heuristic Score", "0–100 auditable score based on rule severity, confirmed auth success, distinct attack stages, and host spread (not risk probability)."),
            ("SHA-256 Provenance", "Every event receives a cryptographic hash (`evt_...`). Analysts can verify exact source row provenance in the forensic modal."),
            ("Chronological Timelines", "Visual attack chain timeline accurately reflects temporal order while preserving timestamp uncertainty warnings.")
        ]),
        ("VERIFIED LOCAL SLM ADVISORY", C_PURPLE, [
            ("Zero Cloud Egress", "Inference runs via Ollama `phi4-mini:latest` bound strictly to localhost loopback (127.0.0.1:11434)."),
            ("Advisory Authority Boundary", "The model provides advisory interpretation. It cannot alter or inflate deterministic findings, scores, severity, or evidence."),
            ("Strict Output Verification", "Automated verifier enforces valid JSON and evidence citations. Invalid or hallucinated output triggers deterministic fallback.")
        ])
    ]

    for idx, (p_title, p_color, items) in enumerate(pillars):
        x = Inches(0.8) + idx * (pillar_w + pillar_gap)
        add_card(s2, x, pillars_top, pillar_w, pillar_h, bg_color=C_SURFACE, border_color=C_BORDER_LIGHT)
        tb_p = s2.shapes.add_textbox(x + Inches(0.2), pillars_top + Inches(0.18), pillar_w - Inches(0.4), pillar_h - Inches(0.36))
        tf_p = tb_p.text_frame
        tf_p.word_wrap = True
        tf_p.margin_left = tf_p.margin_top = tf_p.margin_right = tf_p.margin_bottom = 0

        p = tf_p.paragraphs[0]
        p.text = p_title
        p.font.name = FONT_TITLE
        p.font.size = Pt(10.5)
        p.font.bold = True
        p.font.color.rgb = p_color
        p.space_after = Pt(8)

        for heading, body in items:
            p = tf_p.add_paragraph()
            p.text = heading
            p.font.name = FONT_TITLE
            p.font.size = Pt(9.8)
            p.font.bold = True
            p.font.color.rgb = C_WHITE
            p.space_after = Pt(1.5)

            p = tf_p.add_paragraph()
            p.text = body
            p.font.name = FONT_BODY
            p.font.size = Pt(8.8)
            p.font.color.rgb = C_TEXT_SEC
            p.space_after = Pt(7)

    # Bottom Callout Differentiation Strip
    add_card(s2, Inches(0.8), Inches(6.52), Inches(11.733), Inches(0.58), bg_color=C_SURFACE_DARK, border_color=C_BORDER)
    tb_diff = s2.shapes.add_textbox(Inches(1.0), Inches(6.58), Inches(11.333), Inches(0.45))
    tf_diff = tb_diff.text_frame
    tf_diff.word_wrap = True
    tf_diff.margin_left = tf_diff.margin_top = tf_diff.margin_right = tf_diff.margin_bottom = 0
    p = tf_diff.paragraphs[0]
    p.text = "WHAT MAKES IT DIFFERENT: Deterministic Python rules own all security decisions, scores, and evidence. The local SLM is an advisory synthesis layer that cannot alter findings and is strictly constrained by an automated verifier."
    p.font.name = FONT_BODY
    p.font.size = Pt(9.2)
    p.font.bold = True
    p.font.color.rgb = C_CYAN

    print("[✔] Generated Slide 2: Proposed Solution & Workflow")

    # =========================================================================
    # SLIDE 3: Technology Stack
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "03 / 06", "Technology Stack",
               "Deliberately Lightweight, Dependency-Free & 100% Offline",
               "Built with the Python standard library core, vanilla web standards, and a verified local Small Language Model.")

    # 4 Technology Columns
    stack_top = Inches(1.8)
    col_w4 = Inches(2.78)
    gap4 = Inches(0.2)
    col_h4 = Inches(3.6)

    stack_cols = [
        ("CORE & ENGINE", C_CYAN, [
            ("Python 3.12+", "High-performance, clean, auditable runtime."),
            ("Standard Library Only", "Core engine uses only standard library: `dataclasses`, `hashlib`, `csv`, `json`, `datetime`, `ipaddress`, `queue`."),
            ("Minimal Runtime Dependencies", "Minimizes third-party runtime dependencies; core runtime uses Python standard-library components."),
            ("SHA-256 Provenance", "Cryptographic hashing supports integrity checking and source traceability.")
        ]),
        ("BACKEND & PIPELINE", C_BLUE, [
            ("Standard-Lib HTTP Server", "`http.server.ThreadingHTTPServer` with `email.parser` multipart streaming upload handling."),
            ("Strict Loopback Binding", "Binds strictly to `127.0.0.1:8000` to prevent network exposure."),
            ("Sequential AI Worker", "Dedicated daemon worker thread isolates slow SLM inference from HTTP requests."),
            ("Temporary File Safety", "Bounded 50MB upload limits with immediate post-analysis disk cleanup.")
        ]),
        ("FRONTEND & UI", C_GREEN, [
            ("Vanilla HTML5 / CSS3 / ES6", "Zero npm, zero React, zero build step; served directly by local HTTP server."),
            ("Apple Design System", "Translucent materials (`backdrop-filter`), optical typography tracking, segmented controls, spring physics."),
            ("Fast Client-Side State", "Sub-millisecond navigation, interactive attack timeline, and forensic modal inspector."),
            ("Offline Enforcement", "No external CDNs, Google Fonts, or cloud telemetry. Fully self-contained.")
        ]),
        ("LOCAL SLM & QA", C_PURPLE, [
            ("Ollama Runtime", "Self-contained local inference engine bound to `127.0.0.1:11434`."),
            ("phi4-mini:latest", "3.8B parameter Small Language Model optimized for reasoning and structured JSON output."),
            ("Automated Verifier", "Validates dossier citations, entity counts, and chronology before displaying model text."),
            ("pytest 9.2.0 Test Suite", "150 automated tests covering ingestion, detection, explainer, CLI, and server.")
        ])
    ]

    for idx, (col_title, col_color, items) in enumerate(stack_cols):
        x = Inches(0.8) + idx * (col_w4 + gap4)
        add_card(s3, x, stack_top, col_w4, col_h4, bg_color=C_SURFACE, border_color=C_BORDER_LIGHT)
        tb_col = s3.shapes.add_textbox(x + Inches(0.18), stack_top + Inches(0.16), col_w4 - Inches(0.36), col_h4 - Inches(0.32))
        tf_col = tb_col.text_frame
        tf_col.word_wrap = True
        tf_col.margin_left = tf_col.margin_top = tf_col.margin_right = tf_col.margin_bottom = 0

        p = tf_col.paragraphs[0]
        p.text = col_title
        p.font.name = FONT_TITLE
        p.font.size = Pt(10)
        p.font.bold = True
        p.font.color.rgb = col_color
        p.space_after = Pt(8)

        for h, b in items:
            p = tf_col.add_paragraph()
            p.text = h
            p.font.name = FONT_TITLE
            p.font.size = Pt(9.5)
            p.font.bold = True
            p.font.color.rgb = C_WHITE
            p.space_after = Pt(1.5)

            p = tf_col.add_paragraph()
            p.text = b
            p.font.name = FONT_BODY
            p.font.size = Pt(8.5)
            p.font.color.rgb = C_TEXT_SEC
            p.space_after = Pt(6)

    # Bottom Rationale Cards (3 Horizontal Blocks)
    rat_top = Inches(5.55)
    rat_w = Inches(3.75)
    rat_gap = Inches(0.24)
    rat_h = Inches(1.55)

    rationales = [
        ("WHY STANDARD LIBRARY ONLY?", C_CYAN,
         "Security tools must not introduce supply-chain risks. By relying on Python's standard-library components for the core engine, TRACE-Verified minimizes third-party runtime dependencies and runs reliably in restricted, offline environments."),
        ("WHY A SMALL LOCAL MODEL (phi4-mini)?", C_PURPLE,
         "Large cloud models require transmitting confidential audit logs over the internet. phi4-mini runs on standard analyst laptops (CPU-compatible), keeps data local, and provides structured reasoning when constrained to an incident evidence dossier."),
        ("WHY A VERIFICATION GUARDRAIL?", C_AMBER,
         "Generative AI cannot be trusted unconditionally in incident triage. Our verification pipeline inspects generated JSON, checks cited event IDs against ground-truth evidence, and falls back to deterministic text if ungrounded.")
    ]

    for idx, (rtitle, rcolor, rbody) in enumerate(rationales):
        x = Inches(0.8) + idx * (rat_w + rat_gap)
        add_card(s3, x, rat_top, rat_w, rat_h, bg_color=C_SURFACE_DARK, border_color=C_BORDER)
        tb_r = s3.shapes.add_textbox(x + Inches(0.18), rat_top + Inches(0.14), rat_w - Inches(0.36), rat_h - Inches(0.28))
        tf_r = tb_r.text_frame
        tf_r.word_wrap = True
        tf_r.margin_left = tf_r.margin_top = tf_r.margin_right = tf_r.margin_bottom = 0

        p = tf_r.paragraphs[0]
        p.text = rtitle
        p.font.name = FONT_TITLE
        p.font.size = Pt(9.5)
        p.font.bold = True
        p.font.color.rgb = rcolor
        p.space_after = Pt(4)

        p = tf_r.add_paragraph()
        p.text = rbody
        p.font.name = FONT_BODY
        p.font.size = Pt(8.5)
        p.font.color.rgb = C_TEXT_SEC
        p.line_spacing = 1.15

    print("[✔] Generated Slide 3: Technology Stack")

    # =========================================================================
    # SLIDE 4: System Architecture Diagram
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "04 / 06", "System Architecture",
               "Dual-Track Architecture: Fast Deterministic Core + Isolated SLM",
               "Deterministic analysis runs rapidly on-device; the local SLM runs asynchronously with a 180s timeout and strict verification.")

    # Main Architecture Canvas Card
    arch_bg = add_card(s4, Inches(0.8), Inches(1.8), Inches(11.733), Inches(5.3), bg_color=C_SURFACE_DARK, border_color=C_BORDER)

    # Sub-Box 1: Log Inputs & Normalization (Left)
    b1_x, b1_y, b1_w, b1_h = Inches(1.05), Inches(2.1), Inches(2.4), Inches(4.7)
    add_card(s4, b1_x, b1_y, b1_w, b1_h, bg_color=C_SURFACE, border_color=C_BORDER_LIGHT)
    tb = s4.shapes.add_textbox(b1_x + Inches(0.15), b1_y + Inches(0.15), b1_w - Inches(0.3), b1_h - Inches(0.3))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    p = tf.paragraphs[0]
    p.text = "1. INGESTION & PARSING"
    p.font.name = FONT_TITLE
    p.font.size = Pt(10)
    p.font.bold = True
    p.font.color.rgb = C_CYAN
    p.space_after = Pt(6)

    ing_items = [
        ("Raw Log Sources", "• Windows Event Logs\n• CSV / JSON / JSONL\n• Multi-file batch support"),
        ("Header & Entity Mapping", "• Context-aware field mapping\n• Distinguishes privilege-change actor, target member & group\n• Tolerates missing fields"),
        ("Canonical Normalization", "• SHA-256 row hashing\n• Generates `evt_<id>`\n• Naive timestamp flags\n• EncodedCommand decode"),
        ("Source Provenance", "• Tracks row & source file\n• Malformed row accounting\n• Original values preserved")
    ]
    for h, d in ing_items:
        p = tf.add_paragraph()
        p.text = h
        p.font.name = FONT_TITLE
        p.font.size = Pt(9)
        p.font.bold = True
        p.font.color.rgb = C_WHITE
        p.space_after = Pt(1)

        p = tf.add_paragraph()
        p.text = d
        p.font.name = FONT_BODY
        p.font.size = Pt(8)
        p.font.color.rgb = C_TEXT_SEC
        p.space_after = Pt(5)

    # Sub-Box 2: Deterministic Core (Middle Top)
    b2_x, b2_y, b2_w, b2_h = Inches(3.7), Inches(2.1), Inches(4.3), Inches(2.35)
    add_card(s4, b2_x, b2_y, b2_w, b2_h, bg_color=C_SURFACE, border_color=C_CYAN)
    tb = s4.shapes.add_textbox(b2_x + Inches(0.15), b2_y + Inches(0.12), b2_w - Inches(0.3), b2_h - Inches(0.24))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    p = tf.paragraphs[0]
    p.text = "2. DETERMINISTIC ENGINE (AUTHORITATIVE CORE)"
    p.font.name = FONT_TITLE
    p.font.size = Pt(10)
    p.font.bold = True
    p.font.color.rgb = C_CYAN
    p.space_after = Pt(4)

    det_text = [
        "Four Detection Rule Modules: Repeated Auth Failures (4625), Success After Failures (4624), Privilege/Group Membership Changes (4728/4732), Suspicious Process/Script Hosts (4688). Emits `fnd_<id>`.",
        "Incident Correlation: Correlates findings on User+Host / User+Source-IP within temporal sliding windows. IP-only matches never create an incident.",
        "Additive Heuristic Scoring: 0–100 auditable score based on rule severity, confirmed auth success, attack stages, and host spread (Low 0-24, Med 25-49, High 50-74, Crit 75-100)."
    ]
    for d in det_text:
        p = tf.add_paragraph()
        p.text = f"• {d}"
        p.font.name = FONT_BODY
        p.font.size = Pt(8.2)
        p.font.color.rgb = C_TEXT_SEC
        p.space_after = Pt(3)

    # Sub-Box 3: Local Web Dashboard & Fast Path (Middle Bottom)
    b3_x, b3_y, b3_w, b3_h = Inches(3.7), Inches(4.6), Inches(4.3), Inches(2.2)
    add_card(s4, b3_x, b3_y, b3_w, b3_h, bg_color=C_SURFACE, border_color=C_BLUE)
    tb = s4.shapes.add_textbox(b3_x + Inches(0.15), b3_y + Inches(0.12), b3_w - Inches(0.3), b3_h - Inches(0.24))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    p = tf.paragraphs[0]
    p.text = "3. LOCAL SOC DASHBOARD (FAST DETERMINISTIC PATH)"
    p.font.name = FONT_TITLE
    p.font.size = Pt(10)
    p.font.bold = True
    p.font.color.rgb = C_WHITE
    p.space_after = Pt(4)

    dash_text = [
        "Rapid Local Execution: Deterministic analysis executes on-device in milliseconds without external network overhead or cloud latency.",
        "Interactive SOC Workbench: Incident Explorer, Segmented Subtabs, Heuristic Score Dial, Chronological Attack Timeline, and Evidence Table.",
        "Forensic Inspector: One-click modal displays raw JSON records and decoded PowerShell scripts for deep auditability."
    ]
    for d in dash_text:
        p = tf.add_paragraph()
        p.text = f"✔ {d}"
        p.font.name = FONT_BODY
        p.font.size = Pt(8.2)
        p.font.color.rgb = C_TEXT_SEC
        p.space_after = Pt(3)

    # Sub-Box 4: Asynchronous Advisory SLM Pipeline (Right Column)
    b4_x, b4_y, b4_w, b4_h = Inches(8.25), Inches(2.1), Inches(4.05), Inches(4.7)
    add_card(s4, b4_x, b4_y, b4_w, b4_h, bg_color=C_INDIGO_BG, border_color=C_PURPLE)
    tb = s4.shapes.add_textbox(b4_x + Inches(0.15), b4_y + Inches(0.15), b4_w - Inches(0.3), b4_h - Inches(0.3))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    p = tf.paragraphs[0]
    p.text = "4. VERIFIED LOCAL SLM ADVISORY (ISOLATED)"
    p.font.name = FONT_TITLE
    p.font.size = Pt(10)
    p.font.bold = True
    p.font.color.rgb = C_PURPLE
    p.space_after = Pt(6)

    ai_steps = [
        ("Background Worker Queue", "Non-blocking sequential worker queue. CPU inference can take >100s; guarded by a 180s timeout without freezing the UI."),
        ("Bounded Evidence Dossier", "Compiles compact incident facts. Raw fields are marked untrusted; complete logs are never forwarded."),
        ("Local Ollama Runtime", "Executes `phi4-mini:latest` bound strictly to loopback (127.0.0.1:11434). Zero internet or cloud calls."),
        ("Automated Output Verifier", "Inspects model JSON: validates schema, verifies cited event IDs exist in dossier, checks entity claims and chronology."),
        ("Dual-Outcome Resolution", "• VERIFIED: Displays model interpretation.\n• REJECTED / OFFLINE: Automatic deterministic fallback rule summary.")
    ]
    for h, d in ai_steps:
        p = tf.add_paragraph()
        p.text = h
        p.font.name = FONT_TITLE
        p.font.size = Pt(8.8)
        p.font.bold = True
        p.font.color.rgb = C_WHITE
        p.space_after = Pt(1)

        p = tf.add_paragraph()
        p.text = d
        p.font.name = FONT_BODY
        p.font.size = Pt(7.8)
        p.font.color.rgb = C_TEXT_SEC
        p.space_after = Pt(4)

    print("[✔] Generated Slide 4: System Architecture Diagram")

    # =========================================================================
    # SLIDE 5: Impact
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "05 / 06", "Impact",
               "Operational Efficiency, Data Privacy & Focused Triage",
               "Delivering measurable value across local SOC workflows, privacy-sensitive environments, and resource-constrained teams.")

    # 3 Major Impact Cards (Social/Operational, Economic, Technical)
    imp_top = Inches(1.8)
    imp_w = Inches(3.75)
    imp_gap = Inches(0.24)
    imp_h = Inches(4.5)

    impact_data = [
        ("SOCIAL & OPERATIONAL IMPACT", C_CYAN, [
            ("Combats Alert Fatigue", "Synthesizes isolated, noisy log events into cohesive multi-stage incident narratives, reducing analyst cognitive overload."),
            ("Empowers Resource-Constrained Teams", "Allows small IT departments, universities, and junior analysts to perform structured incident triage without dedicated SIEM engineering."),
            ("Accelerates Investigation Velocity", "Replaces manual grep, spreadsheet filtering, and timestamp alignment with rapid multi-stage correlation."),
            ("Preserves Human Agency", "Provides clear, deterministic next steps and highlights missing evidence, keeping human analysts in control of final containment actions.")
        ]),
        ("ECONOMIC & EFFICIENCY IMPACT", C_GREEN, [
            ("Zero Cloud API & Token Costs", "Eliminates recurring per-token cloud API billing (e.g., OpenAI/Anthropic) that scales unsustainably with large security log volumes."),
            ("Lightweight Local Triage", "Enables local triage and pre-filtering on the analyst workstation before or alongside enterprise logging pipelines."),
            ("Commodity Hardware Compatibility", "Runs efficiently on standard workstation CPUs without requiring expensive enterprise GPU infrastructure."),
            ("Accelerated Threat Visibility", "Early correlation of authentication failures, privilege changes, and suspicious processes provides faster triage context for analyst decision support.")
        ]),
        ("TECHNICAL & INNOVATION IMPACT", C_PURPLE, [
            ("Zero Cloud Data Exposure", "Demonstrates that security incident triage can run entirely on-premises, eliminating cloud exposure for sensitive internal logs."),
            ("Verifiable AI Architecture", "Pioneers a dual-track pattern where an authoritative deterministic engine bounds and audits an advisory local Small Language Model (SLM)."),
            ("Automated Hallucination Defense", "Demonstrates citation enforcement: the model must cite valid canonical event IDs (`evt_...`), or its output defaults to deterministic fallback."),
            ("Standard-Library Resilience", "Built on Python standard-library components to minimize third-party runtime dependencies in incident triage workflows.")
        ])
    ]

    for idx, (title, color, items) in enumerate(impact_data):
        x = Inches(0.8) + idx * (imp_w + imp_gap)
        add_card(s5, x, imp_top, imp_w, imp_h, bg_color=C_SURFACE, border_color=C_BORDER_LIGHT)
        tb_imp = s5.shapes.add_textbox(x + Inches(0.2), imp_top + Inches(0.18), imp_w - Inches(0.4), imp_h - Inches(0.36))
        tf_imp = tb_imp.text_frame
        tf_imp.word_wrap = True
        tf_imp.margin_left = tf_imp.margin_top = tf_imp.margin_right = tf_imp.margin_bottom = 0

        p = tf_imp.paragraphs[0]
        p.text = title
        p.font.name = FONT_TITLE
        p.font.size = Pt(10.5)
        p.font.bold = True
        p.font.color.rgb = color
        p.space_after = Pt(10)

        for h, b in items:
            p = tf_imp.add_paragraph()
            p.text = h
            p.font.name = FONT_TITLE
            p.font.size = Pt(10)
            p.font.bold = True
            p.font.color.rgb = C_WHITE
            p.space_after = Pt(2)

            p = tf_imp.add_paragraph()
            p.text = b
            p.font.name = FONT_BODY
            p.font.size = Pt(8.8)
            p.font.color.rgb = C_TEXT_SEC
            p.space_after = Pt(9)

    # Bottom Prototype Status Disclaimer
    add_card(s5, Inches(0.8), Inches(6.45), Inches(11.733), Inches(0.65), bg_color=C_SURFACE_DARK, border_color=C_BORDER)
    tb_stat = s5.shapes.add_textbox(Inches(1.0), Inches(6.52), Inches(11.333), Inches(0.5))
    tf_stat = tb_stat.text_frame
    tf_stat.word_wrap = True
    tf_stat.margin_left = tf_stat.margin_top = tf_stat.margin_right = tf_stat.margin_bottom = 0
    p = tf_stat.paragraphs[0]
    p.text = "PROTOTYPE SCOPE NOTICE: TRACE-Verified is an analyst decision-support system designed for investigation prioritization. It demonstrates an evidence-backed local-triage paradigm and does not claim to replace enterprise SIEM/EDR platforms or guarantee regulatory compliance."
    p.font.name = FONT_BODY
    p.font.size = Pt(9)
    p.font.bold = True
    p.font.color.rgb = C_MUTED

    print("[✔] Generated Slide 5: Impact")

    # =========================================================================
    # SLIDE 6: Results, Validation & Future Scope
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6)
    add_header(s6, "06 / 06", "Results, Validation & Future Scope",
               "Empirically Validated Capabilities, 150 Tests & Future Scope",
               "Demonstrated attack chain correlation, clean baseline validation, rigorous automated testing, and clear roadmap.")

    col_res_w = Inches(5.75)
    col_fut_w = Inches(5.6)
    gap_rf = Inches(0.38)
    top_rf = Inches(1.8)
    h_rf = Inches(4.5)

    # Left Column: Empirical Validation & Verified Results
    add_card(s6, Inches(0.8), top_rf, col_res_w, h_rf, bg_color=C_SURFACE, border_color=C_BORDER_LIGHT)
    tb_res = s6.shapes.add_textbox(Inches(1.05), top_rf + Inches(0.18), col_res_w - Inches(0.5), h_rf - Inches(0.36))
    tf_res = tb_res.text_frame
    tf_res.word_wrap = True
    tf_res.margin_left = tf_res.margin_top = tf_res.margin_right = tf_res.margin_bottom = 0

    p = tf_res.paragraphs[0]
    p.text = "VERIFIED TEST SCENARIOS & ENGINE METRICS"
    p.font.name = FONT_TITLE
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = C_CYAN
    p.space_after = Pt(8)

    results_data = [
        ("Multi-Stage Attack Chain (attack_chain_mshta)", C_RED,
         "• Successfully ingests Windows authentication, security, and process logs.\n• Detects 8 supporting events across 4 stages: Credential Attack → Successful Authentication → Privilege Change → Suspicious Execution.\n• Correlates into 1 Critical Incident (Heuristic Score 100/100) with complete chronological timeline."),
        ("Clean Baseline Validation (benign)", C_GREEN,
         "• Ingests 6 input rows of clean administrative and operational logs.\n• Evaluated across all 4 detectors with zero incidents produced and complete detector coverage."),
        ("Multi-Entity Windows Audit Scenario", C_BLUE,
         "• Ingests Windows audit logs and correlates 2 distinct concurrent incidents across separate user/host entities without cross-contamination."),
        ("Automated Regression Test Suite", C_CYAN,
         "• 150 automated tests passed across unit, pipeline, and HTTP server test suites.\n• Comprehensive validation: ingestion, normalization, 4 detectors, correlation, scoring, explainer, verifier, CLI, and server.")
    ]

    for title, color, desc in results_data:
        p = tf_res.add_paragraph()
        p.text = title
        p.font.name = FONT_TITLE
        p.font.size = Pt(10)
        p.font.bold = True
        p.font.color.rgb = color
        p.space_after = Pt(1.5)

        p = tf_res.add_paragraph()
        p.text = desc
        p.font.name = FONT_BODY
        p.font.size = Pt(8.8)
        p.font.color.rgb = C_TEXT_SEC
        p.space_after = Pt(7)

    # Right Column: Caveats, Future Scope & References
    add_card(s6, Inches(0.8) + col_res_w + gap_rf, top_rf, col_fut_w, h_rf, bg_color=C_SURFACE, border_color=C_BORDER_LIGHT)
    tb_fut = s6.shapes.add_textbox(Inches(1.05) + col_res_w + gap_rf, top_rf + Inches(0.18), col_fut_w - Inches(0.5), h_rf - Inches(0.36))
    tf_fut = tb_fut.text_frame
    tf_fut.word_wrap = True
    tf_fut.margin_left = tf_fut.margin_top = tf_fut.margin_right = tf_fut.margin_bottom = 0

    p = tf_fut.paragraphs[0]
    p.text = "LIMITATIONS & FUTURE ENGINEERING ROADMAP"
    p.font.name = FONT_TITLE
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = C_PURPLE
    p.space_after = Pt(8)

    future_data = [
        ("Prototype Limitations & Boundaries", C_AMBER,
         "• Heuristic score (0–100) is an investigation prioritization index, not a probabilistic risk score.\n• Sample results are functional software demonstrations, not statistical precision/recall benchmarks.\n• CPU inference can exceed 100 seconds under load; guarded by a configured 180-second timeout with asynchronous UI execution."),
        ("Future Scope & Engineering Roadmap", C_WHITE,
         "• Expanded Windows Telemetry: Integration of Sysmon (Event IDs 1, 3, 7, 10, 11) and PowerShell Script Block Logging (4104).\n• Multi-Platform Ingestion: Linux `auditd`, `/var/log/auth.log`, and cloud trail support.\n• Quantized Security SLMs: Fine-tuned 4-bit GGUF models for faster local CPU inference.\n• Interoperability: Export to STIX 2.1 and MITRE ATT&CK Navigator matrices."),
        ("Key References & Frameworks", C_CYAN,
         "• MITRE ATT&CK Enterprise Matrix (Credential Access, Privilege Escalation, Execution)\n• Microsoft Windows Security Auditing Reference & Log Architecture\n• Ollama Local Inference Framework & Microsoft Phi-4-mini Technical Architecture")
    ]

    for title, color, desc in future_data:
        p = tf_fut.add_paragraph()
        p.text = title
        p.font.name = FONT_TITLE
        p.font.size = Pt(10)
        p.font.bold = True
        p.font.color.rgb = color
        p.space_after = Pt(1.5)

        p = tf_fut.add_paragraph()
        p.text = desc
        p.font.name = FONT_BODY
        p.font.size = Pt(8.8)
        p.font.color.rgb = C_TEXT_SEC
        p.space_after = Pt(7)

    # Bottom Callout Summary Strip
    add_card(s6, Inches(0.8), Inches(6.45), Inches(11.733), Inches(0.65), bg_color=C_SURFACE_DARK, border_color=C_GREEN)
    tb_sum = s6.shapes.add_textbox(Inches(1.0), Inches(6.52), Inches(11.333), Inches(0.5))
    tf_sum = tb_sum.text_frame
    tf_sum.word_wrap = True
    tf_sum.margin_left = tf_sum.margin_top = tf_sum.margin_right = tf_sum.margin_bottom = 0
    p = tf_sum.paragraphs[0]
    p.text = "CONCLUSION: TRACE-Verified delivers a working, privacy-preserving incident triage assistant that combines deterministic security rigor with verified local intelligence — empowering analysts while keeping sensitive data strictly on localhost."
    p.font.name = FONT_TITLE
    p.font.size = Pt(9.5)
    p.font.bold = True
    p.font.color.rgb = C_GREEN

    print("[✔] Generated Slide 6: Results, Validation & Future Scope")

    # Save Final Output
    output_path = Path("TRACE-Verified_TINYVERSE_Presentation.pptx").resolve()
    prs.save(str(output_path))
    print(f"\n=======================================================")
    print(f"[SUCCESS] Presentation saved to: {output_path}")
    print(f"Total slides generated: {len(prs.slides)}")
    print(f"=======================================================")

if __name__ == "__main__":
    create_presentation()
