#!/usr/bin/env python3
"""
Sync and convert MkDocs documentation into Astro Starlight MDX pages.
Maintains 100% parity across all chapters, features, and attack scenarios.
"""

import os
from pathlib import Path
import re
import shutil
import sys
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
MKDOCS_YML = REPO_ROOT / "mkdocs.yml"
DOCS_DIR = REPO_ROOT / "docs"
STARLIGHT_DIR = REPO_ROOT / "starlight"
STARLIGHT_DOCS_DIR = STARLIGHT_DIR / "src" / "content" / "docs"

class SafeLoaderIgnoreUnknown(yaml.SafeLoader):
    pass

SafeLoaderIgnoreUnknown.add_multi_constructor("tag:yaml.org,2002:python/", lambda loader, suffix, node: None)
SafeLoaderIgnoreUnknown.add_multi_constructor("!python/", lambda loader, suffix, node: None)

# Load navigation tree from mkdocs.yml
with open(MKDOCS_YML, "r", encoding="utf-8") as f:
    mkdocs_cfg = yaml.load(f, Loader=SafeLoaderIgnoreUnknown)

nav_tree = mkdocs_cfg.get("nav", [])


def extract_title(content: str) -> str:
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("# "):
            title = line[2:].strip()
            # Clean up markdown formatting if any
            title = re.sub(r"\[(.*?)\]\(.*?\)", r"\1", title)
            return title.replace('"', '\\"')
    return "Documentation"


def convert_admonitions(content: str) -> str:
    """
    Convert MkDocs admonitions:
      !!! note "Title"
          Body
      !!! note
          Body
    to Starlight:
      <Aside type="note" title="Title">
        Body
      </Aside>
    """
    type_map = {
        "note": "note",
        "info": "note",
        "abstract": "note",
        "tip": "tip",
        "warning": "caution",
        "caution": "caution",
        "danger": "danger",
        "failure": "danger",
        "error": "danger",
    }

    lines = content.splitlines()
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        match = re.match(r"^(\s*)!!!\s+(\w+)(?:\s+\"(.*?)\")?\s*$", line)
        if match:
            indent_prefix = match.group(1)
            admon_type = type_map.get(match.group(2).lower(), "note")
            admon_title = match.group(3)

            title_attr = f' title="{admon_title}"' if admon_title else ""
            out.append(f'{indent_prefix}<Aside type="{admon_type}"{title_attr}>')

            i += 1
            body_lines = []
            while i < len(lines):
                cur_line = lines[i]
                if cur_line.strip() == "":
                    body_lines.append("")
                    i += 1
                    continue
                # Indented content belongs to admonition (typically 4 spaces)
                if cur_line.startswith(indent_prefix + "    ") or cur_line.startswith(indent_prefix + "\t"):
                    body_lines.append(cur_line[len(indent_prefix) + 4:])
                    i += 1
                else:
                    break
            # Strip trailing blank lines
            while body_lines and body_lines[-1] == "":
                body_lines.pop()

            for b in body_lines:
                out.append(f"{indent_prefix}  {b}")
            out.append(f"{indent_prefix}</Aside>")
        else:
            out.append(line)
            i += 1
    return "\n".join(out)


def convert_tabs(content: str) -> str:
    """
    Convert PyMdown tabs:
      === "Tab 1"
          Content
      === "Tab 2"
          Content
    to Starlight:
      <Tabs syncKey="arch">
        <TabItem label="Tab 1">
          Content
        </TabItem>
        ...
      </Tabs>
    """
    lines = content.splitlines()
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        tab_match = re.match(r"^(\s*)===\s+\"(.*?)\"\s*$", line)
        if tab_match:
            indent = tab_match.group(1)
            tabs = []

            # Gather all consecutive tabs in this set
            while i < len(lines):
                cur_line = lines[i]
                cur_tab_match = re.match(r"^(\s*)===\s+\"(.*?)\"\s*$", cur_line)
                if cur_tab_match and cur_tab_match.group(1) == indent:
                    tab_label = cur_tab_match.group(2)
                    i += 1
                    tab_body = []
                    while i < len(lines):
                        b_line = lines[i]
                        if b_line.strip() == "":
                            tab_body.append("")
                            i += 1
                            continue
                        if b_line.startswith(indent + "    ") or b_line.startswith(indent + "\t"):
                            tab_body.append(b_line[len(indent) + 4:])
                            i += 1
                        else:
                            break
                    while tab_body and tab_body[-1] == "":
                        tab_body.pop()
                    tabs.append((tab_label, tab_body))
                elif cur_line.strip() == "":
                    # Peek ahead to see if next non-empty is a tab at same indent
                    next_tab = False
                    for peek_idx in range(i + 1, min(i + 5, len(lines))):
                        peek_line = lines[peek_idx]
                        if peek_line.strip() == "":
                            continue
                        if re.match(r"^" + re.escape(indent) + r"===\s+\".*?\"\s*$", peek_line):
                            next_tab = True
                        break
                    if next_tab:
                        i += 1
                        continue
                    else:
                        break
                else:
                    break

            # Render <Tabs syncKey="arch">
            out.append(f'{indent}<Tabs syncKey="arch">')
            for label, body in tabs:
                icon_attr = ""
                clean_label = label
                if "x86" in label.lower():
                    icon_attr = ' icon="laptop"'
                elif "arm" in label.lower() or "aarch64" in label.lower():
                    icon_attr = ' icon="seti:arm"'
                elif "hardened" in label.lower() or "보호 활성화" in label:
                    icon_attr = ' icon="approve-check-circle"'

                out.append(f'{indent}  <TabItem label="{clean_label}"{icon_attr}>')
                for b in body:
                    out.append(f"{indent}    {b}")
                out.append(f'{indent}  </TabItem>')
            out.append(f'{indent}</Tabs>')
        else:
            out.append(line)
            i += 1
    return "\n".join(out)


BASE_URL = os.environ.get("BASE_PATH")
if BASE_URL is None:
    BASE_URL = "/linux-kernel-hardening-lab" if os.environ.get("GITHUB_ACTIONS") else ""
BASE_URL = BASE_URL.rstrip("/")


def fix_asset_paths(content: str) -> str:
    """
    Rewrite relative asset paths (diagrams, images, labs):
      ../../assets/... or ../assets/...
    to base-aware public web path:
      {BASE_URL}/assets/...
    """
    prefix = f"{BASE_URL}/assets/" if BASE_URL else "/assets/"
    return re.sub(r'(?:\.\./)+assets/', prefix, content)


def escape_mdx_prose(content: str) -> str:
    """
    MDX (JSX) parses bare '<' and '{' in prose as JSX tags/expressions.
    Escape bare comparison operators (e.g., '< 1%', '<= size', '{ #anchor }')
    outside of code blocks and valid HTML tags.
    """
    # 0. Strip redundant inline <script> tags used in legacy MkDocs pages
    # (Starlight has starlight-bridge.js loaded globally in head)
    content = re.sub(r'<script\b[^>]*>[\s\S]*?<\/script>', '', content)

    lines = content.splitlines()
    out = []
    in_code_block = False

    for line in lines:
        if line.strip().startswith("```"):
            in_code_block = not in_code_block
            out.append(line)
            continue

        if in_code_block:
            out.append(line)
            continue

        # In prose:
        # 1. Remove MkDocs header anchor syntax: {: #anchor-name } or { #anchor-name }
        line = re.sub(r'\{:?\s*#[a-zA-Z0-9_\-]+\s*\}', '', line)

        # 2. Convert unclosed HTML void tags (<br>, <hr>, <img>) to self-closing (<br />, <hr />, <img />) for JSX compliance
        line = re.sub(r'<(br|hr|img)([^>]*?)(?<!/)>', r'<\1\2 />', line)

        # 3. Escape bare '<' that is not part of a valid HTML tag or Starlight JSX component
        # Valid tags list: a, p, b, i, code, pre, span, div, strong, em, br, hr, img, table, thead, tbody, tr, th, td, ul, ol, li, blockquote, sub, sup, Aside, Tabs, TabItem, Badge, Steps, Card, CardGrid, LinkCard, iframe
        valid_tags = r'/?(?:div|span|iframe|a|p|b|i|code|pre|strong|em|br|hr|img|table|thead|tbody|tr|th|td|ul|ol|li|blockquote|sub|sup|Aside|Tabs|TabItem|Badge|Steps|Card|CardGrid|LinkCard)\b'
        line = re.sub(r'<(?=[0-9%=\s])', '&lt;', line)
        line = re.sub(r'<(?!' + valid_tags + r'|[a-zA-Z]+[0-9]*[\s/>])', '&lt;', line)

        out.append(line)

    return "\n".join(out)


def transform_markdown_to_mdx(src_path: Path, lang: str) -> str:
    with open(src_path, "r", encoding="utf-8") as f:
        raw = f.read()

    # If it's the root index.md, we have a custom curated splash page in Starlight
    if src_path.name == "index.md" and src_path.parent == DOCS_DIR / lang:
        pass  # Will handle index.md specifically

    title = extract_title(raw)
    
    # Strip first H1 line if present, Starlight renders title from frontmatter
    lines = raw.splitlines()
    body_lines = []
    removed_h1 = False
    for l in lines:
        if not removed_h1 and l.strip().startswith("# "):
            removed_h1 = True
            continue
        body_lines.append(l)
    content = "\n".join(body_lines)

    # Conversions
    content = convert_admonitions(content)
    content = convert_tabs(content)
    content = fix_asset_paths(content)
    content = escape_mdx_prose(content)

    # Check which Starlight components were introduced
    needed_imports = []
    if "<Aside" in content:
        needed_imports.append("Aside")
    if "<Tabs" in content:
        needed_imports.append("Tabs")
        needed_imports.append("TabItem")
    if "<Badge" in content or "sl-badge" in content:
        # Replace .sl-badge spans if any
        needed_imports.append("Badge")
        content = re.sub(r'<span class="sl-badge sl-badge--green">(.*?)</span>', r'<Badge text="\1" variant="success" />', content)
        content = re.sub(r'<span class="sl-badge sl-badge--blue">(.*?)</span>', r'<Badge text="\1" variant="tip" />', content)
        content = re.sub(r'<span class="sl-badge sl-badge--purple">(.*?)</span>', r'<Badge text="\1" variant="note" />', content)

    import_header = ""
    if needed_imports:
        unique_components = sorted(list(set(needed_imports)))
        import_header = f"import {{ {', '.join(unique_components)} }} from '@astrojs/starlight/components';\n\n"

    # Frontmatter
    frontmatter = f"---\ntitle: \"{title}\"\n---\n\n"

    return frontmatter + import_header + content


def generate_starlight_sidebar():
    def nav_item_to_sidebar(item):
        if isinstance(item, dict):
            for label, val in item.items():
                if isinstance(val, str):
                    p = Path(val)
                    if p.name == "index.md" and len(p.parts) == 1:
                        # Root index.md is accessed via header logo/title
                        return None
                    if p.name == "index.md":
                        slug = str(p.parent)
                    else:
                        slug = str(p.with_suffix(""))
                    return {"label": label, "slug": slug}
                elif isinstance(val, list):
                    sub_items = [nav_item_to_sidebar(sub) for sub in val]
                    sub_items = [s for s in sub_items if s is not None]
                    return {"label": label, "items": sub_items}
        return None

    sidebar = [nav_item_to_sidebar(item) for item in nav_tree]
    sidebar = [s for s in sidebar if s is not None]
    return sidebar


def update_astro_config_sidebar():
    import json
    sidebar = generate_starlight_sidebar()
    sidebar_json = json.dumps(sidebar, indent=6, ensure_ascii=False)
    # Indent sidebar items properly
    indented_sidebar = "\n".join("      " + line if line.strip() else "" for line in sidebar_json.splitlines()).strip()

    config_path = STARLIGHT_DIR / "astro.config.mjs"
    with open(config_path, "r", encoding="utf-8") as f:
        content = f.read()

    new_content = re.sub(
        r"sidebar:\s*\[[\s\S]*?\],\s*\}\),",
        f"sidebar: {indented_sidebar},\n    }}),",
        content
    )

    with open(config_path, "w", encoding="utf-8") as f:
        f.write(new_content)
    print("[+] Updated starlight/astro.config.mjs sidebar matching mkdocs.yml navigation!")


def ensure_public_assets():
    public_assets = STARLIGHT_DIR / "public" / "assets"
    docs_assets = DOCS_DIR / "assets"
    if not public_assets.exists() and not public_assets.is_symlink():
        try:
            public_assets.symlink_to("../../docs/assets")
            print("[+] Linked docs/assets into starlight/public/assets")
        except Exception:
            shutil.copytree(docs_assets, public_assets)
            print("[+] Copied docs/assets into starlight/public/assets")


def sync_all_docs():
    ensure_public_assets()
    print("[*] Synchronizing docs/ into starlight/src/content/docs/...")

    for lang in ["ko", "en"]:
        src_lang_dir = DOCS_DIR / lang
        if not src_lang_dir.exists():
            continue

        target_base = STARLIGHT_DOCS_DIR if lang == "ko" else STARLIGHT_DOCS_DIR / "en"

        for md_file in src_lang_dir.rglob("*.md"):
            rel_path = md_file.relative_to(src_lang_dir)
            
            # Root index is preserved with custom splash layout
            if rel_path == Path("index.md"):
                print(f"  - Preserving curated splash page for {lang}/index.mdx")
                continue

            # Convert .md extension to .mdx for Starlight
            target_mdx = (target_base / rel_path).with_suffix(".mdx")
            target_mdx.parent.mkdir(parents=True, exist_ok=True)

            mdx_content = transform_markdown_to_mdx(md_file, lang)
            with open(target_mdx, "w", encoding="utf-8") as out_f:
                out_f.write(mdx_content)

    print("[+] All documents converted and synchronized successfully!")
    update_astro_config_sidebar()


if __name__ == "__main__":
    sync_all_docs()

