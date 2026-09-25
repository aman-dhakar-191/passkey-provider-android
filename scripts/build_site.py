#!/usr/bin/env python3
"""Builds the GitHub Pages site into _site/ (used by .github/workflows/pages.yml).

site/ holds the landing page; the privacy page is generated from PRIVACY.md so there is one copy of the
policy. "Last changed" dates come from git, so they can't go stale. Needs git history for those files
(the workflow checks out with fetch-depth: 0). Only handles the Markdown PRIVACY.md uses: headings,
paragraphs, "- " lists with indented continuation lines, **bold**, _italic_, `code` and bare links.
"""
import datetime
import html
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "_site"
REPO = "https://github.com/aman-dhakar-191/passkey-provider-android"


def last_changed(*paths):
    date = subprocess.run(
        ["git", "log", "-1", "--format=%cs", "--", *paths], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    if not date:
        sys.exit(f"No git history for {paths}; check out with fetch-depth: 0")
    return datetime.date.fromisoformat(date).strftime("%-d %B %Y")


def inline(text):
    text = html.escape(text, quote=False)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<![\w/])_([^_]+)_(?!\w)", r"<em>\1</em>", text)
    # Bare links, but not ones inside <code>.
    parts = re.split(r"(<code>.*?</code>)", text)
    parts = [p if p.startswith("<code>") else re.sub(r"(https://[^\s<)]+[^\s<).,])", r'<a href="\1">\1</a>', p)
             for p in parts]
    return "".join(parts)


def markdown(md):
    out, para, items = [], [], []

    def flush():
        if para:
            out.append(f"<p>{inline(' '.join(para))}</p>")
            para.clear()
        if items:
            out.append("<ul>" + "".join(f"<li>{inline(i)}</li>" for i in items) + "</ul>")
            items.clear()

    for line in md.splitlines():
        if not line.strip():
            flush()
        elif m := re.match(r"(#{1,3}) (.*)", line):
            flush()
            level = len(m.group(1))
            out.append(f"<h{level}>{inline(m.group(2))}</h{level}>")
        elif line.startswith("- "):
            if para:
                flush()
            items.append(line[2:].strip())
        elif items and line.startswith("  "):
            items[-1] += " " + line.strip()
        else:
            para.append(line.strip())
    flush()
    return "\n".join(out)


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    shutil.copytree(ROOT / "site", OUT, ignore=shutil.ignore_patterns("*.template.html"))
    shutil.copy(ROOT / "docs/store/icon-512.png", OUT / "icon.png")
    (OUT / "screenshots").mkdir()
    for shot in sorted((ROOT / "docs/store").glob("screenshot-*.png")):
        shutil.copy(shot, OUT / "screenshots" / shot.name)

    index = OUT / "index.html"
    index.write_text(index.read_text().replace(
        "{{SITE_UPDATED}}", last_changed("site", "docs/store", "PRIVACY.md")))

    privacy = (ROOT / "site/privacy.template.html").read_text()
    privacy = (privacy.replace("{{CONTENT}}", markdown((ROOT / "PRIVACY.md").read_text()))
               .replace("{{UPDATED}}", last_changed("PRIVACY.md"))
               .replace("{{HISTORY}}", f"{REPO}/commits/main/PRIVACY.md"))
    (OUT / "privacy").mkdir()
    (OUT / "privacy/index.html").write_text(privacy)

    for page in OUT.rglob("*.html"):
        if "{{" in page.read_text():
            sys.exit(f"Unfilled placeholder in {page}")
    print(f"Built {OUT}")


if __name__ == "__main__":
    main()
