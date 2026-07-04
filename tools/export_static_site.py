"""把已扫描结果导出成自包含静态 HTML 到 docs/，供 GitHub Pages 托管。

用法：
    python tools/export_static_site.py

产物：
    docs/index.html              ← 结果卡片页（所有已扫 skill）
    docs/report-<skill>.html     ← 每个 skill 的 SAFESKILL 报告页

链接已重写成静态相对路径；导航里需要服务器的"扫描"入口被替换成说明。
GitHub Pages 设置：Settings → Pages → Source = main 分支 /docs 目录。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS = REPO_ROOT / "docs"
sys.path.insert(0, str(REPO_ROOT / "web_ui"))

import app  # noqa: E402


def _report_filename(skill_name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", skill_name)
    return f"report-{safe}.html"


def _rewrite_links(html: str, skills: list[dict]) -> str:
    # 卡片 /report/<skill> → 静态文件名
    for s in skills:
        name = str(s["skill_name"])
        html = html.replace(f'href="/report/{name}"', f'href="{_report_filename(name)}"')
    # 导航：扫描(/) 和 结果(/results) 都指回 index（静态站没有上传服务器）
    html = html.replace('href="/results"', 'href="index.html"')
    html = html.replace('href="/"', 'href="index.html"')
    return html


STATIC_BANNER = (
    '<div style="background:#1e3354;color:#cbd5e1;text-align:center;'
    'padding:8px 12px;font-size:12px;border-bottom:1px solid #38bdf8;">'
    '📦 这是一份 <strong>静态快照</strong>（GitHub Pages 托管）。'
    '上传扫描需要本地运行 <code style="background:#07101f;padding:1px 5px;border-radius:3px;">python web_ui/app.py</code>。'
    '</div>'
)


def _inject_banner(html: str) -> str:
    return html.replace("<body>", "<body>\n" + STATIC_BANNER, 1)


def main() -> int:
    skills = app.list_asg_skills()
    if not skills:
        print("没有已扫描结果（analysis_results/asg/ 为空），先扫几个 skill。")
        return 1
    DOCS.mkdir(parents=True, exist_ok=True)

    # 1) 结果页（不分页，一次列全部）
    cards_html = app.render_jobs_cards(skills)
    results_html = app.render_template("results.html", {
        "public_badge": '<span class="public-badge" style="background:#dcfce7;color:#166534;border-color:#86efac;">静态快照</span>',
        "jobs_cards": cards_html,
        "jobs_count": len(skills),
        "pagination": "",
        "page_info": f"共 {len(skills)} 个已扫描 skill · 静态导出",
    }).decode("utf-8")
    results_html = _inject_banner(_rewrite_links(results_html, skills))
    (DOCS / "index.html").write_text(results_html, encoding="utf-8")
    print(f"wrote docs/index.html ({len(skills)} skills)")

    # 2) 每个 skill 的报告页
    for s in skills:
        name = str(s["skill_name"])
        rep = app.render_safeskill_report(s).decode("utf-8")
        rep = _inject_banner(_rewrite_links(rep, skills))
        fn = _report_filename(name)
        (DOCS / fn).write_text(rep, encoding="utf-8")
        print(f"wrote docs/{fn}")

    # 3) .nojekyll（防止 GitHub Pages 的 Jekyll 处理）
    (DOCS / ".nojekyll").write_text("", encoding="utf-8")
    print("wrote docs/.nojekyll")
    print(f"\n完成。共导出 {len(skills) + 1} 个 HTML。")
    print("启用 GitHub Pages：仓库 Settings → Pages → Source = main / docs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
