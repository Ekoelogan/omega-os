"""omega codetrace — Code attribution OSINT:
GitHub commit timezone analysis, language fingerprinting, author geography/timezone inference."""
from __future__ import annotations
import json, os, re, datetime, collections
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
TIMEOUT = 10

# Timezone offset → likely regions (UTC offset → region candidates)
TZ_REGIONS: dict[int, list[str]] = {
    -8:  ["US West (PST)", "Canada (Vancouver)"],
    -7:  ["US Mountain (MST)", "Canada (Calgary)"],
    -6:  ["US Central (CST)", "Mexico City"],
    -5:  ["US East (EST)", "Canada (Toronto)", "Colombia", "Peru"],
    -4:  ["US East DST", "Venezuela", "Chile"],
    -3:  ["Brazil (BRT)", "Argentina", "Uruguay"],
    0:   ["UK (GMT)", "Ireland", "Portugal", "West Africa"],
    1:   ["Central Europe (CET)", "Germany", "France", "Nigeria", "Algeria"],
    2:   ["Eastern Europe (EET)", "Egypt", "South Africa", "Israel"],
    3:   ["Russia (MSK)", "Saudi Arabia", "Kenya", "Iraq"],
    4:   ["UAE", "Azerbaijan", "Georgia", "Mauritius"],
    5:   ["Pakistan", "Uzbekistan"],
    6:   ["Bangladesh", "Kyrgyzstan"],
    7:   ["Thailand", "Vietnam", "Indonesia (WIB)"],
    8:   ["China (CST)", "Singapore", "Taiwan", "Philippines", "Australia (AWST)"],
    9:   ["Japan (JST)", "South Korea"],
    10:  ["Australia (AEST)", "Papua New Guinea"],
    12:  ["New Zealand", "Fiji"],
}

# Coding patterns → likely dev background
LANG_STYLE_HINTS = {
    "py":   "Python developer",
    "js":   "JavaScript/Node.js developer",
    "ts":   "TypeScript developer",
    "rs":   "Rust developer",
    "go":   "Go developer",
    "java": "Java developer",
    "rb":   "Ruby developer",
    "php":  "PHP developer",
    "cs":   "C# / .NET developer",
    "cpp":  "C++ developer",
    "c":    "C systems developer",
    "sh":   "Shell/DevOps engineer",
    "ps1":  "PowerShell / Windows admin",
    "kt":   "Kotlin / Android developer",
    "swift":"Swift / iOS developer",
    "r":    "Data scientist (R)",
    "scala":"Scala / Spark developer",
    "lua":  "Game / embedded developer (Lua)",
    "ex":   "Elixir developer",
    "hs":   "Haskell developer",
}


def _get_user_info(username: str, token: str = "") -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = httpx.get(f"https://api.github.com/users/{username}",
                      headers=headers, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def _get_repos(username: str, token: str = "") -> list[dict]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = httpx.get(
            f"https://api.github.com/users/{username}/repos",
            headers=headers,
            params={"per_page": 100, "sort": "updated", "type": "owner"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return []


def _get_commits(owner: str, repo: str, token: str = "", limit: int = 100) -> list[dict]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = httpx.get(
            f"https://api.github.com/repos/{owner}/{repo}/commits",
            headers=headers,
            params={"per_page": limit},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return []


def _parse_tz_offset(iso_ts: str) -> int | None:
    """Extract UTC offset in hours from ISO8601 timestamp."""
    m = re.search(r"([+-])(\d{2}):(\d{2})$", iso_ts)
    if m:
        sign = 1 if m.group(1) == "+" else -1
        return sign * int(m.group(2))
    return None


def _hour_of_day(iso_ts: str) -> int | None:
    """Extract local hour from ISO8601 timestamp."""
    try:
        # strip tz, get hour
        clean = re.sub(r"[+-]\d{2}:\d{2}$|Z$", "", iso_ts)
        dt = datetime.datetime.fromisoformat(clean)
        return dt.hour
    except Exception:
        return None


def _analyse_commits(all_commits: list[dict]) -> dict[str, Any]:
    tz_offsets: list[int] = []
    hours: list[int] = []
    emails: set[str] = set()
    names: set[str] = set()
    days: list[int] = []  # 0=Mon … 6=Sun
    timestamps: list[str] = []

    for commit_obj in all_commits:
        commit = commit_obj.get("commit", {})
        author = commit.get("author", {})
        ts = author.get("date", "")
        if not ts:
            continue
        timestamps.append(ts)

        email = author.get("email", "")
        name = author.get("name", "")
        if email and "noreply" not in email:
            emails.add(email)
        if name:
            names.add(name)

        tz = _parse_tz_offset(ts)
        if tz is not None:
            tz_offsets.append(tz)

        h = _hour_of_day(ts)
        if h is not None:
            hours.append(h)

        try:
            clean = re.sub(r"[+-]\d{2}:\d{2}$|Z$", "", ts)
            dt = datetime.datetime.fromisoformat(clean)
            days.append(dt.weekday())
        except Exception:
            pass

    # Most common TZ offset
    tz_counter = collections.Counter(tz_offsets)
    hour_counter = collections.Counter(hours)
    day_counter = collections.Counter(days)

    dominant_tz = tz_counter.most_common(1)[0][0] if tz_counter else None
    peak_hours = [h for h, _ in hour_counter.most_common(5)]

    # Work pattern inference
    work_pattern = "unknown"
    if peak_hours:
        avg = sum(peak_hours) / len(peak_hours)
        if 8 <= avg <= 18:
            work_pattern = "day worker (9-5 pattern)"
        elif 18 <= avg <= 23:
            work_pattern = "evening coder"
        elif 0 <= avg <= 6:
            work_pattern = "night owl"
        elif 22 <= avg or avg <= 2:
            work_pattern = "late night / possible different timezone"

    # Weekend ratio
    weekend_commits = sum(day_counter.get(d, 0) for d in [5, 6])
    total_commits = len(hours)
    weekend_ratio = weekend_commits / total_commits if total_commits else 0

    return {
        "total_commits":    total_commits,
        "unique_emails":    list(emails)[:10],
        "unique_names":     list(names)[:10],
        "dominant_tz_offset": dominant_tz,
        "tz_distribution":  dict(tz_counter.most_common(5)),
        "peak_commit_hours":peak_hours,
        "hour_distribution":dict(hour_counter),
        "day_distribution": dict(day_counter),
        "work_pattern":     work_pattern,
        "weekend_ratio":    round(weekend_ratio, 3),
        "region_candidates":TZ_REGIONS.get(dominant_tz, ["Unknown"]) if dominant_tz is not None else [],
        "first_commit":     min(timestamps) if timestamps else None,
        "last_commit":      max(timestamps) if timestamps else None,
    }


def _language_profile(repos: list[dict]) -> dict[str, Any]:
    lang_counter: dict[str, int] = {}
    for repo in repos:
        lang = repo.get("language")
        if lang:
            ext = lang.lower().replace(" ", "").replace("#", "s").replace("+", "p")
            lang_counter[lang] = lang_counter.get(lang, 0) + 1

    total = sum(lang_counter.values())
    profile = []
    for lang, cnt in sorted(lang_counter.items(), key=lambda x: -x[1]):
        ext_key = lang.lower().replace(" ", "")[:6]
        hint = next((v for k, v in LANG_STYLE_HINTS.items() if k in ext_key), "")
        profile.append({
            "language": lang,
            "repos": cnt,
            "pct": round(cnt / total * 100, 1) if total else 0,
            "profile": hint,
        })
    return {"languages": profile, "primary": profile[0]["language"] if profile else "Unknown"}


def run(target: str, token: str = "", repo: str = "", deep: bool = False):
    console.print(Panel(
        f"[bold #ff2d78]🔍  Code Attribution OSINT[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    from omega_cli.config import load as load_cfg
    cfg = load_cfg()
    gh_token = token or cfg.get("github_token", "")

    findings: dict[str, Any] = {"target": target}

    # User profile
    with console.status("[cyan]Fetching GitHub profile…"):
        user = _get_user_info(target, gh_token)

    if user:
        console.print(f"\n[bold]GitHub Profile:[/bold]")
        for field in ["name", "company", "location", "email", "bio", "created_at", "public_repos"]:
            val = user.get(field)
            if val:
                console.print(f"  [#ff2d78]{field}:[/#ff2d78] {val}")
        findings["profile"] = {k: user.get(k) for k in
                               ["login","name","email","company","location","bio","created_at","public_repos"]}
    else:
        console.print(f"[dim]No public GitHub profile found for '{target}'[/dim]")

    # Repos + language profile
    with console.status("[cyan]Fetching repositories…"):
        repos = _get_repos(target, gh_token)
    findings["repo_count"] = len(repos)
    console.print(f"\n[dim]{len(repos)} public repositories found[/dim]")

    lang_prof = _language_profile(repos)
    findings["language_profile"] = lang_prof
    if lang_prof["languages"]:
        t = Table("Language", "Repos", "%", "Dev Profile",
                  title="[bold]Language Fingerprint[/bold]",
                  box=box.SIMPLE_HEAD, header_style="bold #ff2d78")
        for lp in lang_prof["languages"][:10]:
            t.add_row(lp["language"], str(lp["repos"]),
                      f"{lp['pct']}%", lp["profile"] or "—")
        console.print(t)

    # Commit timezone analysis
    target_repo = repo
    if not target_repo and repos:
        # Pick most-starred or first repo
        repos_sorted = sorted(repos, key=lambda r: r.get("stargazers_count", 0), reverse=True)
        target_repo = repos_sorted[0]["name"] if repos_sorted else ""

    commit_data: dict = {}
    if target_repo:
        limit = 100 if deep else 50
        with console.status(f"[cyan]Analysing commits in {target_repo}…"):
            commits = _get_commits(target, target_repo, gh_token, limit)
        commit_data = _analyse_commits(commits)
        findings["commit_analysis"] = commit_data

        console.print(f"\n[bold]Commit Timezone Analysis[/bold] ([dim]{target_repo}[/dim])")
        tz = commit_data["dominant_tz_offset"]
        sign = "+" if tz is not None and tz >= 0 else ""
        console.print(f"  Dominant TZ offset:  [cyan]UTC{sign}{tz}[/cyan]")
        console.print(f"  Region candidates:   [bold]{', '.join(commit_data['region_candidates'])}[/bold]")
        console.print(f"  Work pattern:        [cyan]{commit_data['work_pattern']}[/cyan]")
        console.print(f"  Weekend ratio:       [cyan]{commit_data['weekend_ratio']*100:.0f}%[/cyan] of commits on weekends")
        console.print(f"  Peak hours (local):  {commit_data['peak_commit_hours']}")
        if commit_data["unique_emails"]:
            console.print(f"  Author emails:       [yellow]{', '.join(commit_data['unique_emails'][:5])}[/yellow]")
        if commit_data["unique_names"]:
            console.print(f"  Author names:        {', '.join(commit_data['unique_names'][:5])}")

        # Hour heatmap (mini)
        console.print("\n[bold]Commit Activity Heatmap:[/bold]")
        hour_dist = commit_data["hour_distribution"]
        max_h = max(hour_dist.values()) if hour_dist else 1
        row1, row2 = "", ""
        for h in range(12):
            cnt = hour_dist.get(h, 0)
            bar_h = int(cnt / max_h * 4)
            row1 += f"[dim]{h:02d}[/dim][cyan]{'▪' * bar_h}{'·' * (4-bar_h)}[/cyan] "
        for h in range(12, 24):
            cnt = hour_dist.get(h, 0)
            bar_h = int(cnt / max_h * 4)
            row2 += f"[dim]{h:02d}[/dim][cyan]{'▪' * bar_h}{'·' * (4-bar_h)}[/cyan] "
        console.print(f"  00-11: {row1}")
        console.print(f"  12-23: {row2}")

    # Save
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out = os.path.join(out_dir, f"codetrace_{safe}_{ts}.json")
    with open(out, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out}[/dim]")
