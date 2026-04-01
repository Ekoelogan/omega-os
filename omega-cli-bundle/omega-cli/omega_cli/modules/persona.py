"""omega persona — OpSec persona builder: generate realistic fictitious identity
for red team / undercover OSINT (name, email, username, backstory, documents)."""
from __future__ import annotations
import json, os, re, random, hashlib, datetime, string
from typing import Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# Realistic name pools
FIRST_NAMES_M = ["James","Michael","Robert","David","William","John","Richard","Thomas","Charles","Daniel",
                  "Matthew","Anthony","Mark","Donald","Paul","Andrew","Joshua","Kenneth","Kevin","Brian",
                  "Liam","Noah","Oliver","Ethan","Lucas","Mason","Logan","Aiden","Carter","Dylan"]
FIRST_NAMES_F = ["Mary","Patricia","Jennifer","Linda","Barbara","Susan","Jessica","Sarah","Karen","Lisa",
                  "Betty","Dorothy","Sandra","Ashley","Kimberly","Emily","Donna","Michelle","Carol","Amanda",
                  "Emma","Olivia","Ava","Isabella","Sophia","Charlotte","Mia","Amelia","Harper","Evelyn"]
LAST_NAMES    = ["Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis","Wilson","Anderson",
                  "Taylor","Thomas","Moore","Martin","Jackson","Thompson","White","Harris","Sanchez","Clark",
                  "Lewis","Robinson","Walker","Hall","Allen","Young","King","Wright","Scott","Torres",
                  "Nguyen","Hill","Flores","Green","Adams","Nelson","Baker","Carter","Mitchell","Perez"]

COUNTRIES = [
    {"name":"United States","code":"US","tld":".us","tz":"America/New_York","phone":"+1"},
    {"name":"United Kingdom","code":"GB","tld":".co.uk","tz":"Europe/London","phone":"+44"},
    {"name":"Germany","code":"DE","tld":".de","tz":"Europe/Berlin","phone":"+49"},
    {"name":"Canada","code":"CA","tld":".ca","tz":"America/Toronto","phone":"+1"},
    {"name":"Australia","code":"AU","tld":".au","tz":"Australia/Sydney","phone":"+61"},
    {"name":"Netherlands","code":"NL","tld":".nl","tz":"Europe/Amsterdam","phone":"+31"},
    {"name":"France","code":"FR","tld":".fr","tz":"Europe/Paris","phone":"+33"},
    {"name":"Sweden","code":"SE","tld":".se","tz":"Europe/Stockholm","phone":"+46"},
]

JOBS = [
    "Software Engineer","Product Manager","Data Analyst","Security Researcher","DevOps Engineer",
    "IT Consultant","Network Administrator","Web Developer","Database Administrator","Systems Analyst",
    "Freelance Developer","Technical Writer","UX Designer","Cloud Architect","Penetration Tester",
]

EMAIL_PROVIDERS = ["gmail.com","protonmail.com","outlook.com","yahoo.com","tutanota.com",
                    "icloud.com","zoho.com","fastmail.com","pm.me","mail.com"]

INTERESTS = [
    "hiking","photography","cooking","gaming","reading","travel","music production","3D printing",
    "open source","machine learning","cybersecurity","amateur radio","astronomy","rock climbing",
    "coffee","vinyl records","cryptocurrency","urban exploration","lockpicking","electronics",
]

BACKSTORY_TEMPLATES = [
    "{first} grew up in {city} and studied computer science at {university}. After graduating in {grad_year}, "
    "they worked at several tech startups before going freelance. They enjoy {interest1} and {interest2} in their spare time.",

    "{first} is a {job} with {exp} years of experience. Originally from {country}, they relocated for work "
    "and now live in {city}. Known online for their posts about {interest1}.",

    "{first} {last} works remotely as a {job}. They maintain a low profile online, preferring {interest1} "
    "over social media. They have a side project related to {interest2} they work on weekends.",
]

CITIES = {
    "US": ["New York","San Francisco","Chicago","Austin","Seattle","Denver","Boston","Portland"],
    "GB": ["London","Manchester","Birmingham","Edinburgh","Bristol","Leeds","Liverpool"],
    "DE": ["Berlin","Munich","Hamburg","Frankfurt","Cologne","Stuttgart"],
    "CA": ["Toronto","Vancouver","Montreal","Calgary","Ottawa"],
    "AU": ["Sydney","Melbourne","Brisbane","Perth","Adelaide"],
    "NL": ["Amsterdam","Rotterdam","The Hague","Utrecht","Eindhoven"],
    "FR": ["Paris","Lyon","Marseille","Bordeaux","Toulouse"],
    "SE": ["Stockholm","Gothenburg","Malmo","Uppsala"],
}

UNIVERSITIES = {
    "US": ["MIT","Stanford","Carnegie Mellon","Georgia Tech","University of Washington"],
    "GB": ["University of Edinburgh","King's College London","University of Manchester","Imperial College"],
    "DE": ["TU Berlin","TU Munich","KIT","University of Hamburg"],
    "CA": ["University of Toronto","UBC","McGill","Waterloo"],
    "AU": ["University of Melbourne","University of Sydney","ANU","UNSW"],
    "NL": ["TU Delft","University of Amsterdam","Eindhoven University"],
    "FR": ["École Polytechnique","Paris-Saclay","Sorbonne University"],
    "SE": ["KTH","Chalmers","Uppsala University"],
}


def _weighted_username(first: str, last: str, birth_year: int, rng: random.Random) -> list[str]:
    f, l = first.lower(), last.lower()
    num = str(birth_year)[2:]
    variants = [
        f"{f}.{l}",
        f"{f}{l}",
        f"{f}_{l}",
        f"{f[0]}{l}",
        f"{f}{l}{num}",
        f"{f[0]}{l}{num}",
        f"{l}{f[0]}",
        f"{l}.{f[0]}{num}",
        f"{f}{rng.randint(10,999)}",
        f"_{f}{l}_",
    ]
    rng.shuffle(variants)
    return variants[:5]


def _generate_phone(country: dict, rng: random.Random) -> str:
    prefix = country["phone"]
    digits = "".join(str(rng.randint(0, 9)) for _ in range(9))
    return f"{prefix} {digits[:3]} {digits[3:6]} {digits[6:]}"


def _generate_persona(seed: str = "", gender: str = "random", country_code: str = "") -> dict[str, Any]:
    rng = random.Random(seed or os.urandom(16).hex())

    gender_choice = gender if gender in ("m", "f") else rng.choice(["m", "f"])
    first = rng.choice(FIRST_NAMES_M if gender_choice == "m" else FIRST_NAMES_F)
    last = rng.choice(LAST_NAMES)

    country = next((c for c in COUNTRIES if c["code"] == country_code.upper()), None) \
              or rng.choice(COUNTRIES)
    code = country["code"]

    birth_year = rng.randint(1975, 2000)
    birth_month = rng.randint(1, 12)
    birth_day = rng.randint(1, 28)
    age = datetime.datetime.now().year - birth_year

    city = rng.choice(CITIES.get(code, ["Unknown"]))
    university = rng.choice(UNIVERSITIES.get(code, ["State University"]))
    grad_year = birth_year + rng.randint(21, 24)
    job = rng.choice(JOBS)
    exp = rng.randint(3, age - 22) if age > 26 else 2
    interest1 = rng.choice(INTERESTS)
    interest2 = rng.choice([i for i in INTERESTS if i != interest1])

    usernames = _weighted_username(first, last, birth_year, rng)
    email_provider = rng.choice(EMAIL_PROVIDERS)
    primary_email = f"{usernames[0]}@{email_provider}"
    backup_email  = f"{first.lower()}.{last.lower()}{str(birth_year)[2:]}@{rng.choice(EMAIL_PROVIDERS)}"

    phone = _generate_phone(country, rng)

    # Backstory
    template = rng.choice(BACKSTORY_TEMPLATES)
    backstory = template.format(
        first=first, last=last, city=city, country=country["name"],
        university=university, grad_year=grad_year, job=job,
        interest1=interest1, interest2=interest2, exp=exp,
    )

    # Fingerprint hash
    fp_str = f"{first}{last}{birth_year}{country['code']}{city}"
    persona_id = hashlib.sha256(fp_str.encode()).hexdigest()[:12]

    return {
        "persona_id":   persona_id,
        "full_name":    f"{first} {last}",
        "first_name":   first,
        "last_name":    last,
        "gender":       "Male" if gender_choice == "m" else "Female",
        "date_of_birth":f"{birth_year}-{birth_month:02d}-{birth_day:02d}",
        "age":          age,
        "nationality":  country["name"],
        "country_code": code,
        "city":         city,
        "timezone":     country["tz"],
        "job_title":    job,
        "experience_yrs": exp,
        "university":   university,
        "grad_year":    grad_year,
        "usernames":    usernames,
        "primary_email":primary_email,
        "backup_email": backup_email,
        "phone":        phone,
        "interests":    [interest1, interest2],
        "backstory":    backstory,
        "seed":         seed or "random",
    }


def run(action: str = "new", seed: str = "", gender: str = "random",
        country: str = "", count: int = 1, export: bool = False):
    console.print(Panel(
        "[bold #ff2d78]🎭  OpSec Persona Builder[/bold #ff2d78]",
        box=box.ROUNDED
    ))

    personas = []
    for i in range(max(1, min(count, 10))):
        s = seed if count == 1 else f"{seed or 'omega'}-{i}"
        personas.append(_generate_persona(seed=s, gender=gender, country_code=country))

    for p in personas:
        console.print(Panel(
            f"[bold cyan]{p['full_name']}[/bold cyan]  "
            f"[dim]#{p['persona_id']}[/dim]",
            box=box.SIMPLE
        ))

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        t.add_column("Field", style="bold #ff2d78", width=18)
        t.add_column("Value", style="cyan")

        rows = [
            ("Gender",        p["gender"]),
            ("DOB",           f"{p['date_of_birth']} (age {p['age']})"),
            ("Location",      f"{p['city']}, {p['nationality']}"),
            ("Timezone",      p["timezone"]),
            ("Job",           f"{p['job_title']} ({p['experience_yrs']}y exp)"),
            ("University",    f"{p['university']} ({p['grad_year']})"),
            ("Phone",         p["phone"]),
            ("Primary Email", p["primary_email"]),
            ("Backup Email",  p["backup_email"]),
            ("Usernames",     " / ".join(p["usernames"][:3])),
            ("Interests",     " · ".join(p["interests"])),
        ]
        for field, val in rows:
            t.add_row(field, val)
        console.print(t)
        console.print(f"\n[italic dim]{p['backstory']}[/italic dim]\n")

    if export or count > 1:
        out_dir = os.path.expanduser("~/.omega/reports")
        os.makedirs(out_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out = os.path.join(out_dir, f"persona_{ts}.json")
        with open(out, "w") as f:
            json.dump(personas if count > 1 else personas[0], f, indent=2)
        console.print(f"[dim]Saved → {out}[/dim]")

    console.print("[dim]⚠  For authorized red team / OpSec use only. All data is fictitious.[/dim]")
