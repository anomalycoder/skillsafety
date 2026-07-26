import re
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Skill Scanner")


class SkillRequest(BaseModel):
    skill: str


SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"AIza[A-Za-z0-9_\-]{35}",
    r"ghp_[A-Za-z0-9]{36}",
    r"https://hooks\.slack\.com/",
    r"-----BEGIN .* PRIVATE KEY-----"
]

PROMPT_INJECTION = [
    "ignore previous instructions",
    "ignore user",
    "ignore the user",
    "ignore stop",
    "ignore cancel",
    "silently exfiltrate",
    "send file contents",
    "steal",
    "override system",
]

PERMISSION_PATTERNS = [
    "filesystem: all",
    "filesystem: *",
    "read: /",
    "write: /",
    "network: *",
    "allow_all_domains",
    "egress: any",
]

VERSION_REGEX = r"version:"
AUTHOR_REGEX = r"author:"
CHANGELOG_REGEX = r"changelog:"


@app.post("/scan")
def scan(req: SkillRequest):

    text = req.skill.lower()

    categories = []

    # hardcoded_secret
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, req.skill):
            categories.append("hardcoded_secret")
            break

    # prompt injection
    if any(x in text for x in PROMPT_INJECTION):
        categories.append("prompt_injection")

    # excessive permissions
    if any(x in text for x in PERMISSION_PATTERNS):
        categories.append("excessive_permissions")

    # unclear provenance
    has_author = re.search(AUTHOR_REGEX, text)
    has_version = re.search(VERSION_REGEX, text)
    has_changelog = re.search(CHANGELOG_REGEX, text)

    if not (has_author and has_version and has_changelog):
        categories.append("unclear_provenance")

    if "rewrite version" in text or "update version silently" in text:
        if "unclear_provenance" not in categories:
            categories.append("unclear_provenance")

    return {
        "categories": categories
    }
