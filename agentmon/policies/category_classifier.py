"""Fast heuristic domain categorization.

Classifies domains into categories based on substring patterns.
No LLM required - designed for low-latency inline classification.
"""

CATEGORY_PATTERNS: dict[str, list[str]] = {
    "games": [
        "roblox",
        "fortnite",
        "minecraft",
        "steam",
        "epicgames",
        "playstation",
        "xbox",
        "nintendo",
        "itch.io",
        "gog.com",
        "origin.com",
        "battle.net",
        "blizzard",
        "ea.com",
        "ubisoft",
        "activision",
        "riot",
        "leagueoflegends",
        "valorant",
        "dota2",
        "csgo",
        "overwolf",
    ],
    "social_media": [
        "tiktok",
        "instagram",
        "twitter",
        "x.com",
        "facebook",
        "snapchat",
        "discord",
        "reddit",
        "tumblr",
        "pinterest",
        "linkedin",
        "threads.net",
        "mastodon",
        "bsky.app",
        "bluesky",
        "whatsapp",
        "telegram",
        "signal",
        "wechat",
        "weibo",
    ],
    "ai_tools": [
        "chatgpt",
        "openai",
        "claude",
        "anthropic",
        "copilot",
        "gemini",
        "perplexity",
        "bard.google",
        "character.ai",
        "replika",
        "jasper.ai",
        "writesonic",
        "copy.ai",
        "midjourney",
        "stability.ai",
        "huggingface",
        "poe.com",
    ],
    "video": [
        "youtube",
        "netflix",
        "twitch",
        "hulu",
        "disneyplus",
        "disney+",
        "hbomax",
        "max.com",
        "primevideo",
        "amazon.com/gp/video",
        "peacock",
        "paramount+",
        "paramountplus",
        "crunchyroll",
        "funimation",
        "vimeo",
        "dailymotion",
        "tubi",
        "pluto.tv",
        "roku",
    ],
    "educational": [
        "wikipedia",
        "khanacademy",
        "coursera",
        "edx.org",
        "quizlet",
        "britannica",
        "duolingo",
        "brainly",
        "chegg",
        "studycom",
        "sparknotes",
        "cliffsnotes",
        "wolframalpha",
        "mathway",
        "photomath",
        "symbolab",
        "desmos",
        "geogebra",
        "scratch.mit.edu",
        "codecademy",
        "freecodecamp",
    ],
    "shopping": [
        "amazon.com",
        "ebay",
        "etsy",
        "walmart",
        "target.com",
        "bestbuy",
        "aliexpress",
        "wish.com",
        "shein",
        "temu",
    ],
    "news": [
        "cnn.com",
        "bbc.com",
        "nytimes",
        "washingtonpost",
        "theguardian",
        "reuters",
        "apnews",
        "foxnews",
        "msnbc",
        "npr.org",
    ],
}


def classify_domain(domain: str) -> str:
    """Classify a domain into a category based on pattern matching.

    Args:
        domain: The domain name to classify (e.g., "www.youtube.com")

    Returns:
        Category name (e.g., "video") or "unknown" if no match
    """
    domain_lower = domain.lower()

    for category, patterns in CATEGORY_PATTERNS.items():
        for pattern in patterns:
            if pattern in domain_lower:
                return category

    return "unknown"


def get_all_categories() -> list[str]:
    """Return list of all known categories."""
    return list(CATEGORY_PATTERNS.keys())
