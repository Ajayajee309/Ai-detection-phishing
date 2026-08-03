"""
=====================================================================
  AI-Based Phishing Attack Detection - Dataset Generator
  File: dataset/generate_dataset.py
  Description: Generates a synthetic phishing/legitimate URL dataset
               for training the ML model. In production, replace this
               with a real dataset (e.g., UCI Phishing Dataset).
=====================================================================
"""

import pandas as pd
import numpy as np
import random
import re
import os

# ─── Seed for reproducibility ─────────────────────────────────────
random.seed(42)
np.random.seed(42)

# ─── Sample URL pools ─────────────────────────────────────────────
LEGIT_DOMAINS = [
    "google.com", "amazon.com", "facebook.com", "microsoft.com",
    "apple.com", "twitter.com", "linkedin.com", "github.com",
    "wikipedia.org", "youtube.com", "netflix.com", "reddit.com",
    "stackoverflow.com", "medium.com", "nytimes.com", "bbc.com",
    "cnn.com", "forbes.com", "paypal.com", "ebay.com",
    "shopify.com", "stripe.com", "dropbox.com", "slack.com",
    "zoom.us", "adobe.com", "salesforce.com", "oracle.com"
]

PHISHING_PATTERNS = [
    "secure-{bank}-login.com",
    "paypal-verify-account-{rand}.com",
    "{bank}-update-billing.xyz",
    "account-suspended-{rand}.tk",
    "login-{rand}-secure.ml",
    "verify-{bank}-identity.gq",
    "amazon-prize-winner-{rand}.cf",
    "free-iphone-{rand}.top",
    "click-here-{rand}.info",
    "{bank}-security-alert.pw"
]

BANKS = ["paypal", "amazon", "apple", "google", "microsoft",
         "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc"]

LEGIT_PATHS = [
    "/", "/home", "/about", "/contact", "/products",
    "/services", "/blog", "/news", "/login", "/signup",
    "/help", "/support", "/faq", "/pricing", "/features"
]

PHISHING_PATHS = [
    "/verify-account", "/secure-login", "/update-billing",
    "/confirm-identity", "/reset-password-now",
    "/suspended-account-recover", "/win-prize-claim",
    "/free-gift-activate", "/?id=12345&ref=phish",
    "/account.php?cmd=login&session=abcdef"
]


def generate_legit_url():
    """Generate a realistic legitimate URL."""
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    use_https = random.random() > 0.1       # 90% use HTTPS
    protocol = "https" if use_https else "http"
    subdomain = random.choice(["", "www.", "app.", "api.", "mail."])
    return f"{protocol}://{subdomain}{domain}{path}"


def generate_phishing_url():
    """Generate a realistic phishing URL."""
    pattern = random.choice(PHISHING_PATTERNS)
    bank = random.choice(BANKS)
    rand_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6))
    domain = pattern.format(bank=bank, rand=rand_str)
    path = random.choice(PHISHING_PATHS)

    use_https = random.random() > 0.7       # Only 30% use HTTPS
    protocol = "https" if use_https else "http"

    # Add IP address occasionally (phishing trait)
    if random.random() < 0.15:
        ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        return f"{protocol}://{ip}{path}"

    # Add @ symbol occasionally (phishing trait)
    if random.random() < 0.1:
        return f"{protocol}://user@{domain}{path}"

    # Add extra subdomains occasionally
    if random.random() < 0.2:
        fake_legit = random.choice(["paypal", "amazon", "google", "apple"])
        return f"{protocol}://{fake_legit}.{domain}{path}"

    return f"{protocol}://{domain}{path}"


def create_dataset(n_legit=1500, n_phishing=1500):
    """Create and save the phishing dataset."""
    urls = []
    labels = []

    print(f"[INFO] Generating {n_legit} legitimate URLs...")
    for _ in range(n_legit):
        urls.append(generate_legit_url())
        labels.append(0)  # 0 = Legitimate

    print(f"[INFO] Generating {n_phishing} phishing URLs...")
    for _ in range(n_phishing):
        urls.append(generate_phishing_url())
        labels.append(1)  # 1 = Phishing

    df = pd.DataFrame({"url": urls, "label": labels})

    # Shuffle the dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Save
    os.makedirs("dataset", exist_ok=True)
    output_path = os.path.join("dataset", "phishing_dataset.csv")
    df.to_csv(output_path, index=False)
    print(f"[INFO] Dataset saved -> {output_path}")
    print(f"[INFO] Total samples: {len(df)} | Legit: {n_legit} | Phishing: {n_phishing}")
    # Set stdout encoding for Windows compatibility

    return df


if __name__ == "__main__":
    df = create_dataset()
    print(df.head(10))
    print(f"\nLabel distribution:\n{df['label'].value_counts()}")
