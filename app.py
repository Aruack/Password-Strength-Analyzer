from flask import Flask, render_template, request, jsonify, send_file
import string
import io
import math
import hashlib
import requests as http_requests
import matplotlib
matplotlib.use("Agg")          # non-interactive backend (no GUI window)
import matplotlib.pyplot as plt

app = Flask(__name__)

# Curated list of most commonly used passwords worldwide (SecLists / NIST)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "12345", "12345678", "111111", "1234567",
    "dragon", "123123", "baseball", "football", "shadow", "master", "monkey", "superman",
    "welcome", "admin", "admin123", "password123", "pass1234", "letmein", "sunshine", "princess",
    "iloveyou", "trustno1", "starwars", "charlie", "killer", "login", "solo", "computer",
    "jordan", "michael", "harley", "robert", "thomas", "daniel", "michelle", "andrew",
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "abc12345", "abc123", "test123", "guest", "root",
    "secret", "p@ssword", "p@ssw0rd", "admin@123", "password1", "pass123"
}

TOP_COMMON_EXAMPLES = [
    "123456", "password", "123456789", "qwerty", "admin",
    "welcome", "iloveyou", "12345678", "password123", "pass1234"
]


def analyze_password(password):
    score = 0
    suggestions = []
    is_common = password.lower().strip() in COMMON_PASSWORDS

    # Check password length
    if len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 8 characters.")

    # Check uppercase letter
    if any(char.isupper() for char in password):
        score += 1
    else:
        suggestions.append("Add at least one uppercase letter (A-Z).")

    # Check lowercase letter
    if any(char.islower() for char in password):
        score += 1
    else:
        suggestions.append("Add at least one lowercase letter (a-z).")

    # Check number
    if any(char.isdigit() for char in password):
        score += 1
    else:
        suggestions.append("Add at least one number (0-9).")

    # Check special character
    if any(char in string.punctuation for char in password):
        score += 1
    else:
        suggestions.append("Add at least one special character (@, #, $, %, etc.).")

    # Penalize common passwords
    if is_common:
        score = min(score, 1)
        suggestions.insert(0, "CRITICAL: This is an extremely common, easily guessed password. Avoid dictionary words and common sequences.")

    # Decide password strength
    if score <= 1:
        strength = "VERY WEAK"
    elif score == 2:
        strength = "WEAK"
    elif score == 3:
        strength = "MEDIUM"
    elif score == 4:
        strength = "STRONG"
    else:
        strength = "VERY STRONG"

    return score, strength, suggestions, is_common


def calculate_entropy_and_crack_time(password):
    """Calculates information entropy (bits) and realistic offline brute-force crack time."""
    if not password:
        return 0, "Instant"

    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)

    if pool == 0:
        pool = 128  # fallback

    entropy = round(len(password) * math.log2(pool), 1)

    # Brute force attack speed: 10 billion hashes/sec (standard GPU rig)
    combinations = 2 ** entropy
    seconds = combinations / 10_000_000_000

    if seconds < 1:
        crack_time = "Instant"
    elif seconds < 60:
        crack_time = f"{max(1, int(seconds))}s"
    elif seconds < 3600:
        crack_time = f"{int(seconds // 60)} mins"
    elif seconds < 86400:
        crack_time = f"{int(seconds // 3600)} hours"
    elif seconds < 31536000:
        crack_time = f"{int(seconds // 86400)} days"
    elif seconds < 31536000 * 1000:
        years = int(seconds // 31536000)
        crack_time = f"{years:,} years"
    else:
        crack_time = "Centuries"

    return entropy, crack_time


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Password cannot be empty."}), 400

    score, strength, suggestions, is_common = analyze_password(password)
    entropy, crack_time = calculate_entropy_and_crack_time(password)

    checks = {
        "length":    len(password) >= 8,
        "uppercase": any(c.isupper() for c in password),
        "lowercase": any(c.islower() for c in password),
        "digit":     any(c.isdigit() for c in password),
        "special":   any(c in string.punctuation for c in password),
    }

    return jsonify({
        "score":       score,
        "strength":    strength,
        "suggestions": suggestions,
        "length":      len(password),
        "entropy":     entropy,
        "crack_time":  crack_time,
        "checks":      checks,
        "is_common":   is_common,
        "common_samples": TOP_COMMON_EXAMPLES,
    })


def check_breach(password):
    """
    Check if a password has been exposed in known data breaches
    using the Have I Been Pwned k-anonymity API.
    The full password is NEVER sent — only the first 5 chars of its SHA-1 hash.
    Returns: (pwned: bool, count: int)
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = http_requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5,
            headers={"Add-Padding": "true"}
        )
        response.raise_for_status()
    except Exception:
        return None, 0   # API unreachable — return unknown state

    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return True, int(count)

    return False, 0


@app.route("/breach", methods=["POST"])
def breach():
    """Endpoint to check if a password appears in breach databases."""
    data     = request.get_json()
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Password cannot be empty."}), 400

    pwned, count = check_breach(password)

    if pwned is None:
        return jsonify({"status": "unknown", "count": 0,
                        "message": "Could not reach breach database. Check your internet connection."})
    elif pwned:
        return jsonify({"status": "leaked", "count": count,
                        "message": f"⚠️ This password has been found in {count:,} data breaches! Change it immediately."})
    else:
        return jsonify({"status": "safe", "count": 0,
                        "message": "✅ This password was not found in any known breach database."})


@app.route("/chart", methods=["POST"])
def chart():
    """Generate a matplotlib bar chart for the password criteria and return it as PNG."""
    data     = request.get_json()
    password = data.get("password", "")

    checks = {
        "Length\n(≥8 chars)":   int(len(password) >= 8),
        "Uppercase\n(A-Z)":     int(any(c.isupper() for c in password)),
        "Lowercase\n(a-z)":     int(any(c.islower() for c in password)),
        "Digit\n(0-9)":         int(any(c.isdigit() for c in password)),
        "Special\n(@#$…)":      int(any(c in string.punctuation for c in password)),
    }

    score    = sum(checks.values())
    labels   = list(checks.keys())
    values   = list(checks.values())

    # ── Color per bar ──
    bar_colors = ["#10b981" if v else "#f43f5e" for v in values]

    # ── Strength color for title ──
    strength_color = {0: "#f43f5e", 1: "#f43f5e", 2: "#f97316",
                      3: "#f59e0b", 4: "#10b981", 5: "#8b5cf6"}.get(score, "#94a3b8")

    strength_label = {0: "VERY WEAK", 1: "VERY WEAK", 2: "WEAK",
                      3: "MEDIUM",    4: "STRONG",    5: "VERY STRONG"}.get(score, "—")

    # ── Plot ──
    fig, ax = plt.subplots(figsize=(6.2, 3.2))
    fig.patch.set_facecolor("#0b1120")
    ax.set_facecolor("#0b1120")

    bars = ax.bar(labels, values, color=bar_colors, edgecolor="none",
                  width=0.45, zorder=3, alpha=0.9)

    # Value labels on bars
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.05,
                "PASSED" if val else "FAILED",
                ha="center", va="bottom",
                fontsize=8, fontweight="bold",
                color="#10b981" if val else "#f43f5e")

    ax.set_ylim(0, 1.45)
    ax.set_yticks([])
    ax.tick_params(colors="#94a3b8", labelsize=8.5)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.xaxis.label.set_color("#64748b")

    # Subtle horizontal line
    ax.axhline(1, color="#1e293b", linestyle="--", linewidth=0.8, zorder=1)

    # Title
    ax.set_title(
        f"CRITERIA COMPLIANCE AUDIT  ·  {strength_label} ({score}/5)",
        color=strength_color, fontsize=10.5, fontweight="bold", pad=12,
        letterspacing=1.0
    )

    # Tick label color
    ax.tick_params(axis="x", colors="#94a3b8")

    plt.tight_layout()

    # ── Render to PNG in memory ──
    buf = io.BytesIO()
    plt.savefig(buf, format="png", dpi=120, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)

    return send_file(buf, mimetype="image/png")


if __name__ == "__main__":
    app.run(debug=True)
