"""
PhishGuard - Model Training Script
Trains a Random Forest classifier on a synthetic dataset of phishing and legitimate URLs.
Run this script once to generate the model file: phishguard_model.pkl
"""

import os
import random
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from url_features import extract_features, features_to_vector

# ─── Seed for reproducibility ─────────────────────────────────────────────────
random.seed(42)
np.random.seed(42)

# ─── Sample URL datasets ───────────────────────────────────────────────────────
LEGIT_URLS = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.facebook.com",
    "https://www.amazon.com",
    "https://www.wikipedia.org",
    "https://www.twitter.com",
    "https://www.instagram.com",
    "https://www.linkedin.com",
    "https://www.reddit.com",
    "https://www.netflix.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.github.com",
    "https://www.stackoverflow.com",
    "https://www.nytimes.com",
    "https://www.bbc.co.uk",
    "https://www.cnn.com",
    "https://www.espn.com",
    "https://www.weather.com",
    "https://www.dropbox.com",
    "https://www.spotify.com",
    "https://www.twitch.tv",
    "https://www.paypal.com",
    "https://www.ebay.com",
    "https://www.adobe.com",
    "https://www.salesforce.com",
    "https://www.shopify.com",
    "https://www.wordpress.com",
    "https://www.medium.com",
    "https://www.quora.com",
    "https://mail.google.com/mail/u/0/",
    "https://docs.google.com/document/d/1abc",
    "https://drive.google.com/file/d/xyz",
    "https://accounts.google.com/signin",
    "https://www.chase.com/personal/banking",
    "https://online.citi.com/US/login.do",
    "https://www.wellsfargo.com/",
    "https://secure.bankofamerica.com/login",
    "https://www.discover.com/credit-cards",
    "https://www.capitalone.com/",
    "https://investor.apple.com/news-events",
    "https://support.microsoft.com/en-us",
    "https://developer.mozilla.org/en-US/",
    "https://docs.python.org/3/",
    "https://pytorch.org/docs/stable/",
    "https://scikit-learn.org/stable/",
    "https://numpy.org/doc/stable/",
    "https://pandas.pydata.org/docs/",
    "https://flask.palletsprojects.com/",
    "https://fastapi.tiangolo.com/",
    "https://www.healthline.com/nutrition",
    "https://www.webmd.com/diet/features",
    "https://www.mayoclinic.org/diseases",
    "https://store.steampowered.com/app",
    "https://www.imdb.com/title/tt1234567",
    "https://www.yelp.com/biz/starbucks",
    "https://www.tripadvisor.com/Hotel",
    "https://www.booking.com/hotel",
    "https://www.airbnb.com/rooms/1234",
    "https://www.uber.com/us/en/ride/",
    "https://www.lyft.com/rider/",
    "https://play.google.com/store/apps",
    "https://apps.apple.com/us/app/",
    "https://www.coursera.org/learn/",
    "https://www.udemy.com/course/",
    "https://www.khanacademy.org/math",
    "https://www.duolingo.com/course/",
    "https://www.zoom.us/j/123456",
    "https://teams.microsoft.com/l/channel",
    "https://slack.com/app_redirect",
    "https://trello.com/b/xyz/board",
    "https://notion.so/workspace/page",
    "https://airtable.com/appXYZ/tblABC",
    "https://www.figma.com/file/abc123",
    "https://codepen.io/user/pen/abc",
    "https://jsfiddle.net/user/abc123",
    "https://replit.com/@user/project",
    "https://colab.research.google.com/drive/",
    "https://huggingface.co/models",
    "https://kaggle.com/datasets",
    "https://www.nytimes.com/2024/01/tech",
    "https://techcrunch.com/2024/01/15/",
    "https://www.theverge.com/tech/2024",
    "https://arstechnica.com/science/",
    "https://www.wired.com/story/ai-safety",
    "https://www.forbes.com/sites/tech",
    "https://hbr.org/2024/01/leadership",
    "https://www.wsj.com/articles/finance",
    "https://www.economist.com/finance",
    "https://www.bloomberg.com/markets",
    "https://finance.yahoo.com/quote/AAPL",
    "https://www.investopedia.com/terms",
    "https://www.coinbase.com/price/bitcoin",
    "https://www.binance.com/en/trade",
    "https://etrade.com/trading/stocks",
    "https://robinhood.com/stocks/TSLA",
    "https://www.fidelity.com/accounts",
    "https://www.schwab.com/trading",
    "https://www.vanguard.com/funds",
]

PHISHING_URLS = [
    "http://192.168.1.1/login/paypal/verify",
    "http://paypal-secure-login.xyz/verify?user=victim",
    "http://www.paypal.com.evil.tk/login",
    "http://amazon-account-verify.ml/signin",
    "http://secure-amazon-update.ga/account",
    "http://microsoft-alert-suspicious.cf/verify",
    "http://apple-id-locked-verify.gq/unlock",
    "http://netflix-billing-update.pw/payment",
    "http://google-account-unusual-activity.cc/verify",
    "http://chase-bank-secure.top/login?redirect=true",
    "http://login-wellsfargo-verify.work/account",
    "http://citibank-update-credentials.click/signin",
    "http://bankofamerica-secure-login.xyz/verify",
    "http://capitalone-account-alert.ml/login",
    "http://discover-card-verify.ga/account/update",
    "http://www.paypal.com.phish.cc/webscr?cmd=login",
    "http://secure-paypal-verify-account.pw/cmd",
    "http://ebay-account-suspended.tk/verify",
    "http://apple-icloud-verify.work/signin",
    "http://dropbox-shared-document.xyz/view",
    "http://linkedln-professional-update.ml/login",
    "http://twitter-account-limited.ga/verify",
    "http://facebook-security-update.cf/login",
    "http://instagram-account-verify.gq/recover",
    "http://whatsapp-activation-update.pw/code",
    "http://dhl-package-delivery-update.cc/track",
    "http://fedex-shipment-delivery-notice.top/update",
    "http://usps-package-failed-delivery.work/reship",
    "http://irs-tax-refund-claim.click/refund",
    "http://coinbase-wallet-verify.xyz/login",
    "http://binance-account-security.ml/verify",
    "http://bit.ly/free-prize-winner-claim",
    "http://tinyurl.com/urgent-account-suspended",
    "http://goo.gl/bank-verify-now",
    "http://t.co/limited-offer-click-here",
    "http://paypal-support-login.com-secure.ml/",
    "http://amazon.com.customer-support-verify.xyz/",
    "http://microsoft.com.account-verify.ga/login",
    "http://apple.com.id-confirm-locked.cf/unlock",
    "http://google.com.account-recovery.gq/verify",
    "http://www-paypal-com.tk/myaccount/summary",
    "http://paypal-com-signin.pw/en/signin",
    "http://signin-amazon-secure.cc/ap/signin",
    "http://update-netflix-billing.top/update",
    "http://verify-your-bank-account.work/login",
    "http://account-suspended-click-here.click/verify",
    "http://192.168.0.1/phishing/bank/login.php",
    "http://10.0.0.1/admin/paypal_verify.php",
    "http://172.16.0.1/secure/bank/login",
    "http://203.0.113.1/gmail/login.html",
    "http://secure-login-paypal@evil.com/webscr",
    "http://amazon-login@phisher.tk/signin",
    "http://microsoft@update-security.ml/login",
    "http://free-bitcoin-prize.xyz/claim?winner=you",
    "http://you-won-100000-dollars.ml/collect",
    "http://urgent-account-verify-now.ga/critical",
    "http://password-reset-required.cf/update",
    "http://credential-update-bank.gq/secure",
    "http://suspicious-activity-alert.pw/verify",
    "http://unusual-login-detected.cc/confirm",
    "http://click-here-winner-free-gift.top/claim",
    "http://limited-time-offer-apple.work/buy",
    "http://act-now-account-suspended.click/restore",
    "http://paypal-verify.suspiciouslogin.com/cmd",
    "http://amazon.accountupdate.phishsite.com/login",
    "http://microsoft.securityalert.badsite.tk/verify",
    "http://signin-apple.id-locked.phish.ml/unlock",
    "http://google.accounts.fakesite.ga/signin",
    "http://www.paypal.secure.update.xyz/webscr",
    "http://login.bank.suspicious.cf/account",
    "http://secure.amazon.phishing.gq/signin",
    "http://account.netflix.fakepage.pw/billing",
    "http://my.ebay.com.phisherdomain.cc/sign",
    "http://paypal-secure-update.com/webscr?cmd=_login-submit",
    "http://amazon-prime-renewal-click.com/account?verify=1",
    "http://microsoft-office365-password-expiry.com/reset",
    "http://apple-icloud-account-locked.com/verify?id=abc123",
    "http://netflix-payment-failed-update.com/billing?retry=1",
    "http://chase-online-banking-verify.com/login?redirect=true",
    "http://google-account-suspicious-activity.com/verify",
    "http://facebook-security-checkpoint.com/login",
    "http://instagram-account-disabled.com/appeal",
    "http://twitter-account-restricted.com/confirm",
    "http://dropbox-document-shared-secure.com/view?id=xyz",
    "http://linkedin-profile-view-alert.com/notification",
    "http://coinbase-wallet-suspended.com/verify?user=victim",
    "http://binance-security-alert.com/login?urgent=1",
    "http://irs-stimulus-check-claim.com/verify",
    "http://usps-delivery-failed-reschedule.com/track?id=abc",
    "http://fedex-package-on-hold.com/update?tracking=xyz",
    "http://dhl-express-customs-fee.com/pay?amount=12",
    "http://paypal.com%2flogin%2f@phishing.xyz/webscr",
    "http://amazon.com%40verify.phish.ml/signin",
    "http://free-netflix-premium.xyz/get-access",
    "http://win-free-iphone14.ml/claim-prize",
    "http://bitcoin-double-your-money.ga/invest",
    "http://free-robux-generator.cf/generate",
    "http://steam-gift-card-free.gq/redeem",
    "http://paypal-money-transfer-verify.work/send",
    "http://bank-account-unlock-now.click/urgent",
    "http://credit-card-stolen-alert.cc/freeze",
    "http://social-security-suspended.pw/verify",
    "http://medicare-benefits-expired.top/renew",
]

def build_dataset():
    """Build training dataset from URL lists."""
    X, y = [], []

    # Legitimate URLs (label=0)
    for url in LEGIT_URLS:
        try:
            feat = extract_features(url)
            X.append(features_to_vector(feat))
            y.append(0)
        except Exception as e:
            print(f"[WARN] Skipping legit URL: {url} — {e}")

    # Augment legitimate by slight variations
    for url in LEGIT_URLS[:50]:
        variations = [
            url + "/home",
            url + "/about",
            url + "/search?q=test",
            url.replace("https://", "https://www.") if "www." not in url else url,
        ]
        for v in variations:
            try:
                feat = extract_features(v)
                X.append(features_to_vector(feat))
                y.append(0)
            except Exception:
                pass

    # Phishing URLs (label=1)
    for url in PHISHING_URLS:
        try:
            feat = extract_features(url)
            X.append(features_to_vector(feat))
            y.append(1)
        except Exception as e:
            print(f"[WARN] Skipping phishing URL: {url} — {e}")

    # Augment phishing
    phish_extras = [
        "http://secure-{brand}-login.xyz/verify".format(brand=b)
        for b in ["paypal", "amazon", "google", "microsoft", "apple", "bank", "netflix"]
    ]
    phish_extras += [
        "http://192.168.{a}.{b}/login.php".format(a=random.randint(0, 255), b=random.randint(1, 254))
        for _ in range(20)
    ]
    phish_extras += [
        "http://bit.ly/{code}".format(code=''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=7)))
        for _ in range(20)
    ]

    for url in phish_extras:
        try:
            feat = extract_features(url)
            X.append(features_to_vector(feat))
            y.append(1)
        except Exception:
            pass

    return np.array(X, dtype=float), np.array(y, dtype=int)


def train_and_save():
    print("=" * 60)
    print("  PhishGuard - Model Training")
    print("=" * 60)

    print("\n[1/4] Building dataset...")
    X, y = build_dataset()
    print(f"      Total samples: {len(X)}  (legit={sum(y==0)}, phish={sum(y==1)})")

    print("\n[2/4] Splitting train/test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"      Train: {len(X_train)}  |  Test: {len(X_test)}")

    print("\n[3/4] Training Random Forest classifier...")
    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        max_features="sqrt",
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    print("\n[4/4] Evaluating model...")
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n  Accuracy: {acc:.4f} ({acc*100:.2f}%)\n")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    model_path = os.path.join(os.path.dirname(__file__), "phishguard_model.pkl")
    joblib.dump(clf, model_path)
    print(f"\n[OK] Model saved to: {model_path}")
    print("=" * 60)


if __name__ == "__main__":
    train_and_save()
