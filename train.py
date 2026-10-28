"""Train and compare the detectors, then build the K-Means anomaly detector.   python train.py"""
import json
import os
import time
import warnings
from pathlib import Path

os.environ.setdefault("LOKY_MAX_CPU_COUNT", "4")

import joblib
import matplotlib
import numpy as np
from sklearn.cluster import KMeans
from sklearn.ensemble import AdaBoostClassifier, BaggingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier, export_text

from traffic import CLASSES, FEATURES, TRAIN_MIX, ZERO_DAY, log_scale, make_flows

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

warnings.filterwarnings("ignore")
ROOT = Path(__file__).resolve().parent
(ROOT / "models").mkdir(exist_ok=True)
(ROOT / "reports").mkdir(exist_ok=True)

rng = np.random.default_rng(42)
data = make_flows(24000, TRAIN_MIX, rng)
X, y = data[FEATURES], data["label"]
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
print(f"[data] {len(Xtr)} train / {len(Xte)} test flows, {len(FEATURES)} features, classes {CLASSES}")


def build():
    return {
        "Decision Tree": DecisionTreeClassifier(max_depth=8, random_state=0),
        "Bagging (50 trees)": BaggingClassifier(DecisionTreeClassifier(), n_estimators=50, random_state=0, n_jobs=-1),
        "AdaBoost (stumps)": AdaBoostClassifier(DecisionTreeClassifier(max_depth=1), n_estimators=200, random_state=0),
        "Random Forest": RandomForestClassifier(200, max_depth=14, n_jobs=-1, random_state=0),
        "Voting ensemble": VotingClassifier([
            ("rf", RandomForestClassifier(200, max_depth=14, n_jobs=-1, random_state=1)),
            ("ada", AdaBoostClassifier(DecisionTreeClassifier(max_depth=2), n_estimators=150, random_state=1)),
            ("bag", BaggingClassifier(DecisionTreeClassifier(), n_estimators=50, random_state=1, n_jobs=-1))],
            voting="soft"),
    }


def rates(true, pred):
    """Binary view: attack = anything that is not 'normal'."""
    true, pred = np.asarray(true), np.asarray(pred)
    att = true != "normal"
    return float((pred[att] != "normal").mean()), float((pred[~att] != "normal").mean())   # detection, false alarm


results, models = {}, build()
print(f"{'model':<20}{'accuracy':>9}{'macro F1':>10}{'detect':>8}{'false alarm':>13}{'fit s':>7}")
for name, m in models.items():
    t = time.time()
    m.fit(Xtr, ytr)
    fit = time.time() - t
    p = m.predict(Xte)
    det, fa = rates(yte, p)
    results[name] = dict(accuracy=accuracy_score(yte, p), macro_f1=f1_score(yte, p, average="macro"),
                         detection_rate=det, false_alarm_rate=fa, fit_seconds=fit)
    print(f"{name:<20}{results[name]['accuracy']:>9.3f}{results[name]['macro_f1']:>10.3f}{det:>8.3f}{fa:>13.3f}{fit:>7.1f}")

best_name = max(results, key=lambda k: results[k]["macro_f1"])
ens = models["Voting ensemble"]
pred = ens.predict(Xte)
cm = confusion_matrix(yte, pred, labels=CLASSES)
per_class = {c: float(cm[i, i] / cm[i].sum()) for i, c in enumerate(CLASSES)}
print("[ensemble] per-class recall:", {k: round(v, 3) for k, v in per_class.items()})

# ---- K-Means anomaly detector: learns only what NORMAL traffic looks like (unsupervised)
normal_tr = Xtr[ytr == "normal"]
scaler = StandardScaler().fit(log_scale(normal_tr))
km = KMeans(8, n_init=10, random_state=0).fit(scaler.transform(log_scale(normal_tr)))
dist = lambda df: km.transform(scaler.transform(log_scale(df))).min(axis=1)     # noqa: E731
threshold = float(np.quantile(dist(normal_tr), 0.995))
flag = lambda df: dist(df) > threshold                                           # noqa: E731

zd = make_flows(3000, {ZERO_DAY: 1}, np.random.default_rng(7))[FEATURES]
km_rows = {"normal (false alarm)": float(flag(Xte[yte == "normal"]).mean())}
km_rows.update({c: float(flag(Xte[yte == c]).mean()) for c in CLASSES[1:]})
km_rows[ZERO_DAY + " (zero-day)"] = float(flag(zd).mean())
ens_zd = float((ens.predict(zd) != "normal").mean())
combined_zd = float(((ens.predict(zd) != "normal") | flag(zd)).mean())
ens_fa = float((pred[yte.values == "normal"] != "normal").mean())
comb_fa = float(((ens.predict(Xte[yte == "normal"]) != "normal") | flag(Xte[yte == "normal"])).mean())
print("[kmeans] share of traffic flagged as anomalous:", {k: round(v, 3) for k, v in km_rows.items()})
print(f"[zero-day] botnet caught by ensemble {ens_zd:.1%} | K-Means {km_rows[ZERO_DAY + ' (zero-day)']:.1%} | "
      f"ensemble + K-Means {combined_zd:.1%}  (false alarms {ens_fa:.1%} -> {comb_fa:.1%})")

# ---- interpretability: top of the single decision tree
tree = models["Decision Tree"]
rules = export_text(tree, feature_names=FEATURES, max_depth=3)
(ROOT / "reports" / "tree_rules.txt").write_text(rules, encoding="utf-8")
rf = models["Random Forest"]
imp = sorted(zip(FEATURES, rf.feature_importances_), key=lambda t: -t[1])
print("[forest] top features:", ", ".join(f"{k} {v:.2f}" for k, v in imp[:6]))

joblib.dump({"model": ens, "scaler": scaler, "kmeans": km, "threshold": threshold, "features": FEATURES}, ROOT / "models" / "ids.joblib")
json.dump({"models": results, "per_class_recall": per_class, "kmeans_flagged": km_rows, "zero_day": {
    "ensemble": ens_zd, "kmeans": km_rows[ZERO_DAY + " (zero-day)"], "combined": combined_zd, "false_alarm_ensemble": ens_fa,
    "false_alarm_combined": comb_fa}, "top_features": imp[:10], "train_rows": len(Xtr), "test_rows": len(Xte)},
    open(ROOT / "reports" / "results.json", "w"), indent=2)

# ---- figure for the report
fig, ax = plt.subplots(2, 2, figsize=(12, 9))
im = ax[0, 0].imshow(cm / cm.sum(1, keepdims=True), cmap="Blues", vmin=0, vmax=1)
ax[0, 0].set_xticks(range(len(CLASSES)), CLASSES, rotation=35, ha="right")
ax[0, 0].set_yticks(range(len(CLASSES)), CLASSES)
for i in range(len(CLASSES)):
    for j in range(len(CLASSES)):
        ax[0, 0].text(j, i, cm[i, j], ha="center", va="center", color="white" if cm[i, j] / cm[i].sum() > .5 else "black", fontsize=9)
ax[0, 0].set_xlabel("predicted"); ax[0, 0].set_ylabel("actual"); ax[0, 0].set_title("Voting ensemble: confusion matrix (test set)")
names = list(results)
ax[0, 1].barh(names, [results[n]["macro_f1"] for n in names], color=["#4b8fd0"] * 4 + ["#15803d"])
ax[0, 1].set_xlim(0.6, 1); ax[0, 1].set_title("Macro F1 on the test set")
for i, n in enumerate(names):
    ax[0, 1].text(results[n]["macro_f1"] + .004, i, f"{results[n]['macro_f1']:.3f}", va="center", fontsize=9)
top = imp[:10][::-1]
ax[1, 0].barh([k for k, _ in top], [v for _, v in top], color="#b7791f"); ax[1, 0].set_title("Random Forest: top-10 feature importances")
bars = [("Ensemble", ens_zd), ("K-Means", km_rows[ZERO_DAY + " (zero-day)"]), ("Both", combined_zd)]
ax[1, 1].bar([b[0] for b in bars], [b[1] for b in bars], color=["#4b8fd0", "#b7791f", "#15803d"]); ax[1, 1].set_ylim(0, 1.05)
ax[1, 1].set_title("Unknown (zero-day) botnet traffic detected")
for i, (_, v) in enumerate(bars):
    ax[1, 1].text(i, v + .02, f"{v:.1%}", ha="center")
fig.tight_layout(); fig.savefig(ROOT / "reports" / "results.png", dpi=130)
print("[done] models/ids.joblib, reports/results.json, reports/results.png, reports/tree_rules.txt")
