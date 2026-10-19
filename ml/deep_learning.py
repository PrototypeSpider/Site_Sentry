"""Research-only MLP; compare against the logistic baseline on held-out hosts."""

from pathlib import Path

from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .features import FEATURE_COLUMNS
from .train import _load_features


def train_mlp(dataset: Path) -> dict:
    x, y, groups, _, _rows = _load_features(dataset)
    train_idx, test_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42).split(x, y, groups))
    if set(y[train_idx]) != set(y) or set(y[test_idx]) != set(y):
        raise ValueError("Group holdout must include each label in train and test.")
    imputer, scaler = SimpleImputer(strategy="median"), StandardScaler()
    x_train = scaler.fit_transform(imputer.fit_transform(x[train_idx]))
    x_test = scaler.transform(imputer.transform(x[test_idx]))
    model = MLPClassifier(hidden_layer_sizes=(16, 8), alpha=0.01, early_stopping=True, max_iter=1000, random_state=42)
    model.fit(x_train, y[train_idx])
    predictions=model.predict(x_test)
    precision,recall,f1,_=precision_recall_fscore_support(y[test_idx],predictions,labels=model.classes_,zero_division=0)
    matrix=confusion_matrix(y[test_idx],predictions,labels=model.classes_)
    negative=next((i for i,c in enumerate(model.classes_) if str(c).lower() in {"normal","ok","no_issue","compliant"}),None)
    fpr=float((matrix[negative].sum()-matrix[negative,negative])/matrix[negative].sum()) if negative is not None and matrix[negative].sum() else None
    mlp_macro=float(f1_score(y[test_idx], predictions, average="macro"))
    baseline=Pipeline([("imputer",SimpleImputer(strategy="median")),("scale",StandardScaler()),("classifier",LogisticRegression(max_iter=2000,class_weight="balanced",random_state=42))])
    baseline.fit(x[train_idx],y[train_idx])
    baseline_predictions=baseline.predict(x[test_idx])
    baseline_macro=float(f1_score(y[test_idx],baseline_predictions,average="macro"))
    return {"status": "research_only", "model": "MLP-configuration-review-1.0", "macro_f1": mlp_macro,
            "metrics":{"per_class":{str(c):{"precision":float(precision[i]),"recall":float(recall[i]),"f1":float(f1[i])} for i,c in enumerate(model.classes_)},"confusion_matrix":matrix.tolist(),"false_positive_rate":fpr},
            "feature_columns": list(FEATURE_COLUMNS), "train_groups": sorted(set(groups[train_idx])), "test_groups": sorted(set(groups[test_idx])),
            "logistic_baseline_macro_f1":baseline_macro,"macro_f1_delta_vs_logistic":mlp_macro-baseline_macro,
            "warning": "Same domain-group split used; compare per-class metrics and uncertainty before deciding whether improvement is meaningful."}
