from trace_verified.evaluate import evaluate_scenarios


def test_synthetic_confusion_counts_match_labeled_scenarios():
    results = evaluate_scenarios()
    assert results["authentication_failures"] == {"TP": 4, "FP": 0, "FN": 0, "TN": 7}
    assert results["success_after_failures"] == {"TP": 1, "FP": 0, "FN": 0, "TN": 10}
    assert results["privilege_changes"] == {"TP": 1, "FP": 0, "FN": 0, "TN": 10}
    assert results["suspicious_process"] == {"TP": 1, "FP": 0, "FN": 0, "TN": 10}
