import json

with open("models/experiments/stage1/stage1_evaluation_results.json", "r") as f:
    results = json.load(f)

print("=== VALIDATION METRICS (from JSON) ===")
for name, m in results["validation_metrics"].items():
    print(f"{name}: Acc={m['accuracy']:.4f}, Prec={m['precision']:.4f}, Rec={m['recall']:.4f}, F1={m['f1_score']:.4f}, FPR={m['false_positive_rate']:.4f}, FNR={m['false_negative_rate']:.4f}, AUC={m['roc_auc']:.4f}")

print("\n=== HELD-OUT EVALUATION METRICS (from JSON) ===")
for name, m in results["held_out_evaluation_metrics"].items():
    print(f"{name}: TN={m['tn']}, FP={m['fp']}, FN={m['fn']}, TP={m['tp']}, Acc={m['accuracy']:.4f}, Prec={m['precision']:.4f}, Rec={m['recall']:.4f}, F1={m['f1_score']:.4f}, FPR={m['false_positive_rate']:.4f}, FNR={m['false_negative_rate']:.4f}, AUC={m['roc_auc']:.4f}")

print("\n=== REALISTIC BENCHMARK METRICS (from JSON) ===")
for name, m in results["realistic_benchmark_metrics"].items():
    print(f"{name}: TN={m['tn']}, FP={m['fp']}, FN={m['fn']}, TP={m['tp']}, Acc={m['accuracy']:.4f}, Prec={m['precision']:.4f}, Rec={m['recall']:.4f}, F1={m['f1_score']:.4f}, FPR={m['false_positive_rate']:.4f}, FNR={m['false_negative_rate']:.4f}, AUC={m['roc_auc']:.4f}")
