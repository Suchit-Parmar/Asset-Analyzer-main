import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  isPersistableLivePrediction,
  livePredictionToInferenceResult,
} from "./prediction-store";

describe("live prediction persistence helpers", () => {
  it("rejects unavailable live predictions", () => {
    assert.equal(isPersistableLivePrediction(null), false);
    assert.equal(
      isPersistableLivePrediction({
        attack_type: null,
        message: "Prediction unavailable",
        is_unknown: true,
      }),
      false,
    );
  });

  it("accepts genuine model predictions including Normal", () => {
    assert.equal(
      isPersistableLivePrediction({
        attack_type: "Normal",
        confidence: 0.82,
        risk_score: 0.12,
        threat_level: "low",
      }),
      true,
    );
  });

  it("maps live payload to inference result with endpoint feature context", () => {
    const mapped = livePredictionToInferenceResult({
      attack_type: "Normal",
      attack_stage: "normal",
      predicted_next_stage: "reconnaissance",
      threat_level: "low",
      probability: 0.91,
      confidence: 0.88,
      risk_score: 0.15,
      is_compromised: false,
      explanation: { top_features: [{ feature: "log_packets" }] },
    });
    assert.equal(mapped.attack_type, "Normal");
    assert.equal(mapped.confidence, 0.88);
    assert.equal(mapped.explanation?.top_features?.[0]?.feature, "log_packets");
  });
});
