module.exports = {
  "hydra": [
    "intro",
    "pipeline",
    {
      "type": "category",
      "label": "Phase 1: Source Gathering",
      "items": ["phase-1-source-gathering"]
    },
    {
      "type": "category",
      "label": "Phase 2: Procedure Dataset",
      "items": ["phase-2-procedure-dataset"]
    },
    {
      "type": "category",
      "label": "Phase 3: OpenCTI",
      "items": ["phase-3-opencti"]
    },
    {
      "type": "category",
      "label": "Phase 4: Detection Atlas",
      "items": ["phase-4-detection-atlas"]
    },
    {
      "type": "category",
      "label": "Phase 5: Validation Lab",
      "items": ["phase-5-validation-lab", "phase-5-results"]
    },
    {
      "type": "category",
      "label": "Phase 6: Coverage Matrix",
      "items": ["phase-6-coverage-matrix"]
    },
    "for-defenders",
    "limitations",
    "reproduce",
    "production-scars"
  ]
};
