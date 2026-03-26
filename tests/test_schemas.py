from src.llm.schemas import (
    StepAnnotation, GapStep, VerdictOutput, VerdictOutputBatch,
    DataflowResult, DataflowBatch,
)


def test_step_annotation_parses():
    sa = StepAnnotation(step_index=1, explanation="User input enters here")
    assert sa.step_index == 1
    assert sa.explanation == "User input enters here"


def test_gap_step_parses():
    gs = GapStep(label="propagation", location="utils.py:10", code="transform(x)", explanation="Cross-file call", after_step=2)
    assert gs.after_step == 2
    assert gs.label == "propagation"


def test_verdict_output_with_annotations():
    v = VerdictOutput(
        finding_index=1, reasoning="Vulnerable.", dataflow_analysis="Data flows.",
        step_annotations=[StepAnnotation(step_index=1, explanation="Source")],
        gap_steps=[GapStep(label="propagation", location="x.py:5", code="f()", explanation="gap", after_step=1)],
        flow_steps=[], verdict="true_positive", confidence=0.9,
    )
    assert len(v.step_annotations) == 1
    assert len(v.gap_steps) == 1


def test_verdict_output_defaults_empty_annotations():
    v = VerdictOutput(finding_index=1, reasoning="x", dataflow_analysis="x", verdict="uncertain", confidence=0.5)
    assert v.step_annotations == []
    assert v.gap_steps == []
    assert v.flow_steps == []


def test_dataflow_result_with_annotations():
    dr = DataflowResult(
        finding_index=1, dataflow_analysis="Flow traced.",
        step_annotations=[StepAnnotation(step_index=1, explanation="Source")],
        gap_steps=[], flow_steps=[], flow_complete=True,
    )
    assert len(dr.step_annotations) == 1


def test_verdict_output_batch_round_trip():
    batch = VerdictOutputBatch(verdicts=[
        VerdictOutput(
            finding_index=1, reasoning="x", dataflow_analysis="x",
            step_annotations=[StepAnnotation(step_index=1, explanation="y")],
            gap_steps=[], flow_steps=[], verdict="false_positive", confidence=0.85,
        ),
    ])
    d = batch.model_dump()
    restored = VerdictOutputBatch.model_validate(d)
    assert restored.verdicts[0].step_annotations[0].explanation == "y"
