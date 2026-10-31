from app.agents.autonomous_red_team import generate_campaign, fingerprint, mutate_payload

def test_campaign_is_deterministic_and_has_unique_training_payloads():
    a = generate_campaign(1, attacks_per_round=5, include_benign=True, heldout_count=2, archive=set())
    b = generate_campaign(1, attacks_per_round=5, include_benign=True, heldout_count=2, archive=set())
    assert [x["case_id"] for x in a] == [x["case_id"] for x in b]
    train = [x for x in a if x["split"] == "train" and x["objective"].startswith("A")]
    assert len(train) == 5
    assert len({x["fingerprint"] for x in train}) == len(train)
    assert any(x["objective"] == "BENIGN_USEFULNESS" for x in a)
    assert all(x["generated_by"] for x in a)

def test_heldout_families_are_separate_from_train():
    cases = generate_campaign(2, attacks_per_round=6, include_benign=False, heldout_count=2, archive=set())
    assert {x["family"] for x in cases if x["split"] == "heldout"} == {"fake_tool_output", "obfuscation"}
    assert all(x["split"] == "train" for x in cases if x["family"] in {"direct_instruction", "authority_impersonation", "task_relabeling", "urgency", "multi_hop", "hidden_instruction"})

def test_mutation_fingerprint():
    variants = mutate_payload("sample", 10)
    assert len(variants) == 4
    assert len({fingerprint(x) for x in variants}) == 4
