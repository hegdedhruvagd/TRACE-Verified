from trace_verified.corpus import generate_records


def test_corpus_is_repeatable_and_counted():
    assert generate_records(5, seed=12) == generate_records(5, seed=12)
    assert len(generate_records(3)) == 3
