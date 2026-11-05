"""The chunk capture goldens follow the worker's capture (chunk_capture_goldens.py --check):
a change of the worker's chunks, or of pycti's mutations, must regenerate them, since the
platform's worker-less intake is tested against them."""

from chunk_capture_goldens import main


def test_chunk_capture_goldens_are_up_to_date():
    assert main(check=True) == 0
