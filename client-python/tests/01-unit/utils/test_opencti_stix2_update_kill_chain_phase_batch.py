from pycti.utils.opencti_stix2_update import (
    KILL_CHAIN_PHASE_PREFETCH_BATCH_SIZE,
    OpenCTIStix2Update,
)


class _KillChainPhase:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return {"id": f"kill-chain-phase--{len(self.calls) - 1}"}


class _PrefetchingKillChainPhase:
    def __init__(self):
        self.list_filters = []
        self.list_first = []
        self.create_calls = []

    @staticmethod
    def generate_id(phase_name, kill_chain_name):
        return f"kill-chain-phase--{kill_chain_name}|{phase_name}"

    def list(self, **kwargs):
        ids = kwargs["filters"]["filters"][0]["values"]
        self.list_filters.append(ids)
        self.list_first.append(kwargs["first"])
        return [
            {
                "id": f"internal--{standard_id}",
                "standard_id": standard_id,
                "kill_chain_name": standard_id.removeprefix("kill-chain-phase--").split(
                    "|", 1
                )[0],
                "phase_name": standard_id.removeprefix("kill-chain-phase--").split(
                    "|", 1
                )[1],
                "x_opencti_order": 0,
            }
            for standard_id in ids
        ]

    def create(self, **kwargs):
        self.create_calls.append(kwargs)
        standard_id = self.generate_id(kwargs["phase_name"], kwargs["kill_chain_name"])
        return {"id": f"internal--{standard_id}"}


class _RelationAdder:
    def __init__(self):
        self.calls = []

    def add_kill_chain_phase(self, id, kill_chain_phase_id):
        self.calls.append((id, kill_chain_phase_id))
        return True


class _NestedRefRelationship:
    def __init__(self):
        self.object_calls = []
        self.relationship_calls = []

    def add_many_to_stix_core_object(self, from_id, to_ids, relationship_type):
        self.object_calls.append((from_id, list(to_ids), relationship_type))
        return True

    def add_many_to_stix_core_relationship(self, from_id, to_ids, relationship_type):
        self.relationship_calls.append((from_id, list(to_ids), relationship_type))
        return True


class _OpenCTI:
    def __init__(self, with_bulk=True):
        self.kill_chain_phase = _KillChainPhase()
        self.stix_domain_object = _RelationAdder()
        self.stix_cyber_observable = _RelationAdder()
        self.stix_core_relationship = _RelationAdder()
        if with_bulk:
            self.stix_nested_ref_relationship = _NestedRefRelationship()


class _PrefetchOpenCTI(_OpenCTI):
    def __init__(self):
        super().__init__()
        self.kill_chain_phase = _PrefetchingKillChainPhase()


def _kill_chain_phases(count):
    return [
        {
            "value": {
                "kill_chain_name": "benchmark-chain",
                "phase_name": f"phase-{index}",
            }
        }
        for index in range(count)
    ]


def test_add_kill_chain_phases_batches_domain_object_relations_in_bounded_chunks():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.add_kill_chain_phases("indicator", "indicator--1", _kill_chain_phases(201))

    assert len(opencti.kill_chain_phase.calls) == 201
    assert opencti.stix_nested_ref_relationship.object_calls == [
        (
            "indicator--1",
            [f"kill-chain-phase--{index}" for index in range(100)],
            "kill-chain-phase",
        ),
        (
            "indicator--1",
            [f"kill-chain-phase--{index}" for index in range(100, 200)],
            "kill-chain-phase",
        ),
    ]
    assert opencti.stix_domain_object.calls == [
        ("indicator--1", "kill-chain-phase--200")
    ]


def test_add_kill_chain_phases_uses_relationship_bulk_edit_path():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.add_kill_chain_phases(
        "relationship", "relationship--1", _kill_chain_phases(2)
    )

    assert opencti.stix_nested_ref_relationship.relationship_calls == [
        (
            "relationship--1",
            ["kill-chain-phase--0", "kill-chain-phase--1"],
            "kill-chain-phase",
        )
    ]
    assert opencti.stix_core_relationship.calls == []


def test_add_kill_chain_phases_falls_back_to_single_mutations_without_bulk_helper():
    opencti = _OpenCTI(with_bulk=False)
    updater = OpenCTIStix2Update(opencti)

    updater.add_kill_chain_phases("indicator", "indicator--1", _kill_chain_phases(2))

    assert opencti.stix_domain_object.calls == [
        ("indicator--1", "kill-chain-phase--0"),
        ("indicator--1", "kill-chain-phase--1"),
    ]


def test_add_kill_chain_phases_preserves_optional_create_fields():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.add_kill_chain_phases(
        "indicator",
        "indicator--1",
        [
            {
                "value": {
                    "id": "kill-chain-phase--stix",
                    "kill_chain_name": "benchmark-chain",
                    "phase_name": "phase",
                    "x_opencti_order": 7,
                }
            }
        ],
    )

    assert opencti.kill_chain_phase.calls == [
        {
            "kill_chain_name": "benchmark-chain",
            "phase_name": "phase",
            "x_opencti_order": 7,
            "stix_id": "kill-chain-phase--stix",
        }
    ]


def test_add_kill_chain_phases_prefetches_existing_phases_in_bounded_chunks():
    opencti = _PrefetchOpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.add_kill_chain_phases(
        "indicator",
        "indicator--1",
        _kill_chain_phases(KILL_CHAIN_PHASE_PREFETCH_BATCH_SIZE + 1),
    )

    assert opencti.kill_chain_phase.list_filters[0] == [
        f"kill-chain-phase--benchmark-chain|phase-{index}"
        for index in range(KILL_CHAIN_PHASE_PREFETCH_BATCH_SIZE)
    ]
    assert opencti.kill_chain_phase.list_filters[1] == [
        f"kill-chain-phase--benchmark-chain|phase-{KILL_CHAIN_PHASE_PREFETCH_BATCH_SIZE}"
    ]
    assert opencti.kill_chain_phase.list_first == [
        KILL_CHAIN_PHASE_PREFETCH_BATCH_SIZE,
        1,
    ]
    assert opencti.kill_chain_phase.create_calls == []


def test_add_kill_chain_phases_keeps_changed_order_on_per_item_create():
    opencti = _PrefetchOpenCTI()
    updater = OpenCTIStix2Update(opencti)
    kill_chain_phases = _kill_chain_phases(2)
    for kill_chain_phase in kill_chain_phases:
        kill_chain_phase["value"]["x_opencti_order"] = 1

    updater.add_kill_chain_phases("indicator", "indicator--1", kill_chain_phases)

    assert [
        call["x_opencti_order"] for call in opencti.kill_chain_phase.create_calls
    ] == [1, 1]


def test_add_kill_chain_phases_keeps_explicit_ids_on_per_item_create():
    opencti = _PrefetchOpenCTI()
    updater = OpenCTIStix2Update(opencti)
    kill_chain_phases = _kill_chain_phases(2)
    for index, kill_chain_phase in enumerate(kill_chain_phases):
        kill_chain_phase["value"]["id"] = f"kill-chain-phase--explicit-{index}"

    updater.add_kill_chain_phases("indicator", "indicator--1", kill_chain_phases)

    assert opencti.kill_chain_phase.list_filters == []
    assert [call["stix_id"] for call in opencti.kill_chain_phase.create_calls] == [
        "kill-chain-phase--explicit-0",
        "kill-chain-phase--explicit-1",
    ]


def test_add_kill_chain_phases_falls_back_to_per_item_create_when_prefetch_fails():
    opencti = _PrefetchOpenCTI()
    updater = OpenCTIStix2Update(opencti)
    opencti.kill_chain_phase.list = lambda **_kwargs: (_ for _ in ()).throw(
        RuntimeError("prefetch failed")
    )

    updater.add_kill_chain_phases("indicator", "indicator--1", _kill_chain_phases(2))

    assert [call["phase_name"] for call in opencti.kill_chain_phase.create_calls] == [
        "phase-0",
        "phase-1",
    ]
