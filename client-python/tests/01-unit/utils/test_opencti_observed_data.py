from pycti.entities.opencti_observed_data import ObservedData


class _FakeObservableApi:
    def __init__(self):
        self.calls = 0

    def create(self, **kwargs):
        del kwargs
        standard_id = f"observable--{self.calls}"
        self.calls += 1
        return {"standard_id": standard_id}


class _FakeLogger:
    def error(self, *args, **kwargs):
        del args, kwargs


class _FakeOpenCTI:
    def __init__(self):
        self.stix_cyber_observable = _FakeObservableApi()
        self.app_logger = _FakeLogger()

    @staticmethod
    def get_attribute_in_extension(*args, **kwargs):
        del args, kwargs
        return None

    @staticmethod
    def copy_attributes_from_extension(*args, **kwargs):
        del args, kwargs


class _CaptureObservedData(ObservedData):
    def __init__(self, opencti):
        super().__init__(opencti)
        self.last_objects = None

    def create(self, **kwargs):
        self.last_objects = kwargs["objects"]
        return {"id": "observed-data--test"}


def test_import_from_stix2_adds_each_embedded_observable_ref_once():
    observed_data = _CaptureObservedData(_FakeOpenCTI())
    stix_object = {
        "id": "observed-data--test",
        "type": "observed-data",
        "objects": {
            "0": {"type": "ipv4-addr", "value": "198.51.100.1"},
            "1": {"type": "ipv4-addr", "value": "198.51.100.2"},
            "2": {"type": "ipv4-addr", "value": "198.51.100.3"},
        },
    }

    observed_data.import_from_stix2(
        stixObject=stix_object,
        extras={"object_ids": ["observable--existing"]},
    )

    assert observed_data.last_objects == [
        "observable--existing",
        "observable--0",
        "observable--1",
        "observable--2",
    ]
