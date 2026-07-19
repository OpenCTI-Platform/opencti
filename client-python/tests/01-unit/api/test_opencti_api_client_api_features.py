import threading

from pycti.api.opencti_api_client import (
    API_FEATURE_BULK_REF_RELATION_VALIDATION,
    OpenCTIApiClient,
)


def _client_with_query(query):
    client = object.__new__(OpenCTIApiClient)
    client._api_features = None
    client._api_features_lock = threading.Lock()
    client.query = query
    return client


def test_supports_api_feature_caches_advertised_features():
    query_calls = []

    def query(_query):
        query_calls.append(True)
        return {
            "data": {
                "about": {"api_features": [API_FEATURE_BULK_REF_RELATION_VALIDATION]}
            }
        }

    client = _client_with_query(query)

    assert client.supports_api_feature(API_FEATURE_BULK_REF_RELATION_VALIDATION)
    assert not client.supports_api_feature("UNKNOWN_FEATURE")
    assert len(query_calls) == 1


def test_supports_api_feature_caches_older_schema_fallback():
    query_calls = []

    def query(_query):
        query_calls.append(True)
        raise ValueError(
            {"error_message": ('Cannot query field "api_features" on type "AppInfo".')}
        )

    client = _client_with_query(query)

    assert not client.supports_api_feature(API_FEATURE_BULK_REF_RELATION_VALIDATION)
    assert not client.supports_api_feature(API_FEATURE_BULK_REF_RELATION_VALIDATION)
    assert len(query_calls) == 1


def test_supports_api_feature_retries_after_transient_lookup_failure():
    query_calls = []

    def query(_query):
        query_calls.append(True)
        if len(query_calls) == 1:
            raise RuntimeError("temporary failure")
        return {
            "data": {
                "about": {"api_features": [API_FEATURE_BULK_REF_RELATION_VALIDATION]}
            }
        }

    client = _client_with_query(query)

    assert not client.supports_api_feature(API_FEATURE_BULK_REF_RELATION_VALIDATION)
    assert client.supports_api_feature(API_FEATURE_BULK_REF_RELATION_VALIDATION)
    assert len(query_calls) == 2
