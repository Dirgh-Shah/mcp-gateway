import pytest

from app.policy import (
    ARGUMENT_TOO_LONG,
    COLLECTION_TOO_LARGE,
    DENIED_BY_RULE,
    NOT_ALLOWED,
    UNKNOWN_ROLE,
    VALUE_NOT_PERMITTED,
    Policy,
    PolicyError,
)

RAW = {
    "version": 1,
    "roles": {
        "reader": {
            "allow": ["search_*", "get_*"],
            "deny": ["delete_*", "get_secrets"],
            "limits": {"max_string_length": 20, "max_collection_size": 3},
            "arguments": {
                "search_documents": {
                    "query": {"max_length": 10},
                    "scope": {"enum": ["team", "personal"]},
                    "tags": {"max_items": 2},
                }
            },
        },
        "auditor": {"admin": True, "allow": [], "deny": ["*"]},
    },
}


def policy():
    return Policy.from_dict(RAW)


def test_allowed_tool_passes():
    assert policy().decide("reader", "get_document", {"document_id": "doc-1"}).allowed


def test_tool_outside_allow_list_is_denied():
    decision = policy().decide("reader", "fetch_ci_config", {})
    assert not decision.allowed
    assert decision.code == NOT_ALLOWED


def test_deny_pattern_overrides_allow_pattern():
    # get_secrets matches the allow pattern get_* and the deny entry get_secrets.
    decision = policy().decide("reader", "get_secrets", {})
    assert not decision.allowed
    assert decision.code == DENIED_BY_RULE


def test_unknown_role_is_denied_not_unlimited():
    decision = policy().decide("nonexistent", "get_document", {})
    assert not decision.allowed
    assert decision.code == UNKNOWN_ROLE


def test_tools_list_omits_tools_the_role_cannot_call():
    catalogue = [
        {"name": "search_documents"},
        {"name": "get_document"},
        {"name": "delete_document"},
        {"name": "get_secrets"},
        {"name": "fetch_ci_config"},
    ]
    visible = {tool["name"] for tool in policy().visible_tools("reader", catalogue)}
    assert visible == {"search_documents", "get_document"}


def test_unknown_role_sees_an_empty_catalogue():
    assert policy().visible_tools("nonexistent", [{"name": "get_document"}]) == []


def test_oversized_string_argument_is_rejected():
    decision = policy().decide("reader", "get_document", {"document_id": "x" * 21})
    assert not decision.allowed
    assert decision.code == ARGUMENT_TOO_LONG


def test_oversized_nested_string_is_rejected():
    decision = policy().decide(
        "reader", "get_document", {"filter": {"deep": ["ok", "y" * 50]}}
    )
    assert not decision.allowed
    assert decision.code == ARGUMENT_TOO_LONG


def test_oversized_collection_is_rejected():
    decision = policy().decide("reader", "get_document", {"ids": [1, 2, 3, 4]})
    assert not decision.allowed
    assert decision.code == COLLECTION_TOO_LARGE


def test_per_argument_length_limit_is_tighter_than_the_role_limit():
    # 15 chars: under the role's 20, over search_documents.query's 10.
    decision = policy().decide("reader", "search_documents", {"query": "x" * 15})
    assert not decision.allowed
    assert decision.code == ARGUMENT_TOO_LONG
    # The same value elsewhere is fine.
    assert policy().decide("reader", "get_document", {"query": "x" * 15}).allowed


def test_enum_membership_is_enforced():
    assert policy().decide("reader", "search_documents", {"scope": "team"}).allowed
    decision = policy().decide("reader", "search_documents", {"scope": "all"})
    assert not decision.allowed
    assert decision.code == VALUE_NOT_PERMITTED


def test_per_argument_item_limit_is_enforced():
    decision = policy().decide("reader", "search_documents", {"tags": ["a", "b", "c"]})
    assert not decision.allowed
    assert decision.code == COLLECTION_TOO_LARGE


def test_non_object_arguments_are_rejected():
    assert not policy().decide("reader", "get_document", ["not", "an", "object"]).allowed


def test_admin_flag_is_read_from_the_policy():
    assert policy().is_admin("auditor")
    assert not policy().is_admin("reader")
    assert not policy().is_admin("nonexistent")


def test_unknown_keys_in_the_policy_file_are_an_error():
    bad = {"version": 1, "roles": {"reader": {"allw": ["get_*"]}}}
    with pytest.raises(PolicyError):
        Policy.from_dict(bad)


def test_unsupported_version_is_an_error():
    with pytest.raises(PolicyError):
        Policy.from_dict({"version": 99, "roles": {"reader": {"allow": ["*"]}}})


def test_policy_without_roles_is_an_error():
    with pytest.raises(PolicyError):
        Policy.from_dict({"version": 1, "roles": {}})


def test_shipped_policy_file_parses_and_denies_by_default():
    loaded = Policy.load("policy.yaml")
    assert set(loaded.roles) == {"reader", "editor", "operator", "auditor"}
    assert not loaded.decide("reader", "delete_document", {"document_id": "d"}).allowed
    assert loaded.decide("editor", "delete_document", {"document_id": "d"}).allowed
    # editor allows fetch_*, so this can only be a deny-beats-allow outcome.
    assert loaded.decide("editor", "fetch_ci_config", {}).code == DENIED_BY_RULE
    assert loaded.decide("operator", "fetch_ci_config", {}).allowed
    assert not loaded.decide("operator", "delete_document", {"document_id": "d"}).allowed


def test_shipped_policy_hides_build_configuration_from_readers():
    loaded = Policy.load("policy.yaml")
    catalogue = [{"name": "get_document"}, {"name": "fetch_ci_config"}]
    assert [t["name"] for t in loaded.visible_tools("reader", catalogue)] == [
        "get_document"
    ]
