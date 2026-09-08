from cve_agent.classification.prompts import CLASSIFICATION_SYSTEM_PROMPT, HIERARCHY_ROUTING_SYSTEM_PROMPT
from cve_agent.core.investigation import InvestigationAspect
from cve_agent.investigation.prompts import RESEARCH_SYSTEM_PROMPT
from cve_agent.investigation.schemas import AGENT_TOOLS


def test_prompts_require_mechanism_focused_evidence_without_exposing_taxonomy_to_research():
    prompt = RESEARCH_SYSTEM_PROMPT.casefold()
    assert "taxonomy" not in prompt
    assert "strongest starting evidence" in prompt
    assert "without performing web research" not in prompt
    assert "search the web only" not in prompt
    assert "never call fetch" not in prompt
    assert "same stored passages" in prompt
    assert "one repeat fetch per document is permitted" in prompt
    assert "further repeats return a no-new-information error" in prompt
    assert "search omits results" in prompt
    assert "immediately after each successful fetch" in prompt
    assert "before searching, fetching another source" in prompt
    assert "never a search result or its snippet" in prompt
    assert "must not be recorded again" in prompt
    assert "separate root_cause or exploitation_mechanism finding" in prompt
    assert "act as a trusted service" in prompt
    assert "could allow remote code execution" in prompt
    assert "do not finish on that phrase alone" in prompt
    assert "make a targeted search" in prompt
    assert "additional targeted research is appropriate" in prompt
    assert "information that could change classification" in prompt
    assert "expected only to restate recorded facts" in prompt
    assert "root cause" in RESEARCH_SYSTEM_PROMPT
    assert "record_evidence" in RESEARCH_SYSTEM_PROMPT
    assert "untrusted source data" in RESEARCH_SYSTEM_PROMPT
    assert "not a checklist" in RESEARCH_SYSTEM_PROMPT
    assert "consequence" in CLASSIFICATION_SYSTEM_PROMPT
    assert "does not by itself prove" in CLASSIFICATION_SYSTEM_PROMPT
    assert "regardless of their organizational aspect" in CLASSIFICATION_SYSTEM_PROMPT
    assert "acts as a trusted service through an alternate route" in CLASSIFICATION_SYSTEM_PROMPT
    assert "semantic specialization" in HIERARCHY_ROUTING_SYSTEM_PROMPT
    assert "exactly one routing decision" in HIERARCHY_ROUTING_SYSTEM_PROMPT


def test_finish_tool_uses_five_optional_topics_without_unknown_or_status_matrix():
    finish = next(item["function"] for item in AGENT_TOOLS if item["function"]["name"] == "finish_investigation")
    parameters = finish["parameters"]
    aspects = parameters["properties"]["findings"]["items"]["properties"]["aspect"]["enum"]

    assert parameters["required"] == ["findings", "summary"]
    assert set(aspects) == {item.value for item in InvestigationAspect}
    assert "unknowns" not in parameters["properties"]
    assert "information_status" not in parameters["properties"]
    fetch = next(item["function"] for item in AGENT_TOOLS if item["function"]["name"] == "fetch")
    assert "available_documents" in fetch["description"]
    assert "same stored passages" in fetch["description"]
    assert "Never fetch" not in fetch["description"]
    assert "permitted to redisplay" in fetch["description"]
    assert "immediately record" in fetch["description"].casefold()
    record = next(item["function"] for item in AGENT_TOOLS if item["function"]["name"] == "record_evidence")
    assert "every distinct, substantive passage" in record["description"]
    assert "nvd-description" in record["description"]
    assert "already in recorded_evidence" in record["description"]
    assert "separate root_cause or exploitation_mechanism findings" in finish["description"]
