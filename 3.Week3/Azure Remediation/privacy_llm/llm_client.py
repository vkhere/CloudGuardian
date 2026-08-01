"""
privacy_llm/llm_client.py

WHAT: The only place in this project allowed to make an outbound
      call to an LLM API. Every call is forced through
      tokenize_finding() -> verify_no_leakage() -> [API call] ->
      detokenize(), in that order, with no way to skip a step.

WHY PROVIDER-AGNOSTIC: this project's Week 2 LLM verification work
      may already target a specific provider. Rather than guess and
      hardcode a dependency you may not have configured, this module
      takes the actual API call as an injected function
      (`llm_call_fn`). Two ready-to-use implementations are provided
      below - `azure_openai_call` (keeps the call inside your Azure
      tenant boundary end-to-end, the Well-Architected-aligned
      choice) and `anthropic_call` (if you're calling Claude directly).
      Wire whichever one your Week 2 notebook already uses.

WHERE THIS RUNS: called from a Function (or a notebook, or the
      dashboard) any time you need a plain-English explanation of a
      finding. Not wired into the Function App's HTTP/Event Grid
      triggers by default - the remediation engine itself never
      needs to call an LLM to DO a remediation, only to EXPLAIN one,
      so keeping this decoupled from function_app.py is deliberate.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from privacy_llm.tokenizer import TokenMap, detokenize, tokenize_finding, verify_no_leakage

logger = logging.getLogger("cloudguardian.privacy_llm")

LlmCallFn = Callable[[str], str]  # takes a prompt string, returns the raw completion text

SYSTEM_PROMPT = (
    "You are a cloud security analyst. You will receive a JSON-encoded "
    "CSPM finding where identifying values have been replaced with "
    "tokens like ⟪RESOURCE_1⟫ - treat these tokens as opaque "
    "placeholders, do not attempt to guess what they represent. Produce "
    "a 2-line plain-English explanation: line 1 = business impact, "
    "line 2 = recommended remediation. Keep the tokens verbatim in your "
    "response wherever you refer to the resource, subscription, or "
    "principal involved."
)


def explain_finding(
    finding: dict,
    llm_call_fn: LlmCallFn,
    token_map: Optional[TokenMap] = None,
) -> dict:
    """Full privacy-preserving round trip for one finding.

    Returns a dict with both the raw (tokenized) and final
    (detokenized) explanation, plus the fields Week 2's verification
    pipeline needs to check the LLM's claims against the raw scanner
    data: which control this was, and a flag confirming detokenization
    ran (so a downstream consumer can refuse to display anything that
    skipped it).
    """
    sanitized_finding, token_map = tokenize_finding(finding, token_map)

    prompt = (
        f"{SYSTEM_PROMPT}\n\nFinding (tokenized):\n{sanitized_finding}"
    )

    # Guardrail runs on the EXACT string being sent, not the dict -
    # catches anything an f-string/json.dumps might have reintroduced.
    verify_no_leakage(prompt)

    logger.info(
        "Calling LLM for control_id=%s with %d tokenized value(s)",
        finding.get("control_id"),
        len(token_map.token_to_real),
    )
    raw_response = llm_call_fn(prompt)

    final_response = detokenize(raw_response, token_map)

    return {
        "control_id": finding.get("control_id"),
        "finding_id": finding.get("finding_id"),
        "tokens_used": len(token_map.token_to_real),
        "raw_llm_response_tokenized": raw_response,
        "explanation": final_response,
        "detokenized": True,
    }


# ---------------------------------------------------------------
# Reference implementations of LlmCallFn - pick one, or write your
# own with the same signature (str -> str).
# ---------------------------------------------------------------

def azure_openai_call(deployment_name: str, endpoint: str, credential) -> LlmCallFn:
    """Azure OpenAI, authenticated via the SAME DefaultAzureCredential
    pattern as the remediation engine (see shared/azure_clients.py) -
    no separate API key to manage, and the call never leaves Azure's
    network boundary. This is the recommended choice for the "keep
    everything inside the tenant" story in your final report.

    Usage:
        from azure.identity import DefaultAzureCredential, get_bearer_token_provider
        cred = DefaultAzureCredential()
        call_fn = azure_openai_call("gpt-4o-mini", "https://<your-aoai>.openai.azure.com/", cred)
        result = explain_finding(finding, call_fn)
    """
    from azure.identity import get_bearer_token_provider
    from openai import AzureOpenAI

    token_provider = get_bearer_token_provider(credential, "https://cognitiveservices.azure.com/.default")
    client = AzureOpenAI(
        azure_endpoint=endpoint,
        azure_ad_token_provider=token_provider,
        api_version="2024-08-01-preview",
    )

    def _call(prompt: str) -> str:
        completion = client.chat.completions.create(
            model=deployment_name,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            temperature=0.2,
        )
        return completion.choices[0].message.content or ""

    return _call


def anthropic_call(api_key: str, model: str = "claude-sonnet-5") -> LlmCallFn:
    """Direct Anthropic API call. Simpler to set up for a lab/demo,
    at the cost of the prompt leaving Azure's boundary (still fully
    tokenized/pseudonymized by the time it does)."""
    from anthropic import Anthropic

    client = Anthropic(api_key=api_key)

    def _call(prompt: str) -> str:
        message = client.messages.create(
            model=model,
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in message.content if block.type == "text")

    return _call
