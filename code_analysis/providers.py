"""What counts as "a model was invoked here".

Shared by every rule, because the answer must not drift between them: if
Article 12 and Article 50 disagree about whether a call invokes a model, one of
them is wrong on every repo. Adding a provider or a call shape happens here
once.
"""
from __future__ import annotations

# Importing one of these is evidence the file talks to a model provider.
PROVIDER_MODULES = {
    "openai", "anthropic", "cohere", "mistralai", "groq", "litellm",
    "google.generativeai", "google.genai", "together", "replicate",
    "huggingface_hub", "langchain", "langchain_openai", "langchain_anthropic",
    "langchain_community", "llama_index", "ollama", "vertexai", "boto3",
}

# Dotted suffixes that mean "invoke a model" and nothing else. Deliberately
# excludes generic verbs — `.generate()`, `.invoke()`, `.predict()` appear on
# plenty of non-AI objects and firing on them discredits every precise rule.
GENERATION_CALLS = (
    "chat.completions.create",
    "chat.completions.acreate",
    "completions.create",
    "completions.acreate",
    "responses.create",
    "messages.create",          # Anthropic — see NOT_GENERATION
    "messages.stream",
    # OpenAI Assistants: the run invokes the model; appending a thread message
    # does not.
    "threads.runs.create",
    "threads.runs.stream",
    "threads.runs.create_and_poll",
    "runs.create_and_poll",
    "generate_content",
    "text_generation",
    "chat_completion",
    "litellm.completion",
    "litellm.acompletion",
)

# Checked first. `client.beta.threads.messages.create` appends a message to an
# Assistants thread — it invokes no model, so claiming it generates output is
# simply false. Found by scanning openai-quickstart-python, where it was the
# only thing the Article 50 rule fired on.
NOT_GENERATION = (
    "threads.messages.create",
    "threads.messages.list",
    "threads.runs.retrieve",
    "threads.create",
)


# Plenty of production apps never touch an SDK. open-webui proxies raw HTTP to
# https://api.openai.com/v1, so import-based detection sees nothing at all.
PROVIDER_ENDPOINTS = (
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.cohere.ai",
    "api.cohere.com",
    "api.mistral.ai",
    "api.groq.com",
    "openai.azure.com",
    "api.together.xyz",
    "api.replicate.com",
    "bedrock-runtime",
    "api.deepseek.com",
    "openrouter.ai",
    ":11434",            # ollama default
    "api.x.ai",
)

# Path fragments that mean "generate". Reaching the right host is not enough:
# open-webui's pull_model, push_model, copy_model and get_ollama_tags all POST
# to the same Ollama server as its chat endpoint, and flagging them produced 20
# findings about operations that generate nothing.
_GENERATION_PATHS = (
    "chat/completions",
    "/completions",
    "/api/chat",
    "/api/generate",
    "/messages",
    "/generate",
    "/responses",
    ":generatecontent",
    "/invoke",              # bedrock
    "/predict",             # vertex
)

# Same host, but no content is produced for a person. Embeddings return
# vectors; the rest are model management. Checked before the paths above.
_NON_GENERATION_PATHS = (
    "/embeddings", "/embed", "/tags", "/pull", "/push", "/copy", "/show",
    "/version", "/models", "/blobs", "/ps", "/unload", "/delete",
    "/audio", "/speech", "/transcriptions", "/translations", "/moderations",
    "/files", "/fine_tun", "/batches", "/assistants",
)

# Names that carry a provider base URL. open-webui keeps OPENAI_API_BASE_URLS
# in config.py and the call site only sees the variable. Every entry names a
# provider: a bare `base_url` is far too common — combined with the equally
# common `client.post(...)` it made healthchecks and avatar endpoints look
# like model calls, which is how one scan produced 395 findings.
_BASE_URL_NAMES = (
    "openai_api_base", "openai_base_url", "openai_api_url",
    "anthropic_base", "anthropic_api_url",
    "llm_base", "llm_api_base", "model_base_url", "ollama_base",
    "inference_url", "completion_url",
)

_HTTP_METHODS = {"post", "stream", "request", "send", "put"}
_HTTP_CLIENTS = ("requests", "httpx", "aiohttp", "session", "client", "urllib")


def endpoint_evidence(text: str) -> bool:
    """Does this text reference a model provider endpoint?"""
    lowered = text.lower()
    return any(host in lowered for host in PROVIDER_ENDPOINTS)


def looks_like_http_model_call(callee: str, nearby_text: str) -> bool:
    """An HTTP POST that plausibly invokes a model.

    Requires two things: a call shaped like an HTTP request, and evidence in
    the surrounding code that the target is a model provider — either the host
    itself, a generation path, or a variable holding a provider base URL.
    """
    if not callee:
        return False
    lowered = callee.lower()
    tail = lowered.rsplit(".", 1)[-1]
    if tail not in _HTTP_METHODS:
        return False
    if not any(client in lowered for client in _HTTP_CLIENTS):
        return False

    context = nearby_text.lower()

    # A management or embeddings path wins over everything else: it is positive
    # evidence that this particular call does not generate content.
    if any(path in context for path in _NON_GENERATION_PATHS):
        return False

    if not any(path in context for path in _GENERATION_PATHS):
        return False

    # Generation-shaped path, but is it a model provider at the other end?
    return (
        endpoint_evidence(context)
        or any(name in context for name in _BASE_URL_NAMES)
    )


# Classes whose construction means "this file builds a language model". Their
# presence is what makes the generic verbs below safe to match.
LLM_CONSTRUCTORS = {
    "ChatOpenAI", "AzureChatOpenAI", "ChatAnthropic", "ChatGroq", "ChatMistralAI",
    "ChatGoogleGenerativeAI", "ChatVertexAI", "ChatCohere", "ChatOllama",
    "ChatLiteLLM", "ChatBedrock", "HuggingFaceHub", "HuggingFacePipeline",
    "LLMChain", "ConversationChain", "RetrievalQA", "ConversationalRetrievalChain",
    "AgentExecutor", "SequentialChain",
}

# Verbs that invoke a chain. Far too generic on their own — `.run()` and
# `.predict()` are everywhere — so they only count alongside a constructor.
CHAIN_VERBS = {
    "run", "arun", "invoke", "ainvoke", "predict", "apredict",
    "predict_messages", "batch", "abatch", "stream", "astream",
}


# Objects that take the same verbs without invoking a model. A retriever
# fetches documents; a parser parses; a runnable may be anything at all.
# Without this, scanning langchain itself reported `self.retriever.invoke` and
# `self.runnable.stream` as model calls.
_NON_LLM_RECEIVERS = (
    "retriever", "runnable", "parser", "splitter", "loader", "embedding",
    "vectorstore", "vector_store", "memory", "store", "db", "index",
    "transformer", "compressor", "reranker", "tool", "callback",
)


def _is_non_llm_receiver(receiver: str) -> bool:
    """Match receiver *tokens*, never raw substrings.

    A substring test made "feedback" match "db", which silenced the Article 50
    findings on an AI interview tool. Short markers now need a whole token.
    """
    tokens = [
        token for token in receiver.lower().replace(".", "_").split("_") if token
    ]
    for marker in _NON_LLM_RECEIVERS:
        if len(marker) <= 5:
            if marker in tokens:
                return True
        elif any(marker in token for token in tokens):
            return True
    return False


def constructs_llm(callees: tuple[str, ...]) -> bool:
    """Does this file build a language model object?"""
    return any(
        callee.rsplit(".", 1)[-1] in LLM_CONSTRUCTORS
        for callee in callees
        if callee
    )


def uses_provider(imports: set[str], callees: tuple[str, ...] = ()) -> bool:
    """Does this file talk to a model provider?

    Imports alone are not enough. aider reaches litellm through
    `from aider.llm import litellm`, so the import table contains 'aider' and
    the provider is invisible — while the call site still reads
    `litellm.completion(...)`. Re-exports and lazy imports are common enough
    that the call root has to count as evidence too.
    """
    if PROVIDER_MODULES & imports:
        return True
    return any(
        callee.split(".", 1)[0] in PROVIDER_MODULES
        for callee in callees
        if callee
    )


def is_generation_call(callee: str, chain_context: bool = False) -> bool:
    """True only for unambiguous model invocations.

    `chain_context` says the file constructs an LLM object, which is what makes
    `chain.run(...)` readable as a model call. GPTInterviewer — a behavioural
    screening tool — went undetected because LangChain never uses an SDK call
    shape.
    """
    if not callee:
        return False

    def matches(targets: tuple[str, ...]) -> bool:
        return any(
            callee == target or callee.endswith("." + target)
            for target in targets
        )

    if matches(NOT_GENERATION):
        return False
    if matches(GENERATION_CALLS):
        return True
    if not chain_context:
        return False
    parts = callee.rsplit(".", 1)
    if parts[-1] not in CHAIN_VERBS:
        return False
    return not _is_non_llm_receiver(parts[0] if len(parts) > 1 else "")
