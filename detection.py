"""Guardia AI — shared CI detection module.

Ported from the Guardia backend scanner (backend/services/repo_scanner.py) so CI
scans detect the same things the platform does: AI libraries across Python, JS/TS,
Go, Java/Kotlin, Ruby and Rust, plus AI usage hidden in configuration files
(model names, provider endpoints, credential env keys).

Keep this file identical in github-action/ and gitlab-component/.
"""
from __future__ import annotations

import json
import os
import re

# ---------- Library signatures: name → (category, note) ----------

PY_AI_LIBRARIES: dict[str, tuple[str, str]] = {
    "openai": ("LLM API", "OpenAI GPT models detected — deployer obligations apply"),
    "anthropic": ("LLM API", "Anthropic Claude models detected — deployer obligations apply"),
    "google-generativeai": ("LLM API", "Google Gemini models detected"),
    "cohere": ("LLM API", "Cohere LLMs detected"),
    "mistralai": ("LLM API", "Mistral AI models detected"),
    "together": ("LLM API", "Together AI hosted models detected"),
    "groq": ("LLM API", "Groq-hosted LLMs detected"),
    "replicate": ("LLM API", "Replicate API detected"),
    "ai21": ("LLM API", "AI21 language models detected"),
    "huggingface_hub": ("Model Hub", "HuggingFace Hub usage detected — provider obligations may apply"),
    "transformers": ("ML Framework", "HuggingFace Transformers detected — possible self-hosted model"),
    "diffusers": ("Generative AI", "HuggingFace Diffusers (image generation) detected"),
    "torch": ("ML Framework", "PyTorch detected — ML model likely present"),
    "tensorflow": ("ML Framework", "TensorFlow detected — ML model likely present"),
    "keras": ("ML Framework", "Keras detected — ML model likely present"),
    "sklearn": ("ML Framework", "scikit-learn detected"),
    "scikit-learn": ("ML Framework", "scikit-learn detected"),
    "xgboost": ("ML Framework", "XGBoost decision model detected — may be high-risk"),
    "lightgbm": ("ML Framework", "LightGBM decision model detected — may be high-risk"),
    "catboost": ("ML Framework", "CatBoost decision model detected — may be high-risk"),
    "azure-ai-textanalytics": ("Cloud AI", "Azure Text Analytics detected"),
    "azure-cognitiveservices-vision": ("Cloud AI", "Azure Computer Vision detected — check for biometric use"),
    "azure-ai-formrecognizer": ("Cloud AI", "Azure Form Recognizer detected"),
    "google-cloud-aiplatform": ("Cloud AI", "Google Cloud AI Platform detected"),
    "google-cloud-vision": ("Cloud AI", "Google Cloud Vision detected — may process biometric data"),
    "boto3": ("Cloud SDK", "AWS SDK detected — check for SageMaker/Rekognition/Comprehend usage"),
    "pinecone": ("Vector DB", "Pinecone vector database detected"),
    "chromadb": ("Vector DB", "ChromaDB vector database detected"),
    "weaviate": ("Vector DB", "Weaviate vector database detected"),
    "qdrant": ("Vector DB", "Qdrant vector database detected"),
    "langchain": ("AI Orchestration", "LangChain AI framework detected"),
    "llama-index": ("AI Orchestration", "LlamaIndex RAG framework detected"),
    "llamaindex": ("AI Orchestration", "LlamaIndex RAG framework detected"),
    "autogen": ("AI Agents", "AutoGen multi-agent framework detected"),
    "crewai": ("AI Agents", "CrewAI agents framework detected"),
    "pydantic-ai": ("AI Orchestration", "PydanticAI framework detected"),
    "opencv-python": ("Computer Vision", "OpenCV detected — check for biometric use"),
    "deepface": ("Biometric AI", "DeepFace FACIAL RECOGNITION detected — likely HIGH RISK (Annex III §1)"),
    "face-recognition": ("Biometric AI", "face-recognition library detected — HIGH RISK (Annex III §1)"),
    "mediapipe": ("Computer Vision", "MediaPipe (pose/face) detected — check for biometric use"),
}

JS_AI_LIBRARIES: dict[str, tuple[str, str]] = {
    "openai": ("LLM API", "OpenAI GPT models detected — deployer obligations apply"),
    "@anthropic-ai/sdk": ("LLM API", "Anthropic Claude models detected"),
    "@google/generative-ai": ("LLM API", "Google Gemini models detected"),
    "cohere-ai": ("LLM API", "Cohere LLMs detected"),
    "@mistralai/mistralai": ("LLM API", "Mistral AI models detected"),
    "replicate": ("LLM API", "Replicate API detected"),
    "groq-sdk": ("LLM API", "Groq-hosted LLMs detected"),
    "@huggingface/inference": ("Model Hub", "HuggingFace Inference API detected"),
    "@tensorflow/tfjs": ("ML Framework", "TensorFlow.js detected"),
    "@tensorflow/tfjs-node": ("ML Framework", "TensorFlow.js Node detected"),
    "@xenova/transformers": ("ML Framework", "Transformers.js detected — provider obligations may apply"),
    "brain.js": ("ML Framework", "Brain.js neural network library detected"),
    "onnxruntime-web": ("ML Framework", "ONNX Runtime Web detected"),
    "onnxruntime-node": ("ML Framework", "ONNX Runtime Node detected"),
    "ai": ("AI Orchestration", "Vercel AI SDK detected — deployer obligations apply"),
    "@ai-sdk/openai": ("AI Orchestration", "Vercel AI SDK OpenAI provider detected"),
    "@ai-sdk/anthropic": ("AI Orchestration", "Vercel AI SDK Anthropic provider detected"),
    "@ai-sdk/google": ("AI Orchestration", "Vercel AI SDK Google provider detected"),
    "langchain": ("AI Orchestration", "LangChain JS detected"),
    "@langchain/openai": ("AI Orchestration", "LangChain OpenAI integration detected"),
    "@langchain/anthropic": ("AI Orchestration", "LangChain Anthropic integration detected"),
    "@langchain/google-genai": ("AI Orchestration", "LangChain Google integration detected"),
    "@langchain/community": ("AI Orchestration", "LangChain community integrations detected"),
    "llamaindex": ("AI Orchestration", "LlamaIndex JS detected"),
    "@pinecone-database/pinecone": ("Vector DB", "Pinecone vector database detected"),
    "chromadb": ("Vector DB", "ChromaDB vector database detected"),
    "@weaviate/weaviate-ts-client": ("Vector DB", "Weaviate vector database detected"),
    "@azure/ai-text-analytics": ("Cloud AI", "Azure Text Analytics detected"),
    "@azure/ai-form-recognizer": ("Cloud AI", "Azure Form Recognizer detected"),
    "@azure/openai": ("LLM API", "Azure OpenAI Service detected"),
    "@aws-sdk/client-rekognition": ("Cloud AI", "AWS Rekognition detected — likely HIGH RISK (Annex III)"),
    "@aws-sdk/client-sagemaker": ("Cloud AI", "AWS SageMaker detected"),
    "@aws-sdk/client-bedrock-runtime": ("LLM API", "AWS Bedrock detected"),
    "@aws-sdk/client-comprehend": ("Cloud AI", "AWS Comprehend detected"),
    "@aws-sdk/client-textract": ("Cloud AI", "AWS Textract detected"),
    "@google-cloud/aiplatform": ("Cloud AI", "Google Cloud AI Platform detected"),
    "@google-cloud/vision": ("Cloud AI", "Google Cloud Vision detected — may process biometric data"),
    "face-api.js": ("Biometric AI", "face-api.js FACIAL RECOGNITION detected — HIGH RISK (Annex III §1)"),
    "@vladmandic/face-api": ("Biometric AI", "Face API detected — HIGH RISK (Annex III §1)"),
}

GO_AI_LIBRARIES: dict[str, tuple[str, str]] = {
    "github.com/sashabaranov/go-openai": ("LLM API", "OpenAI GPT models (go-openai) detected"),
    "github.com/openai/openai-go": ("LLM API", "OpenAI official Go SDK detected"),
    "github.com/anthropics/anthropic-sdk-go": ("LLM API", "Anthropic Claude models detected"),
    "github.com/google/generative-ai-go": ("LLM API", "Google Gemini models detected"),
    "github.com/cohere-ai/cohere-go": ("LLM API", "Cohere LLMs detected"),
    "github.com/tmc/langchaingo": ("AI Orchestration", "LangChainGo detected"),
    "github.com/ollama/ollama": ("LLM API", "Ollama self-hosted LLM detected — provider obligations may apply"),
    "github.com/aws/aws-sdk-go-v2/service/bedrockruntime": ("LLM API", "AWS Bedrock detected"),
    "github.com/pinecone-io/go-pinecone": ("Vector DB", "Pinecone vector database detected"),
    "github.com/weaviate/weaviate-go-client": ("Vector DB", "Weaviate vector database detected"),
    "github.com/qdrant/go-client": ("Vector DB", "Qdrant vector database detected"),
}

JAVA_AI_LIBRARIES: dict[str, tuple[str, str]] = {
    "com.openai": ("LLM API", "OpenAI official Java SDK detected"),
    "com.theokanning": ("LLM API", "OpenAI GPT models (openai-gpt3-java) detected"),
    "com.anthropic": ("LLM API", "Anthropic Claude models detected"),
    "dev.langchain4j": ("AI Orchestration", "LangChain4j detected"),
    "org.springframework.ai": ("AI Orchestration", "Spring AI detected"),
    "ai.djl": ("ML Framework", "Deep Java Library (DJL) detected"),
    "org.deeplearning4j": ("ML Framework", "Deeplearning4j detected"),
    "org.tensorflow": ("ML Framework", "TensorFlow Java detected"),
    "azure-ai-openai": ("LLM API", "Azure OpenAI Service detected"),
    "com.azure.ai.openai": ("LLM API", "Azure OpenAI Service detected"),
    "bedrockruntime": ("LLM API", "AWS Bedrock detected"),
    "google-cloud-vertexai": ("Cloud AI", "Google Cloud Vertex AI detected"),
    "com.google.cloud.vertexai": ("Cloud AI", "Google Cloud Vertex AI detected"),
}

RUBY_AI_LIBRARIES: dict[str, tuple[str, str]] = {
    "ruby-openai": ("LLM API", "OpenAI GPT models (ruby-openai) detected"),
    "openai": ("LLM API", "OpenAI GPT models detected"),
    "anthropic": ("LLM API", "Anthropic Claude models detected"),
    "gemini-ai": ("LLM API", "Google Gemini models detected"),
    "cohere-ruby": ("LLM API", "Cohere LLMs detected"),
    "langchainrb": ("AI Orchestration", "Langchain.rb detected"),
    "aws-sdk-bedrockruntime": ("LLM API", "AWS Bedrock detected"),
    "torch-rb": ("ML Framework", "torch.rb (PyTorch bindings) detected"),
    "transformers-rb": ("ML Framework", "Transformers.rb detected"),
}

RUST_AI_LIBRARIES: dict[str, tuple[str, str]] = {
    "async-openai": ("LLM API", "OpenAI GPT models (async-openai) detected"),
    "openai": ("LLM API", "OpenAI GPT models detected"),
    "anthropic": ("LLM API", "Anthropic Claude models detected"),
    "genai": ("LLM API", "genai multi-provider LLM client detected"),
    "ollama-rs": ("LLM API", "Ollama self-hosted LLM detected"),
    "tiktoken-rs": ("LLM API", "tiktoken tokenizer detected — indicates OpenAI LLM usage"),
    "aws-sdk-bedrockruntime": ("LLM API", "AWS Bedrock detected"),
    "tch": ("ML Framework", "tch (libtorch bindings) detected"),
    "candle-core": ("ML Framework", "HuggingFace Candle detected"),
    "burn": ("ML Framework", "Burn deep learning framework detected"),
    "llm": ("LLM API", "llm crate detected — runs local LLMs"),
}

# Merged lookup for display: name → (category, note). Order matters: first hit wins.
LIBRARY_META: dict[str, tuple[str, str]] = {}
for _d in (JS_AI_LIBRARIES, PY_AI_LIBRARIES, GO_AI_LIBRARIES, JAVA_AI_LIBRARIES,
           RUBY_AI_LIBRARIES, RUST_AI_LIBRARIES):
    for _k, _v in _d.items():
        LIBRARY_META.setdefault(_k, _v)

# ---------- Config-file AI indicators (model names, endpoints, env keys) ----------

MODEL_NAME_RE = re.compile(
    r'\b('
    r'gpt-[34][\w.\-]*|gpt-4o[\w\-]*'
    r'|claude-[\w][\w.\-]*'
    r'|gemini-[\w][\w.\-]*'
    r'|mistral-(?:tiny|small|medium|large|nemo)[\w.\-]*'
    r'|(?:meta-)?llama-?[23][\w.\-]*'
    r'|text-embedding-[\w\-]+'
    r'|dall-e-\d'
    r'|whisper-\d'
    r'|command-r[\w\-]*'
    r')\b',
    re.IGNORECASE,
)

AI_ENDPOINTS: dict[str, str] = {
    "api.openai.com": "OpenAI API endpoint configured — an OpenAI integration exists even without an SDK import",
    "openai.azure.com": "Azure OpenAI endpoint configured",
    "api.anthropic.com": "Anthropic API endpoint configured — Claude integration exists",
    "generativelanguage.googleapis.com": "Google Gemini API endpoint configured",
    "aiplatform.googleapis.com": "Google Cloud AI Platform endpoint configured",
    "api.mistral.ai": "Mistral AI endpoint configured",
    "api.cohere.ai": "Cohere API endpoint configured",
    "api.cohere.com": "Cohere API endpoint configured",
    "api.groq.com": "Groq API endpoint configured",
    "api.together.xyz": "Together AI endpoint configured",
    "api-inference.huggingface.co": "HuggingFace Inference API endpoint configured",
    "api.replicate.com": "Replicate API endpoint configured",
    "bedrock-runtime": "AWS Bedrock runtime endpoint configured",
    "openrouter.ai": "OpenRouter endpoint configured — routes to multiple LLM providers",
}

AI_ENV_KEYS: dict[str, str] = {
    "OPENAI_API_KEY": "OpenAI credentials configured — OpenAI usage likely even without SDK import",
    "AZURE_OPENAI_API_KEY": "Azure OpenAI credentials configured",
    "AZURE_OPENAI_ENDPOINT": "Azure OpenAI endpoint configured",
    "ANTHROPIC_API_KEY": "Anthropic (Claude) credentials configured",
    "GEMINI_API_KEY": "Google Gemini credentials configured",
    "GOOGLE_GENERATIVE_AI_API_KEY": "Google Gemini credentials configured",
    "MISTRAL_API_KEY": "Mistral AI credentials configured",
    "COHERE_API_KEY": "Cohere credentials configured",
    "GROQ_API_KEY": "Groq credentials configured",
    "TOGETHER_API_KEY": "Together AI credentials configured",
    "REPLICATE_API_TOKEN": "Replicate credentials configured",
    "HUGGINGFACE_API_KEY": "HuggingFace credentials configured",
    "HUGGINGFACEHUB_API_TOKEN": "HuggingFace Hub credentials configured",
    "HF_TOKEN": "HuggingFace credentials configured",
    "OPENROUTER_API_KEY": "OpenRouter credentials configured — multi-LLM routing",
}

AI_ENV_KEY_RE = re.compile(r'\b(' + '|'.join(re.escape(k) for k in AI_ENV_KEYS) + r')\b')

CONFIG_EXTENSIONS = {'.yml', '.yaml', '.tf', '.tfvars', '.toml', '.ini', '.cfg', '.conf', '.properties'}
JS_EXTENSIONS = {'.js', '.ts', '.tsx', '.jsx', '.mjs', '.cjs'}

SKIP_DIRS = {"node_modules", "venv", ".venv", "vendor", "dist", ".next", "__pycache__", ".git", "target", "build"}

MAX_FILE_BYTES = 2 * 1024 * 1024

# ---------- File typing ----------


def file_type(path: str) -> str:
    """Return a scan category for the file (mirrors the backend scanner)."""
    lower = path.lower().replace("\\", "/")
    basename = lower.split('/')[-1]
    if basename == 'package.json':
        return 'package_json'
    if any(lower.endswith(e) for e in JS_EXTENSIONS):
        return 'js'
    if lower.endswith('.py'):
        return 'py'
    if basename in ('requirements.txt', 'pipfile') or lower.endswith('pyproject.toml') or lower.endswith('setup.py'):
        return 'requirements'
    if basename == 'go.mod' or lower.endswith('.go'):
        return 'go'
    if basename in ('pom.xml', 'build.gradle', 'build.gradle.kts') or lower.endswith('.java') or lower.endswith('.kt'):
        return 'java'
    if basename in ('gemfile', 'gemfile.lock') or lower.endswith('.gemspec') or lower.endswith('.rb'):
        return 'ruby'
    if basename == 'cargo.toml':
        return 'cargo'
    if lower.endswith('.rs'):
        return 'rust'
    if basename.startswith('.env') or basename.startswith('dockerfile'):
        return 'config'
    if any(lower.endswith(e) for e in CONFIG_EXTENSIONS):
        return 'config'
    return 'other'


def should_scan(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")
    if any(p in SKIP_DIRS for p in parts):
        return False
    return file_type(path) != 'other'


# ---------- Matchers (mirroring backend/services/repo_scanner.py) ----------

_PY_IMPORT_PATTERNS = [
    re.compile(r'^\s*import\s+([\w]+)', re.MULTILINE),
    re.compile(r'^\s*from\s+([\w]+)', re.MULTILINE),
]
_JS_IMPORT_PATTERNS = [
    re.compile(r'''(?:import|from)\s+['"](@?[\w\-]+(?:/[\w\-\.]+)?)['"]''', re.MULTILINE),
    re.compile(r'''require\s*\(\s*['"](@?[\w\-]+(?:/[\w\-\.]+)?)['"]\s*\)''', re.MULTILINE),
]
_REQUIREMENTS_PATTERN = re.compile(r'^([\w\-]+)', re.MULTILINE)


def _match_py(names: set) -> list:
    matched = []
    for lib in PY_AI_LIBRARIES:
        if lib.lower() in names or lib.lower().replace('-', '_') in names:
            matched.append(lib)
    return matched


def _match_js(names: set) -> list:
    names_lower = {n.lower() for n in names}
    return [lib for lib in JS_AI_LIBRARIES if lib.lower() in names_lower]


def _extract_py_imports(content: str) -> set:
    found = set()
    for pattern in _PY_IMPORT_PATTERNS:
        for m in pattern.finditer(content):
            name = m.group(1).strip().lower()
            found.add(name)
            found.add(name.replace('_', '-'))
    return found


def _extract_js_imports(content: str) -> set:
    found = set()
    for pattern in _JS_IMPORT_PATTERNS:
        for m in pattern.finditer(content):
            found.add(m.group(1).strip())
    return found


def _extract_package_json_deps(content: str) -> set:
    try:
        data = json.loads(content)
        deps = set()
        for section in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
            deps.update(data.get(section, {}).keys())
        return deps
    except (json.JSONDecodeError, AttributeError):
        return set()


def _extract_requirements_names(content: str) -> set:
    found = set()
    for m in _REQUIREMENTS_PATTERN.finditer(content):
        name = m.group(1).strip().lower()
        found.add(name)
        found.add(name.replace('_', '-'))
    return found


def _match_go(content: str) -> list:
    return [lib for lib in GO_AI_LIBRARIES if lib in content]


def _match_java(content: str) -> list:
    return [lib for lib in JAVA_AI_LIBRARIES if lib in content]


def _match_ruby(content: str) -> list:
    matched = []
    for gem in RUBY_AI_LIBRARIES:
        if re.search(rf'''(?:gem|require|require_relative|spec\.add_dependency)\s*\(?\s*['"]{re.escape(gem)}['"]''', content):
            matched.append(gem)
    return matched


def _match_rust_cargo(content: str) -> list:
    matched = []
    for crate in RUST_AI_LIBRARIES:
        if re.search(rf'^\s*"?{re.escape(crate)}"?\s*=', content, re.MULTILINE):
            matched.append(crate)
    return matched


def _match_rust_source(content: str) -> list:
    matched = []
    for crate in RUST_AI_LIBRARIES:
        underscored = crate.replace('-', '_')
        if re.search(rf'\b(?:use|extern\s+crate)\s+{re.escape(underscored)}\b', content):
            matched.append(crate)
    return matched


def scan_config_content(content: str) -> list:
    """Scan config-file text for AI indicators. Returns [(kind, indicator, note)]."""
    findings = []
    seen = set()
    for m in MODEL_NAME_RE.finditer(content):
        indicator = m.group(1).lower()
        if indicator not in seen:
            seen.add(indicator)
            findings.append((
                "model_name", indicator,
                f"AI model identifier '{indicator}' found in configuration — this AI usage may not appear in code imports",
            ))
    for endpoint, note in AI_ENDPOINTS.items():
        if endpoint in content and endpoint not in seen:
            seen.add(endpoint)
            findings.append(("api_endpoint", endpoint, note))
    for m in AI_ENV_KEY_RE.finditer(content):
        indicator = m.group(1)
        if indicator not in seen:
            seen.add(indicator)
            findings.append(("env_key", indicator, AI_ENV_KEYS[indicator]))
    return findings


def detect_file(path: str, content: str) -> tuple:
    """Detect AI usage in a single file.

    Returns (matched_libraries, config_findings) where config_findings is
    [(kind, indicator, note)] for config-type files, else [].
    """
    ftype = file_type(path)
    if ftype == 'package_json':
        return _match_js(_extract_package_json_deps(content)), []
    if ftype == 'js':
        return _match_js(_extract_js_imports(content)), []
    if ftype == 'py':
        return _match_py(_extract_py_imports(content)), []
    if ftype == 'requirements':
        return _match_py(_extract_requirements_names(content)), []
    if ftype == 'go':
        return _match_go(content), []
    if ftype == 'java':
        return _match_java(content), []
    if ftype == 'ruby':
        return _match_ruby(content), []
    if ftype == 'cargo':
        return _match_rust_cargo(content), []
    if ftype == 'rust':
        return _match_rust_source(content), []
    if ftype == 'config':
        return [], scan_config_content(content)
    return [], []


def scan_workspace(root: str) -> tuple:
    """Walk a local workspace and detect AI usage.

    Returns (library_files, config_hits):
      library_files: {library: [relative file paths]}
      config_hits:   {indicator: (kind, note, [relative file paths])}
    """
    library_files: dict = {}
    config_hits: dict = {}

    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            fpath = os.path.join(dirpath, fname)
            rel_path = os.path.relpath(fpath, root).replace("\\", "/")
            if file_type(rel_path) == 'other':
                continue
            try:
                if os.path.getsize(fpath) > MAX_FILE_BYTES:
                    continue
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            libs, config_findings = detect_file(rel_path, content)
            for lib in libs:
                library_files.setdefault(lib, [])
                if rel_path not in library_files[lib]:
                    library_files[lib].append(rel_path)
            for kind, indicator, note in config_findings:
                if indicator not in config_hits:
                    config_hits[indicator] = (kind, note, [])
                if rel_path not in config_hits[indicator][2]:
                    config_hits[indicator][2].append(rel_path)

    return library_files, config_hits
