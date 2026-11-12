"""Rebuild ai_tool_vulnerabilities.csv from the GitHub Advisory Database."""
import csv, json, sys, tarfile, urllib.request

START = "2023-01-01"
URL = "https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main"

# (ecosystem, package) -> tool name
TOOLS = {
    ("PyPI", "langchain"): "LangChain", ("PyPI", "langchain-core"): "LangChain",
    ("PyPI", "langchain-community"): "LangChain", ("PyPI", "langchain-experimental"): "LangChain",
    ("PyPI", "langchain-openai"): "LangChain", ("npm", "langchain"): "LangChain",
    ("npm", "@langchain/core"): "LangChain",
    ("PyPI", "llama-index"): "LlamaIndex", ("PyPI", "llama-index-core"): "LlamaIndex",
    ("PyPI", "llama-index-cli"): "LlamaIndex",
    ("PyPI", "gradio"): "Gradio", ("PyPI", "mlflow"): "MLflow", ("PyPI", "vllm"): "vLLM",
    ("PyPI", "ray"): "Ray", ("PyPI", "open-webui"): "Open WebUI", ("PyPI", "litellm"): "LiteLLM",
    ("PyPI", "bentoml"): "BentoML", ("PyPI", "haystack-ai"): "Haystack", ("PyPI", "sglang"): "SGLang",
    ("PyPI", "langflow"): "Langflow", ("npm", "flowise"): "Flowise",
    ("Go", "github.com/ollama/ollama"): "Ollama", ("PyPI", "transformers"): "Transformers",
    ("PyPI", "lmdeploy"): "LMDeploy", ("PyPI", "semantic-kernel"): "Semantic Kernel",
}

# CWE -> plain-language flaw type (first match in ORDER wins)
GROUPS = {
    "Run an attacker's code": "94 77 78 502 95 1336 913 917 74 88",
    "Read or write files they shouldn't": "22 23 73 59 434 36 29 24",
    "Make the server reach other systems": "918",
    "Weak or missing access control": "284 285 862 863 287 306 639 269 266 352 1220 288 290 613 620 640 345 346 668 732 276 280",
    "Inject scripts into web pages": "79 80 116 1021 601",
    "Leak sensitive data": "200 532 209 312 319 522 798 359 201 538 214 497",
    "Crash or overload the service": "400 770 1333 674 834 835 20 1284 789 369 190",
}
ORDER = ["Run an attacker's code", "Read or write files they shouldn't",
         "Make the server reach other systems", "Weak or missing access control",
         "Leak sensitive data", "Inject scripts into web pages", "Crash or overload the service"]
CWE = {f"CWE-{c}": g for g, cs in GROUPS.items() for c in cs.split()}


def flaw_type(cwes):
    found = {CWE.get(c) for c in cwes}
    return next((g for g in ORDER if g in found), "Other")


def main(out="2ai_tool_vulnerabilities.csv"):
    needles = [name.encode() for _, name in TOOLS]
    rows = []
    with urllib.request.urlopen(URL) as resp, tarfile.open(fileobj=resp, mode="r|gz") as tar:
        for m in tar:
            if not (m.isfile() and "/github-reviewed/" in m.name and m.name.endswith(".json")):
                continue
            raw = tar.extractfile(m).read()
            if not any(n in raw for n in needles):
                continue
            a = json.loads(raw)
            if a.get("withdrawn") or a["published"][:10] < START:
                continue
            tools = sorted({TOOLS[k] for k in
                            ((x["package"]["ecosystem"], x["package"]["name"]) for x in a.get("affected", []))
                            if k in TOOLS})
            if not tools:
                continue
            ds = a.get("database_specific") or {}
            cwes = ds.get("cwe_ids", [])
            rows.append({
                "GHSA ID": a["id"],
                "CVE": ",".join(x for x in a.get("aliases", []) if x.startswith("CVE")),
                "AI tool": ";".join(tools),
                "Published": a["published"][:10],
                "Severity": (ds.get("severity") or "").title(),
                "Flaw type": flaw_type(cwes),
                "CWE IDs": ",".join(cwes),
                "Summary": (a.get("summary") or "").strip(),
                "Link": f"https://github.com/advisories/{a['id']}",
            })
    rows.sort(key=lambda r: (r["Published"], r["GHSA ID"]))
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} advisories written to {out}")


if __name__ == "__main__":
    main(*sys.argv[1:])
