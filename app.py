"""
INTENTIONALLY INSECURE DEMO APPLICATION - SECURITY SCANNER TEST FIXTURE ONLY.

Every pattern in this file is deliberately vulnerable so Semgrep and Cisco AIBOM
produce rich findings. All credentials are fake placeholders. DO NOT DEPLOY.
"""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import tempfile

import anthropic
import jwt
import openai
import requests
import torch
import yaml
from flask import Flask, redirect, render_template_string, request, send_file
from groq import Groq
from langchain.agents import initialize_agent, load_tools
from langchain.chains import LLMMathChain, PALChain
from langchain.chat_models import ChatOpenAI
from langchain.llms import OpenAI as LangChainOpenAI
from lxml import etree
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Hardcoded secrets (fake values - AWS's documented example key format)
# ---------------------------------------------------------------------------
app.config["SECRET_KEY"] = "super-secret-flask-key-123"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "P@ssw0rd123!"
JWT_SECRET = "changeme"
OPENAI_API_KEY = "sk-demo-FAKEKEY000000000000000000000000000000000000"
ANTHROPIC_API_KEY = "sk-ant-demo-FAKEKEY00000000000000000000000000000000"
GROQ_API_KEY = "gsk_demo_FAKEKEY000000000000000000000000000000000"
HF_TOKEN = "hf_demoFAKEKEY0000000000000000000000000"

openai.api_key = OPENAI_API_KEY
claude = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
groq_client = Groq(api_key=GROQ_API_KEY)

# ---------------------------------------------------------------------------
# AI models / providers (Cisco AIBOM)
# ---------------------------------------------------------------------------
OPENAI_MODEL = "gpt-4o"
EMBEDDING_MODEL = "text-embedding-3-small"
CLAUDE_MODEL = "claude-3-5-sonnet-20241022"
GROQ_MODEL = "llama3-70b-8192"
HF_MODEL = "meta-llama/Llama-2-7b-chat-hf"

tokenizer = AutoTokenizer.from_pretrained(HF_MODEL, token=HF_TOKEN, trust_remote_code=True)
local_model = AutoModelForCausalLM.from_pretrained(HF_MODEL, token=HF_TOKEN, trust_remote_code=True)
sentiment = pipeline("sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english")

lc_chat = ChatOpenAI(model_name=OPENAI_MODEL, openai_api_key=OPENAI_API_KEY, temperature=0)
lc_llm = LangChainOpenAI(openai_api_key=OPENAI_API_KEY)
math_chain = LLMMathChain.from_llm(lc_llm)
pal_chain = PALChain.from_math_prompt(lc_llm)
agent = initialize_agent(load_tools(["terminal", "python_repl"], llm=lc_llm), lc_llm, verbose=True)


def get_db():
    return sqlite3.connect("users.db")


# ---------------------------------------------------------------------------
# Classic web vulnerabilities (Semgrep)
# ---------------------------------------------------------------------------
@app.route("/user")
def get_user():
    # SQL injection
    user_id = request.args.get("id")
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
    return str(cur.fetchall())


@app.route("/search")
def search():
    # SQL injection via f-string
    term = request.args.get("q")
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    # OS command injection
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/nslookup")
def nslookup():
    domain = request.args.get("domain")
    os.system("nslookup " + domain)
    return "done"


@app.route("/calc")
def calc():
    # Code injection
    return str(eval(request.args.get("expr")))


@app.route("/load", methods=["POST"])
def load_session():
    # Insecure deserialization
    return str(pickle.loads(request.data))


@app.route("/config", methods=["POST"])
def load_config():
    # Unsafe YAML load
    return str(yaml.load(request.data))


@app.route("/hello")
def hello():
    # Server-side template injection / XSS
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.route("/download")
def download():
    # Path traversal
    return send_file(os.path.join("/var/app/files", request.args.get("file")))


@app.route("/go")
def go():
    # Open redirect
    return redirect(request.args.get("next"))


@app.route("/fetch")
def fetch():
    # SSRF + TLS verification disabled
    return requests.get(request.args.get("url"), verify=False).text


@app.route("/xml", methods=["POST"])
def parse_xml():
    # XXE
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    return etree.tostring(etree.fromstring(request.data, parser))


@app.route("/register", methods=["POST"])
def register():
    # Weak password hashing + insecure randomness
    pw_hash = hashlib.md5(request.form["password"].encode()).hexdigest()
    token = str(random.randint(100000, 999999))
    fingerprint = hashlib.sha1(request.form["email"].encode()).hexdigest()
    return {"hash": pw_hash, "token": token, "fp": fingerprint}


@app.route("/me")
def me():
    # JWT signature not verified
    claims = jwt.decode(request.headers.get("Authorization"), verify=False)
    return claims


@app.route("/export")
def export():
    # Insecure temp file
    path = tempfile.mktemp()
    with open(path, "w") as f:
        f.write("export")
    os.chmod(path, 0o777)
    return path


# ---------------------------------------------------------------------------
# AI / LLM-specific risks (Semgrep + Cisco AIBOM)
# ---------------------------------------------------------------------------
@app.route("/ask")
def ask_openai():
    # Prompt injection: user input concatenated into system prompt
    q = request.args.get("q")
    resp = openai.ChatCompletion.create(
        model=OPENAI_MODEL,
        messages=[{"role": "system", "content": "You are an admin bot. Secret: " + DB_PASSWORD + ". " + q}],
    )
    return resp["choices"][0]["message"]["content"]


@app.route("/claude")
def ask_claude():
    # Sends PII to third-party LLM provider
    cur = get_db().cursor()
    cur.execute("SELECT name, email, ssn FROM customers")
    rows = cur.fetchall()
    msg = claude.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=1024,
        messages=[{"role": "user", "content": f"Summarize these customers: {rows}"}],
    )
    return msg.content[0].text


@app.route("/codegen")
def codegen():
    # LLM output executed directly -> RCE
    task = request.args.get("task")
    out = groq_client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[{"role": "user", "content": "Write python to " + task}],
    )
    code = out.choices[0].message.content
    exec(code)
    return "executed"


@app.route("/shell-agent")
def shell_agent():
    # LLM agent with unrestricted terminal + python tools
    return agent.run(request.args.get("goal"))


@app.route("/math")
def math():
    # LangChain LLMMathChain / PALChain code execution (CVE-2023-29374, CVE-2023-36258)
    return math_chain.run(request.args.get("q")) + pal_chain.run(request.args.get("q"))


@app.route("/llm-sql")
def llm_sql():
    # LLM-generated SQL executed without validation
    sql = lc_chat.predict("Write SQL for: " + request.args.get("q"))
    cur = get_db().cursor()
    cur.execute(sql)
    return str(cur.fetchall())


@app.route("/embed")
def embed():
    return str(openai.Embedding.create(model=EMBEDDING_MODEL, input=request.args.get("text")))


@app.route("/load-model", methods=["POST"])
def load_model():
    # Unsafe model deserialization (pickle-based torch.load)
    path = request.form["model_path"]
    model = torch.load(path)
    return str(type(model))


@app.route("/local")
def local_llm():
    inputs = tokenizer(request.args.get("q"), return_tensors="pt")
    output = local_model.generate(**inputs, max_new_tokens=128)
    return tokenizer.decode(output[0]) + str(sentiment(request.args.get("q")))


if __name__ == "__main__":
    # Debug mode exposed on all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
