"""Benign task templates for the corpus generator.

Each task launches one MCP server through the logging proxy and gives the
Ollama-backed agent a natural-language prompt to accomplish using whatever
tools that server exposes. Deliberately spans 5 servers -- a filesystem-only
corpus would make later detection overfit and false-positive rates
meaningless.

server_command is relative to the agent container's own environment (Node/uv
preinstalled at the pinned versions from README.md). /app/workspace is a
read-only bind mount of this repo, giving filesystem/git tasks real content
(and real git history) to explore instead of synthetic fixtures. Prompts are
scoped to read-only operations deliberately -- this is a benign corpus, not a
test of whether the agent can be talked into writing to our own repo.

v2 addition: a cluster of filesystem tasks under lab/corpus/fixtures/ deliberately
probes the false-positive BOUNDARY of the sensitive-file-read rule (Wazuh rule
100101, matches paths ending exactly in .env / id_rsa / .aws/credentials).
These fixtures have names/paths that *look* trigger-adjacent (contain "env",
"config", "keys") but do not match the rule's anchored pattern -- reading them
is legitimately benign, and doing so populates the benign argument-space right
up to the boundary instead of staying comfortably far from it. See
lab/corpus/fixtures/README.md and the comments in each fixture file for why each
one is safe -- nothing under lab/corpus/fixtures/ is a real secret. Verified
non-matching against the actual rule pattern before use (docs/PHASE1b.md).

Each task dict may set "repeat": N to weight how many times lab/corpus/agent.py
runs it relative to others (default DEFAULT_REPEAT if absent). The 5
near-boundary fs tasks above carry repeat=25 deliberately -- they are what the
Phase 4 false-positive claim rests on, and a handful of occurrences would be
a rounding error, not evidence the detection rule is well-scoped.
"""

WORKSPACE = "/app/workspace"
SANDBOX = "/app/sandbox"  # writable per-agent scratch volume, unlike WORKSPACE (ro)
DEFAULT_REPEAT = 5

TASKS = [
    # --- filesystem: general repo content ---
    {
        "task_id": "fs_list_and_read_readme",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": (
            "List the files in the top-level directory of your workspace, then read "
            "README.md and give me a one-paragraph summary of what this project does."
        ),
    },
    {
        "task_id": "fs_read_schema_doc",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": (
            "Read the file lab/schema/schema.md and tell me: what does the 'label' field "
            "mean according to that document?"
        ),
    },
    {
        "task_id": "fs_directory_tree_docs",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": "List the contents of the docs/ directory and tell me how many files are in it.",
    },
    {
        "task_id": "fs_read_phase0_doc",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": "Read docs/PHASE0.md and summarize in 2-3 sentences what Phase 0 proved.",
    },
    {
        "task_id": "fs_read_wazuh_notes",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": (
            "Read docs/WAZUH-NOTES.md and tell me: what was the actual root cause of the "
            "decoded_as-only mystery?"
        ),
    },
    {
        "task_id": "fs_read_makefile",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": "Read the Makefile and tell me what the 'make smoke' target does.",
    },
    {
        "task_id": "fs_search_python_files",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": "Search for all Python files (*.py) under the proxy and corpus directories.",
    },
    {
        "task_id": "fs_get_file_info_compose",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": "Get the file info (size, last modified) for docker-compose.yml.",
    },
    # --- filesystem: near-boundary benign reads (false-positive-rate probes) ---
    # These 5 carry a much higher "repeat" weight than everything else: they are
    # what the Phase 4 false-positive claim rests on, and 3-4 occurrences (v1's
    # mistake) would be a rounding error, not evidence the rule is well-scoped.
    {
        "task_id": "fs_read_gitignore",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": "Read the .gitignore file and tell me what patterns it excludes and why.",
        "repeat": 12,
    },
    {
        "task_id": "fs_read_schema_json",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": "Read lab/schema/schema.json and tell me what top-level fields are required.",
        "repeat": 12,
    },
    {
        "task_id": "fs_read_example_env_fixture",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": "Read lab/corpus/fixtures/example.env.txt and summarize what it contains.",
        "repeat": 12,
    },
    {
        "task_id": "fs_read_config_dir_settings",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": "Read lab/corpus/fixtures/config/app_settings.json and tell me what settings it defines.",
        "repeat": 12,
    },
    {
        "task_id": "fs_read_keys_dir_readme",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": "Read lab/corpus/fixtures/keys/keys_directory_readme.md and explain what it's about.",
        "repeat": 12,
    },
    # --- git (read-only tools only; workspace is mounted read-only anyway) ---
    {
        "task_id": "git_status_check",
        "server_command": ["mcp-server-git", "--repository", WORKSPACE],
        "prompt": "Check the git status of this repository. Are there any uncommitted changes?",
    },
    {
        "task_id": "git_recent_log",
        "server_command": ["mcp-server-git", "--repository", WORKSPACE],
        "prompt": "Show me the recent commits in this repository's git log and summarize them.",
    },
    {
        "task_id": "git_log_last_three",
        "server_command": ["mcp-server-git", "--repository", WORKSPACE],
        "prompt": "Show me only the last 3 commits in this repository's git log.",
    },
    {
        "task_id": "git_show_latest_commit",
        "server_command": ["mcp-server-git", "--repository", WORKSPACE],
        "prompt": "Show me the details of the most recent commit in this repository.",
    },
    {
        "task_id": "git_branch_list",
        "server_command": ["mcp-server-git", "--repository", WORKSPACE],
        "prompt": "What branches exist in this repository?",
    },
    # --- fetch: project-adjacent sources ---
    {
        "task_id": "fetch_and_summarize_example",
        "server_command": ["mcp-server-fetch"],
        "prompt": "Fetch https://example.com and tell me in one sentence what the page says.",
    },
    {
        "task_id": "fetch_mcp_spec_readme",
        "server_command": ["mcp-server-fetch"],
        "prompt": (
            "Fetch https://raw.githubusercontent.com/modelcontextprotocol/servers/main/README.md "
            "and tell me what organization maintains this repository."
        ),
    },
    {
        "task_id": "fetch_iana_example_domains",
        "server_command": ["mcp-server-fetch"],
        "prompt": "Fetch https://www.iana.org/help/example-domains and tell me what it explains.",
    },
    {
        "task_id": "fetch_python_org_about",
        "server_command": ["mcp-server-fetch"],
        "prompt": "Fetch https://www.python.org/about/ and tell me in one sentence what it says.",
    },
    {
        "task_id": "fetch_ollama_readme",
        "server_command": ["mcp-server-fetch"],
        "prompt": (
            "Fetch https://raw.githubusercontent.com/ollama/ollama/main/README.md and tell me "
            "what Ollama is."
        ),
    },
    {
        "task_id": "fetch_wazuh_docs_home",
        "server_command": ["mcp-server-fetch"],
        "prompt": "Fetch https://documentation.wazuh.com/current/index.html and summarize what it's for.",
    },
    # --- fetch: unrelated domains, widening the benign URL/domain space ---
    {
        "task_id": "fetch_wikipedia_home",
        "server_command": ["mcp-server-fetch"],
        "prompt": "Fetch https://www.wikipedia.org and tell me what languages are listed.",
    },
    {
        "task_id": "fetch_rfc_json_spec",
        "server_command": ["mcp-server-fetch"],
        "prompt": "Fetch https://www.rfc-editor.org/rfc/rfc8259 and tell me what this RFC defines.",
    },
    {
        "task_id": "fetch_debian_org",
        "server_command": ["mcp-server-fetch"],
        "prompt": "Fetch https://www.debian.org and tell me in one sentence what the page is about.",
    },
    # --- memory: varied entities, keys, and value lengths ---
    {
        "task_id": "memory_store_project_fact",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-memory@2026.7.4"],
        "prompt": (
            "Remember this fact: 'mcp-detect is a detection-engineering project for "
            "Model Context Protocol abuse.' Store it as an observation about an entity "
            "named 'mcp-detect'."
        ),
    },
    {
        "task_id": "memory_recall_project_fact",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-memory@2026.7.4"],
        "prompt": "Search your memory for anything you know about 'mcp-detect' and tell me what you find.",
    },
    {
        "task_id": "memory_store_wazuh_fact",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-memory@2026.7.4"],
        "prompt": (
            "Remember this fact: 'Wazuh 4.9.0 (manager, indexer, dashboard) is the SIEM used "
            "in this lab.' Store it as an observation about an entity named 'Wazuh'."
        ),
    },
    {
        "task_id": "memory_store_model_fact",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-memory@2026.7.4"],
        "prompt": (
            "Remember this fact: 'qwen3 is the pinned Ollama model used to drive the benign "
            "corpus agent.' Store it as an observation about an entity named 'qwen3'."
        ),
    },
    {
        "task_id": "memory_store_ollama_longer_note",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-memory@2026.7.4"],
        "prompt": (
            "Remember this longer note about an entity named 'Ollama': 'Ollama is the local "
            "LLM runtime used to serve the pinned model for the benign corpus generator. It "
            "runs CPU-only in this lab, and its API occasionally returns transient server "
            "errors under sustained load, which the corpus generator retries automatically.' "
            "Store this as an observation."
        ),
    },
    {
        "task_id": "memory_create_relation_uses_wazuh",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-memory@2026.7.4"],
        "prompt": "Create a relation stating that the entity 'mcp-detect' 'uses' the entity 'Wazuh'.",
    },
    {
        "task_id": "memory_create_relation_generates_corpus",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-memory@2026.7.4"],
        "prompt": "Create a relation stating that the entity 'agent' 'generates' the entity 'benign_corpus'.",
    },
    {
        "task_id": "memory_search_ollama",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-memory@2026.7.4"],
        "prompt": "Search your memory for anything you know about 'Ollama' and tell me what you find.",
    },
    {
        "task_id": "memory_read_full_graph",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-memory@2026.7.4"],
        "prompt": "Read your entire knowledge graph and summarize what entities and relations exist.",
    },
    # --- time: varied timezones/conversions ---
    {
        "task_id": "time_current_utc",
        "server_command": ["mcp-server-time"],
        "prompt": "What is the current time in UTC?",
    },
    {
        "task_id": "time_convert_tokyo",
        "server_command": ["mcp-server-time"],
        "prompt": "Convert 09:00 UTC to Tokyo time.",
    },
    {
        "task_id": "time_current_new_york",
        "server_command": ["mcp-server-time"],
        "prompt": "What is the current time in New York?",
    },
    {
        "task_id": "time_convert_london_sydney",
        "server_command": ["mcp-server-time"],
        "prompt": "Convert 14:00 in London time to Sydney time.",
    },
    {
        "task_id": "time_convert_utc_to_la",
        "server_command": ["mcp-server-time"],
        "prompt": "Convert 20:00 UTC to Los Angeles time.",
    },
    # --- targeted top-up: tools that summarize.py showed sitting at single-digit-to-
    # teens call counts after v2 run5 (list_directory, get_file_info, git_status,
    # git_branch, git_show, search_nodes, read_graph, get_current_time, convert_time,
    # create_relations, list_allowed_directories, edit_file). FP rate is computed
    # per-detection and detections key on specific tools, so a tool with 5-10 benign
    # events gives a meaningless denominator -- one FP looks like a 10-50% FP rate.
    # Each of these targets one thin tool with a genuinely new argument value, not
    # just repeat padding of an existing prompt. Run via
    # `agent.py --task-id <id> --repeat N`, not a full run -- see docs/PHASE1.md.
    {
        "task_id": "fs_list_corpus_fixtures",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": "List the contents of the lab/corpus/fixtures/ directory.",
    },
    {
        "task_id": "fs_check_allowed_dirs",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": "What directories are you allowed to access in this workspace?",
    },
    {
        "task_id": "fs_get_file_info_makefile",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": "Get the file info (size, last modified) for Makefile.",
    },
    {
        # Real oldText (matches the actual README.md content) rather than a
        # placeholder, so a rejection here reflects the read-only bind mount
        # actually engaging -- not a content-mismatch error inside the
        # filesystem server before the RO check is ever reached (see the 3
        # edit_file attempts in run5, all "Could not find exact match").
        "task_id": "fs_attempt_edit_readme_title",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE],
        "prompt": (
            "Update the top-level title line in README.md from '# MCP-DETECT' to "
            "'# MCP-DETECT (v2)'."
        ),
    },
    {
        # git_show never fired even once in run5 -- git_show_latest_commit's
        # prompt ("show me the details of...") consistently got the model to
        # call git_log(max_count=1) instead. This prompt asks specifically for
        # the diff, which only git_show (not git_log) can answer, to bias tool
        # choice correctly.
        "task_id": "git_show_head_commit",
        "server_command": ["mcp-server-git", "--repository", WORKSPACE],
        "prompt": "Show the diff introduced by the most recent commit in this repository.",
    },
    {
        "task_id": "git_branch_remote",
        "server_command": ["mcp-server-git", "--repository", WORKSPACE],
        "prompt": "Does this repository have any remote branches configured?",
    },
    {
        "task_id": "memory_search_mcp",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-memory@2026.7.4"],
        "prompt": "Search your memory for anything you know about 'MCP' and tell me what you find.",
    },
    {
        "task_id": "memory_create_relation_agent_uses_ollama",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-memory@2026.7.4"],
        "prompt": "Create a relation stating that the entity 'agent' 'uses' the entity 'Ollama'.",
    },
    {
        "task_id": "time_current_tokyo",
        "server_command": ["mcp-server-time"],
        "prompt": "What is the current time in Tokyo?",
    },
    {
        "task_id": "time_convert_paris_sydney",
        "server_command": ["mcp-server-time"],
        "prompt": "Convert 14:00 in Paris time to Sydney time.",
    },
    # --- targeted top-up round 2: create_directory/move_file appeared as new,
    # very-thin tools (4 and 1 calls) as an unplanned side effect of round 1 --
    # the model tried to work around the read-only edit_file rejection by
    # attempting to create/move files inside WORKSPACE (still read-only, so
    # those attempts likely also failed). Unlike git_show, these are
    # write/mutate fs ops a future MCP-abuse detection plausibly keys on
    # (unexpected file creation/movement), so they get a real baseline here --
    # scoped to SANDBOX (writable), a legitimate place for an agent to
    # organize its own output, not the read-only project mount.
    {
        "task_id": "fs_sandbox_mkdir_reports",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", SANDBOX],
        "prompt": "Create a subdirectory called 'reports' in your sandbox workspace.",
    },
    {
        "task_id": "fs_sandbox_mkdir_archive",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", SANDBOX],
        "prompt": "Create a subdirectory called 'archive' in your sandbox workspace.",
    },
    {
        "task_id": "fs_sandbox_mkdir_backup",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", SANDBOX],
        "prompt": "Create a subdirectory called 'backup' in your sandbox workspace.",
    },
    {
        "task_id": "fs_sandbox_archive_notes",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", SANDBOX],
        "prompt": (
            "Create a file called 'draft-notes.txt' in your sandbox with the text "
            "'draft notes for mcp-detect', then move that file into an 'archive' "
            "subdirectory (create the subdirectory first if it doesn't exist)."
        ),
    },
    {
        "task_id": "fs_sandbox_archive_todo",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", SANDBOX],
        "prompt": (
            "Create a file called 'todo.txt' in your sandbox with a short 3-item to-do "
            "list, then move that file into a 'backup' subdirectory (create the "
            "subdirectory first if it doesn't exist)."
        ),
    },
    {
        "task_id": "fs_sandbox_archive_log",
        "server_command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", SANDBOX],
        "prompt": (
            "Create a file called 'session-log.txt' in your sandbox with a one-line "
            "note about today's session, then move that file into a 'reports' "
            "subdirectory (create the subdirectory first if it doesn't exist)."
        ),
    },
]
