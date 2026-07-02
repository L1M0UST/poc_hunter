# poc_hunter

PoC/EXP collection pipeline for `ycdxsb/PocOrExp_in_Github`.

## Flow

1. Online host reads the upstream CVE index and GitHub repositories.
2. It selects README and high-signal PoC/EXP files, grouped by CVE.
3. It writes OpenAI-compatible LLM tasks to `data/outbox/<run_id>/tasks.jsonl`.
4. The task package is pushed to a transfer host with SFTP.
5. The offline host pulls the package, calls the internal OpenAI-compatible HTTP endpoint, strips `<think>` blocks, validates JSON, and imports extractable rows into ClickHouse.

## Commands

Show the configured ClickHouse insert columns:

```bash
python main.py schema
```

Copy `configs/clickhouse_config.example.yaml` to `configs/clickhouse_config.yaml` before importing into ClickHouse.

Build a task package from the existing local index:

```bash
python main.py build-tasks --from-output output/cve_poc_2025.json
```

Build a task package from the upstream year file:

```bash
python main.py build-tasks --year 2025
```

Push a package directory to a transfer host:

```bash
python main.py sftp-push data/outbox/<run_id> user@host:/path/inbox/<run_id>
```

Run extraction on the offline host:

```bash
set OFFLINE_LLM_BASE_URL=http://127.0.0.1:8000/v1
set OFFLINE_LLM_MODEL=minmax2.7
python main.py offline-extract data/outbox/<run_id>/tasks.jsonl data/outbox/<run_id>/results.jsonl
```

`OFFLINE_LLM_CHAT_COMPLETIONS_URL` can be used when the endpoint is not `/v1/chat/completions`.

Import extracted rows into ClickHouse:

```bash
python main.py ck-import data/outbox/<run_id>/results.jsonl
```
