# poc_hunter

PoC/EXP collection pipeline for `ycdxsb/PocOrExp_in_Github`, scoped to CVE-2026 and later.

## Flow

1. Online host reads the upstream yearly CVE index from 2026 through the current year.
2. It selects README and high-signal PoC/EXP files from GitHub repositories.
3. It stores evidence files once under content-addressed blob paths in `data/outbox/<run_id>/evidence/blobs/`.
4. It writes lightweight task references to `data/outbox/<run_id>/tasks.jsonl`.
5. It creates a transferable archive in `data/transfer/poc_hunter_tasks_<run_id>.tar.gz`.
6. Online host pushes the archive to the transfer server with SFTP.
7. Offline host pulls archives from the transfer server with FTP. A remote archive is deleted after it is fully saved locally.
8. Offline host extracts packages, calls the internal OpenAI-compatible HTTP endpoint, strips `<think>` blocks, deduplicates parsed signatures, and imports rows into ClickHouse.

## ClickHouse Schema

Configured insert columns for `exploit_signature_distributed`:

```text
id
related_cve
vulnerability_name
url_signature
http_method
header_signature
body_signature
response_status
response_indicator
source
description
storage_time
```

Copy `configs/clickhouse_config.example.yaml` to `configs/clickhouse_config.yaml` before importing into ClickHouse.

## Online Commands

Build task packages from upstream 2026+ indexes:

```bash
python main.py build-tasks
```

Build a package for one supported year:

```bash
python main.py build-tasks --year 2026
```

Push the generated archive to a transfer host with SFTP:

```bash
python main.py sftp-push data/transfer/poc_hunter_tasks_<run_id>.tar.gz user@host:/remote/inbox/poc_hunter_tasks_<run_id>.tar.gz
```

## Offline Commands

Pull archives from the transfer host with FTP. Files are deleted from the FTP server after local save succeeds:

```bash
python main.py ftp-pull --host 10.0.0.10 --username user --password pass --remote-dir /remote/inbox
```

Process local inbox archives and write LLM results only:

```bash
set OFFLINE_LLM_BASE_URL=http://127.0.0.1:8000/v1
set OFFLINE_LLM_MODEL=minmax2.7
python main.py process-inbox
```

Process local inbox archives and import extractable rows into ClickHouse:

```bash
python main.py process-inbox --import-ck
```

`OFFLINE_LLM_CHAT_COMPLETIONS_URL` can be used when the endpoint is not `/v1/chat/completions`.

## Crontab Shape

Online host:

```cron
*/30 * * * * cd /opt/poc_hunter && ./scripts/online_collect_and_push.sh
```

Offline host:

```cron
*/30 * * * * cd /opt/poc_hunter && python main.py ftp-pull --host 10.0.0.10 --username user --password pass --remote-dir /remote/inbox && python main.py process-inbox --import-ck
```

The online wrapper should read `archive_path` from `python main.py build-tasks` output and call `sftp-push` only when `tasks_created > 0`.
