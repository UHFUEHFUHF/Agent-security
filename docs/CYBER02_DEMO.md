# AgentShield CYBER-02 demo

## New endpoints
- `POST /api/v1/documents/analyze-invoice` — authenticated multipart upload (`file`) of a text-based PDF or UTF-8 text file. Extracts text and runs deterministic invoice/prompt-injection checks. Scanned PDFs need OCR, not included in this version.
- `POST /api/v1/evaluations/run` — authenticated multi-round evaluation. JSON body: `{"rounds": 4}` (1–10).
- Existing `POST /api/v1/scenarios/run` and `/batch` still work.

## Demo flow
1. Register/login and copy the bearer token.
2. Upload `examples/malicious_invoice.txt` to `/api/v1/documents/analyze-invoice`.
3. Observe `BLOCK`, flags, and `SIMULATED_ONLY` payment mode.
4. Run `/api/v1/evaluations/run` with `{"rounds": 8}` and show attack-block and legitimate-task-success metrics.
5. Inspect `/api/v1/audit` and `/api/v1/runs` for traceability.

All tools are synthetic. No real email is sent, no live browser is controlled, and no money moves. The browser tool is a mock browser search, not an Internet browser. Uploaded document contents are treated as untrusted data. Text extraction is capped at 5 MB and 30 pages for PDFs. Do not upload confidential or real customer documents for the demo.
