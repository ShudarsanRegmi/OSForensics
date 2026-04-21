## Feature List

1. Multi-source forensic analysis
- Analyze mounted filesystems or disk images
- Analyze live systems
- Analyze remote systems over SSH/SSHFS
- Case-based workflow with multiple sources per case

2. Core artifact detection
- Tool/process detection and risk classification
- Timeline reconstruction
- Deleted file detection and targeted recovery
- File carving by signature groups

3. Persistence and system abuse analysis
- Linux persistence mechanism checks
- Configuration security analysis
- Service enumeration and suspicious service detection
- Container/Kubernetes artifact analysis

4. Browser and multimedia forensics
- Browser profile artifacts (history, cookies, extensions, etc.)
- Multimedia metadata and suspicious media indicators
- Tails OS-specific artifact analysis (including deep scan paths)

5. Memory forensics (major module)
- Live RAM metrics and process analysis
- Memory dump ingestion + Volatility-based analysis
- Hidden process and malfind-style anomaly coverage
- Process tree, module/library, injection, handle, privilege, thread, credential, kernel, and memory timeline views
- AI-assisted memory report generation

6. AI-assisted investigation
- AI timeline analysis
- AI memory analysis (live + dump context)
- Agent/session workflows with memory/state management

7. Evidence governance / legal readiness
- Evidence integrity metadata (hashing, timestamps)
- Chain-of-custody structures
- Evidence provenance tracking
- Audit logging for case and analysis actions
- Legal disclaimer support in reports

8. Reporting and export
- Structured forensic report model
- Export to JSON, HTML, and PDF
- Executive/legal/comprehensive report variants
- Case-level aggregated reporting

9. Interactive desktop-like UI
- Home, Cases, Explorer, Report, Agent, and Memory views
- Autopsy-style filesystem explorer
- Rich tabbed artifact navigation with adaptive overflow handling
- Real-time/live scan status and actionable summaries

10. API-first architecture
- FastAPI endpoints for all major modules
- Upload-based and path-based analysis workflows
- Extensible service-oriented backend modules
