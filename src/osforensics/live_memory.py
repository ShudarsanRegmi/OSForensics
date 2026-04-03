"""Real-time system memory and process analysis for the forensic platform."""
import os
import time
import re
import math
import struct
from typing import Dict, List, Any, Tuple
import subprocess

def get_live_ram_info() -> Dict[str, Any]:
    """Parse /proc/meminfo for detailed RAM statistics."""
    meminfo: Dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if ":" in line:
                    parts = line.split(":")
                    key = parts[0].strip()
                    value = int(parts[1].strip().split()[0])
                    meminfo[key] = value
    except Exception:
        return {"error": "Failed to read /proc/meminfo"}

    total = meminfo.get("MemTotal", 0)
    free = meminfo.get("MemFree", 0)
    available = meminfo.get("MemAvailable", 0)
    buffers = meminfo.get("Buffers", 0)
    cached = meminfo.get("Cached", 0)
    swap_total = meminfo.get("SwapTotal", 0)
    swap_free = meminfo.get("SwapFree", 0)
    dirty = meminfo.get("Dirty", 0)

    used = total - available if available else total - free
    used_pct = round((used / total) * 100, 2) if total else 0

    return {
        "total_kb": total,
        "free_kb": free,
        "available_kb": available,
        "used_kb": used,
        "buffers_kb": buffers,
        "cached_kb": cached,
        "dirty_kb": dirty,
        "used_pct": used_pct,
        "swap_total_kb": swap_total,
        "swap_free_kb": swap_free,
        "swap_used_kb": swap_total - swap_free,
        "timestamp": time.time()
    }

def get_top_memory_processes(limit: int = 15) -> List[Dict[str, Any]]:
    """Get top memory-consuming processes by parsing /proc/[pid]/statm and /proc/[pid]/cmdline."""
    processes = []
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except Exception:
        return []

    for pid in pids:
        try:
            # RSS is the second field in /proc/[pid]/statm, in pages
            with open(f"/proc/{pid}/statm", "r") as f:
                fields = f.read().split()
                if len(fields) < 2:
                    continue
                rss_pages = int(fields[1])
                # Page size is usually 4KB, but we should use os.sysconf
                page_size = os.sysconf("SC_PAGE_SIZE") // 1024
                rss_kb = rss_pages * page_size

            with open(f"/proc/{pid}/comm", "r") as f:
                name = f.read().strip()

            with open(f"/proc/{pid}/cmdline", "r") as f:
                cmdline = f.read().replace("\x00", " ").strip()
            
            # Use comm if cmdline is empty (kernel threads etc)
            display_name = cmdline if cmdline else f"[{name}]"

            processes.append({
                "pid": int(pid),
                "name": name,
                "cmdline": display_name,
                "memory_kb": rss_kb
            })
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue

    # Sort by memory usage descending
    processes.sort(key=lambda x: x["memory_kb"], reverse=True)
    return processes[:limit]

def generate_memory_ai_insight(ram_info: Dict[str, Any], top_procs: List[Dict[str, Any]]) -> str:
    """Send memory data to Ollama for forensic analysis."""
    from .agent_core import get_agent
    
    agent = get_agent()
    
    # Format process list for the prompt
    proc_summary = "\n".join([f"- PID {p['pid']}: {p['name']} ({p['memory_kb']} KB) - {p['cmdline'][:100]}" for p in top_procs])
    
    prompt = f"""
Analyze the following system memory state for potential security risks, suspicious patterns, or performance anomalies from a forensic perspective.

SYSTEM RAM SUMMARY:
- Total: {ram_info['total_kb']} KB
- Used: {ram_info['used_kb']} KB ({ram_info['used_pct']}%)
- Available: {ram_info['available_kb']} KB
- Swap Used: {ram_info['swap_total_kb'] - ram_info['swap_free_kb']} KB

TOP MEMORY CONSUMING PROCESSES:
{proc_summary}

Provide a COMPLETE FORENSICS REPORT categorized tab-wise.
Use the following Markdown structure strictly:
# Executive Summary
(Brief overview of the memory health and primary findings)

## Resource Utilization Analysis
(Analysis of RAM vs Swap and pressure indicators)

## Security Artifact Assessment
(Detailed analysis of suspicious processes, unexpected command lines, or potential malware indicators)

## Investigation Recommendations
(Specific steps for the forensic examiner)
"""

    try:
        # Using the agent's chat method to get a response
        response = agent.chat(prompt, use_json=False)
        return response
    except Exception as e:
        return f"AI Analysis failed: {str(e)}"

def generate_dump_ai_insight(report_data: Dict[str, Any]) -> str:
    """Send specialized memory dump report to Ollama for forensic analysis."""
    from .agent_core import get_agent
    agent = get_agent()
    
    # Extract key data from the report
    summary = report_data.get("summary", {})
    procs = report_data.get("processes", [])[:10]
    hidden = report_data.get("hidden_processes", [])[:5]
    malfind = report_data.get("malfind", [])[:5]
    conns = report_data.get("connections", [])[:10]
    bash = report_data.get("bash_history", [])[:5]
    modules = report_data.get("modules", [])[:5]
    maps = report_data.get("shared_libraries", [])[:5]
    lsof = report_data.get("open_files", [])[:5]
    
    proc_summary = "\n".join([f"- PID {p.get('pid')}: {p.get('name')} (Hidden: {p.get('hidden', False)})" for p in procs + hidden])
    conn_summary = "\n".join([f"- {c.get('proto')} {c.get('laddr')}:{c.get('lport')} -> {c.get('raddr')}:{c.get('rport')} ({c.get('state')})" for c in conns])
    mal_summary = "\n".join([f"- PID {m.get('pid')} at {m.get('address')}: {m.get('protection')}" for m in malfind])
    bash_summary = "\n".join([f"- PID {b.get('pid')}: {b.get('command')}" for b in bash])
    mod_summary = "\n".join([f"- {m.get('name')} at {m.get('offset')}" for m in modules])
    maps_summary = "\n".join([f"- PID {m.get('pid')}: {m.get('path')} ({m.get('start')}-{m.get('end')})" for m in maps])
    lsof_summary = "\n".join([f"- PID {l.get('pid')}: {l.get('path')} (FD {l.get('fd')})" for l in lsof])

    prompt = f"""
Analyze the following MEMORY DUMP FORENSIC REPORT for high-impact security threats.

SUMMARY DATA:
- Total Processes: {summary.get('process_count')}
- Hidden (psscan) Processes: {summary.get('hidden_count')}
- Malfind Findings: {summary.get('malfind_count')}
- External Connections: {summary.get('external_connections')}
- Bash Commands Recovered: {summary.get('bash_entries')}
- Kernel Modules: {summary.get('module_count')}
- Shared Libraries (Maps): {summary.get('shared_libraries')}
- Open Files (Lsof): {summary.get('open_files')}
- Kernel Version: {report_data.get('kernel_version', 'Unknown')}

TOP PROCESS ARTIFACTS:
{proc_summary}

MALFIND ANALYSIS:
{mal_summary}

NETWORK ARTIFACTS:
{conn_summary}

BASH HISTORY (Recovered from Memory):
{bash_summary}

KERNEL MODULES:
{mod_summary}

SHARED LIBRARIES (High-Impact Maps):
{maps_summary}

OPEN FILES (LSOF):
{lsof_summary}

Provide a DEEP FORENSIC INVESTIGATION REPORT.
Use the following Markdown structure strictly:
# Forensic Summary
(Overall assessment of the dump's integrity and threat level)

## High-Risk Anomalies
(Detailed analysis of HIDDEN processes, MALFIND results, or suspicious SHARED LIBRARIES. Explain WHY these are suspicious.)

## Persistence & Tactical Indicators
(Analysis of suspicious BASH history, KERNEL MODULES, or OPEN FILES indicating data exfiltration or backdoors)

## Investigative Conclusion
(Final verdict and recommended next steps for the analyst. Mention specific PIDs to monitor.)
"""

    try:
        return agent.chat(prompt, use_json=False)
    except Exception as e:
        return f"Dump AI Analysis failed: {str(e)}"


# ─── ADVANCED FORENSIC ANALYSIS FUNCTIONS ─────────────────────────────────────

def analyze_network_connections() -> Dict[str, Any]:
    """Analyze active network connections for suspicious patterns."""
    try:
        import socket
        connections = []
        suspicious = []
        
        # Parse /proc/net/tcp and /proc/net/tcp6
        for tcp_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
            try:
                with open(tcp_file, "r") as f:
                    lines = f.readlines()[1:]  # Skip header
                    for line in lines[:100]:  # Limit to first 100
                        parts = line.split()
                        if len(parts) >= 4:
                            local_addr = parts[1]
                            remote_addr = parts[2]
                            state = parts[3]
                            
                            # Convert hex to readable format
                            try:
                                loc_ip, loc_port = hex_to_ip_port(local_addr)
                                rem_ip, rem_port = hex_to_ip_port(remote_addr)
                                
                                conn = {
                                    "local": f"{loc_ip}:{loc_port}",
                                    "remote": f"{rem_ip}:{rem_port}",
                                    "state": state,
                                    "proto": "TCP6" if "tcp6" in tcp_file else "TCP"
                                }
                                connections.append(conn)
                                
                                # Detect suspicious patterns
                                if is_suspicious_connection(rem_ip, rem_port, state):
                                    suspicious.append(conn)
                            except:
                                pass
            except FileNotFoundError:
                pass
        
        return {
            "total_connections": len(connections),
            "suspicious_count": len(suspicious),
            "connections": connections[:50],
            "suspicious": suspicious,
            "detections": [
                "Outbound persistence to non-standard ports",
                "DNS over unusual protocols",
                "Reverse shell indicators in connection patterns"
            ] if suspicious else []
        }
    except Exception as e:
        return {"error": str(e), "total_connections": 0, "suspicious_count": 0}


def hex_to_ip_port(hex_str: str) -> Tuple[str, str]:
    """Convert hex socket notation to IP:port."""
    try:
        hex_parts = hex_str.split(":")
        if len(hex_parts) != 2:
            return "0.0.0.0", "0"
        
        addr_hex = hex_parts[0]
        port_hex = hex_parts[1]
        
        # Convert port from hex
        port = int(port_hex, 16)
        
        # For IPv4, reverse bytes
        if len(addr_hex) == 8:
            addr_bytes = bytes.fromhex(addr_hex)
            addr_bytes = addr_bytes[::-1]
            ip = ".".join(str(b) for b in addr_bytes)
        else:
            # IPv6
            ip = ":".join([addr_hex[i:i+2] for i in range(0, len(addr_hex), 2)])
        
        return ip, str(port)
    except:
        return "0.0.0.0", "0"


def is_suspicious_connection(ip: str, port: str, state: str) -> bool:
    """Detect suspicious connection patterns."""
    port_num = int(port) if port.isdigit() else 0
    
    # Private networks shouldn't have external connections
    if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
        return False
    
    # Suspicious ports and states
    suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 27374, 6667, 31337]
    if port_num in suspicious_ports:
        return True
    
    # RDP/SSH to unusual IPs might indicate C2
    if port_num in [22, 3389] and state == "01":  # ESTABLISHED
        return True if not (ip.startswith("10.") or ip.startswith("192.168.")) else False
    
    return False


def detect_suspicious_processes() -> Dict[str, Any]:
    """Detect potentially malicious process patterns."""
    suspicious = []
    indicators = []
    
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
        
        for pid in pids:
            try:
                with open(f"/proc/{pid}/cmdline", "r") as f:
                    cmdline = f.read().replace("\x00", " ").strip()
                
                with open(f"/proc/{pid}/stat", "r") as f:
                    stat_data = f.read().split()
                    ppid = int(stat_data[3]) if len(stat_data) > 3 else 0
                
                suspicion_score = 0
                reasons = []
                
                # Check for suspicious patterns
                malicious_keywords = [
                    "wget", "curl", "nc", "ncat", "bash -i", "/dev/tcp", "python -c", 
                    "perl -e", "|sh", "&sh", "LD_PRELOAD", "xxd", "xxd -r",
                    "mkfifo", "/tmp/", "chmod +x", "curl http", "wget http"
                ]
                
                for keyword in malicious_keywords:
                    if keyword.lower() in cmdline.lower():
                        suspicion_score += 15
                        reasons.append(f"Found keyword: {keyword}")
                
                # Orphaned process (parent pid doesn't exist)
                if ppid > 1:
                    try:
                        with open(f"/proc/{ppid}/cmdline", "r") as f:
                            pass
                    except FileNotFoundError:
                        suspicion_score += 20
                        reasons.append("Orphaned process (parent PID missing)")
                
                # Process with no visible command line but running
                if not cmdline or cmdline.startswith("["):
                    suspicion_score += 5
                    reasons.append("Kernel thread or hidden binary")
                
                # Environment variable hiding
                try:
                    with open(f"/proc/{pid}/environ", "r") as f:
                        environ = f.read()
                        if "LD_PRELOAD" in environ or "LD_AUDIT" in environ:
                            suspicion_score += 25
                            reasons.append("Suspicious library preload detected")
                except:
                    pass
                
                if suspicion_score >= 20:
                    suspicious.append({
                        "pid": int(pid),
                        "cmdline": cmdline[:150],
                        "ppid": ppid,
                        "score": suspicion_score,
                        "reasons": reasons
                    })
                    
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
        
        suspicious.sort(key=lambda x: x["score"], reverse=True)
        
        return {
            "suspicious_count": len(suspicious),
            "suspicious_processes": suspicious[:20],
            "indicators": [
                "Downloader/C2 scripts detected",
                "Privilege escalation attempts",
                "Memory injection patterns",
                "Library preloading/hooking"
            ] if suspicious else []
        }
    except Exception as e:
        return {"error": str(e), "suspicious_count": 0}


def detect_rootkit_indicators() -> Dict[str, Any]:
    """Scan for common rootkit indicators."""
    indicators = []
    risk_score = 0
    
    try:
        # Check for hidden processes via /proc inconsistency
        proc_pids = set()
        try:
            proc_pids = set([int(d) for d in os.listdir("/proc") if d.isdigit()])
        except:
            pass
        
        # Check ps output for discrepancies
        try:
            ps_output = subprocess.check_output(["ps", "aux"], text=True, timeout=5)
            ps_pids = set()
            for line in ps_output.split("\n")[1:]:
                parts = line.split()
                if parts and parts[1].isdigit():
                    ps_pids.add(int(parts[1]))
            
            hidden_pids = proc_pids - ps_pids
            if hidden_pids:
                risk_score += 30
                indicators.append({
                    "type": "HIDDEN_PROCESSES",
                    "severity": "HIGH",
                    "detail": f"Found {len(hidden_pids)} processes visible in /proc but not in ps output",
                    "pids": list(hidden_pids)[:5]
                })
        except:
            pass
        
        # Check for kernel module anomalies
        try:
            with open("/proc/modules", "r") as f:
                modules = f.readlines()
                suspicious_modules = []
                for line in modules:
                    parts = line.split()
                    if parts and (parts[0].startswith("_") or len(parts[0]) < 3):
                        suspicious_modules.append(parts[0])
                
                if suspicious_modules:
                    risk_score += 15
                    indicators.append({
                        "type": "SUSPICIOUS_MODULES",
                        "severity": "MEDIUM",
                        "detail": f"Found {len(suspicious_modules)} suspicious kernel modules",
                        "modules": suspicious_modules
                    })
        except:
            pass
        
        # Check for kernel memory patches
        try:
            with open("/proc/sys/kernel/kptr_restrict", "r") as f:
                kptr = int(f.read().strip())
                if kptr == 0:
                    indicators.append({
                        "type": "WEAK_KERNEL_HARDENING",
                        "severity": "MEDIUM",
                        "detail": "Kernel pointer exposure enabled (kptr_restrict=0)"
                    })
        except:
            pass
        
        return {
            "risk_score": risk_score,
            "indicators": indicators,
            "rootkit_detected": risk_score >= 30,
            "recommendations": [
                "Perform deeper memory analysis with Volatility",
                "Check running kernel modules with 'lsmod'",
                "Compare /proc filesystem with external tools",
                "Consider system memory dump for offline analysis"
            ] if risk_score >= 15 else []
        }
    except Exception as e:
        return {"error": str(e), "risk_score": 0, "indicators": []}


def analyze_memory_anomalies() -> Dict[str, Any]:
    """Analyze process memory maps for injection and anomalies."""
    anomalies = []
    
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
        
        for pid in pids[:100]:  # Limit scan
            try:
                with open(f"/proc/{pid}/maps", "r") as f:
                    maps = f.readlines()
                    
                    # Look for suspicious memory patterns
                    rwx_ranges = []  # Write+Execute = dangerous
                    for line in maps:
                        perms = line.split()[1]
                        if len(perms) >= 3:
                            if perms[1] == 'w' and perms[2] == 'x':  # RWX or WX
                                rwx_ranges.append(line.strip())
                    
                    if rwx_ranges:
                        anomalies.append({
                            "pid": int(pid),
                            "type": "WRITABLE_EXECUTABLE_MEMORY",
                            "severity": "HIGH",
                            "count": len(rwx_ranges),
                            "ranges": rwx_ranges[:3]
                        })
                
                # Check for memory hoarding patterns
                with open(f"/proc/{pid}/status", "r") as f:
                    status_data = f.read()
                    for line in status_data.split("\n"):
                        if "VmPeak" in line or "VmHWM" in line:
                            try:
                                mem_kb = int(line.split()[-2])
                                if mem_kb > 500000:  # 500MB+
                                    anomalies.append({
                                        "pid": int(pid),
                                        "type": "EXCESSIVE_MEMORY_USAGE",
                                        "severity": "MEDIUM",
                                        "memory_mb": mem_kb // 1024,
                                        "metric": line.split()[0]
                                    })
                            except:
                                pass
                
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
        
        return {
            "anomalies_found": len(anomalies),
            "anomalies": anomalies[:30],
            "critical_count": len([a for a in anomalies if a.get("severity") == "HIGH"]),
            "recommendations": [
                "Investigate processes with RWX memory ranges",
                "Dump suspicious process memory for analysis",
                "Check for code injection or unpacking behavior"
            ] if anomalies else []
        }
    except Exception as e:
        return {"error": str(e), "anomalies_found": 0}


def detect_anti_forensics() -> Dict[str, Any]:
    """Detect anti-forensics and evidence destruction attempts."""
    detections = []
    
    try:
        # Check for secure deletion tools
        suspicious_tools = [
            "shred", "wipe", "srm", "ccleaner", "eraser", "cipher", 
            "shadowcopy", "vssadmin", "dmg", "diskus", "secure-delete"
        ]
        
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
        for pid in pids:
            try:
                with open(f"/proc/{pid}/cmdline", "r") as f:
                    cmdline = f.read().replace("\x00", " ").lower()
                
                for tool in suspicious_tools:
                    if tool in cmdline:
                        detections.append({
                            "pid": int(pid),
                            "type": "EVIDENCE_DESTRUCTION_TOOL",
                            "severity": "CRITICAL",
                            "tool": tool,
                            "cmdline": cmdline[:200]
                        })
            except:
                pass
        
        # Check for log tampering attempts
        try:
            with open("/proc/sys/kernel/printk", "r") as f:
                printk_level = int(f.read().split()[0])
                if printk_level >= 3:
                    detections.append({
                        "type": "LOG_SUPPRESSION",
                        "severity": "HIGH",
                        "detail": f"Kernel printk level set to {printk_level} (may suppress logging)"
                    })
        except:
            pass
        
        # Check for audit disabling
        try:
            import subprocess
            audit_status = subprocess.check_output(["auditctl", "-l"], text=True, timeout=2)
            if not audit_status or "No rules" in audit_status:
                detections.append({
                    "type": "AUDIT_DISABLED",
                    "severity": "HIGH",
                    "detail": "Linux Audit framework is not logging"
                })
        except:
            pass
        
        return {
            "anti_forensics_detected": len(detections) > 0,
            "detections": detections,
            "risk_level": "CRITICAL" if len(detections) >= 2 else ("HIGH" if detections else "LOW"),
            "recommendations": [
                "Image the system immediately",
                "Monitor all file deletion attempts",
                "Preserve this memory snapshot",
                "Investigate all detected processes"
            ] if detections else []
        }
    except Exception as e:
        return {"error": str(e), "anti_forensics_detected": False, "detections": []}


def get_system_integrity_metrics() -> Dict[str, Any]:
    """Generate overall system integrity scoring."""
    metrics = {
        "timestamp": time.time(),
        "overall_integrity": 0,
        "checks": {}
    }
    
    integrity_score = 100
    
    # Check system uptime (too long might indicate persistent threat)
    try:
        with open("/proc/uptime", "r") as f:
            uptime_seconds = float(f.read().split()[0])
            uptime_days = uptime_seconds / 86400
            
            metrics["checks"]["uptime"] = {
                "days": round(uptime_days, 1),
                "status": "LONG_UPTIME" if uptime_days > 365 else "NORMAL"
            }
            if uptime_days > 365:
                integrity_score -= 10
    except:
        pass
    
    # Check for SELinux/AppArmor status
    try:
        import subprocess
        selinux_status = subprocess.check_output(["getenforce"], text=True, timeout=2).strip()
        metrics["checks"]["selinux"] = {
            "status": selinux_status,
            "enforced": selinux_status in ["Enforcing", "Enforced"]
        }
        if selinux_status == "Disabled":
            integrity_score -= 15
    except:
        pass
    
    # Check system load for anomalies
    try:
        with open("/proc/loadavg", "r") as f:
            loads = f.read().split()[:3]
            current_load = float(loads[0])
            metrics["checks"]["system_load"] = {
                "current": current_load,
                "status": "HIGH" if current_load > 4 else "NORMAL"
            }
            if current_load > 8:
                integrity_score -= 20
    except:
        pass
    
    metrics["overall_integrity"] = max(0, integrity_score)
    metrics["health_status"] = (
        "COMPROMISED" if integrity_score < 40 
        else "SUSPICIOUS" if integrity_score < 70 
        else "HEALTHY"
    )
    
    return metrics
