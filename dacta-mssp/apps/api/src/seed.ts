/**
 * DACTA MSSP - Database Seed Script
 *
 * Run: cd apps/api && pnpm db:seed
 *
 * Populates: organizations, users, assets, tickets, timeline entries
 * Requires: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env
 */
import "dotenv/config";
import { createClient } from "@supabase/supabase-js";

const db = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

async function seed() {
  console.log("Seeding DACTA MSSP database...\n");

  // ─── Organizations ──────────────────────────────────────────
  console.log("1. Organizations...");
  const orgs = [
    { name: "Dacta Global", short_name: "DG", color: "#3b82f6", status: "active", contract_type: "internal", sla_tier: "platinum", primary_contact_email: "security@dactaglobal.com" },
    { name: "Naga World", short_name: "NW", color: "#8b5cf6", status: "active", contract_type: "mssp", sla_tier: "gold", primary_contact_email: "it@nagaworld.com" },
    { name: "EM Services", short_name: "EM", color: "#10b981", status: "active", contract_type: "mssp", sla_tier: "silver", primary_contact_email: "security@emservices.com.sg" },
    { name: "SP Telecom", short_name: "SP", color: "#f59e0b", status: "active", contract_type: "mssp", sla_tier: "gold", primary_contact_email: "soc@sptelecom.com" },
    { name: "Toyota Financial", short_name: "TF", color: "#ef4444", status: "active", contract_type: "retainer", sla_tier: "platinum", primary_contact_email: "ciso@toyotafinancial.sg" },
  ];

  const { data: orgData, error: orgErr } = await db
    .from("organizations")
    .upsert(orgs, { onConflict: "short_name" })
    .select();

  if (orgErr) { console.error("  Org error:", orgErr.message); return; }
  const orgMap: Record<string, string> = {};
  orgData!.forEach((o: any) => { orgMap[o.short_name] = o.id; });
  console.log("  Created", orgData!.length, "organizations");

  // ─── Users (SOC analysts) ───────────────────────────────────
  console.log("2. Users...");
  const users = [
    { email: "ahmad.rizal@dacta.sg", name: "Ahmad Rizal", role: "soc_analyst_l2", shift: "morning", org_id: null },
    { email: "sarah.chen@dacta.sg", name: "Sarah Chen", role: "soc_analyst_l2", shift: "morning", org_id: null },
    { email: "marcus.tan@dacta.sg", name: "Marcus Tan", role: "soc_analyst_l1", shift: "morning", org_id: null },
    { email: "priya.sharma@dacta.sg", name: "Priya Sharma", role: "soc_engineer", shift: "morning", org_id: null },
    { email: "james.wu@dacta.sg", name: "James Wu", role: "soc_analyst_l1", shift: "afternoon", org_id: null },
    { email: "aisha.rahman@dacta.sg", name: "Aisha Rahman", role: "soc_analyst_l2", shift: "afternoon", org_id: null },
    { email: "manager@dacta.sg", name: "SOC Manager", role: "soc_manager", shift: null, org_id: null },
  ];

  const { data: userData, error: userErr } = await db
    .from("users")
    .upsert(users, { onConflict: "email" })
    .select();

  if (userErr) { console.error("  User error:", userErr.message); return; }
  const userMap: Record<string, string> = {};
  userData!.forEach((u: any) => { userMap[u.email] = u.id; });
  console.log("  Created", userData!.length, "users");

  // ─── Assets ─────────────────────────────────────────────────
  console.log("3. Assets...");
  const assets = [
    { hostname: "DG-FIN-003", org_id: orgMap["DG"], asset_type: "workstation", os: "Windows 11 Pro", ip_address: "10.21.0.69", agent_installed: true, status: "compromised", criticality: "high", risk_score: 95, department: "Finance", owner: "yangpeng.lee" },
    { hostname: "DG-WEB-01", org_id: orgMap["DG"], asset_type: "server", os: "Ubuntu 22.04", ip_address: "10.21.1.10", agent_installed: true, status: "active", criticality: "critical", risk_score: 45, department: "IT", owner: "infra.team" },
    { hostname: "NW-GAM-PC12", org_id: orgMap["NW"], asset_type: "workstation", os: "Windows 10 Pro", ip_address: "192.168.5.112", agent_installed: true, status: "active", criticality: "medium", risk_score: 35, department: "Gaming", owner: "dealer5" },
    { hostname: "NW-HR-PC03", org_id: orgMap["NW"], asset_type: "workstation", os: "Windows 11 Pro", ip_address: "192.168.5.43", agent_installed: true, status: "active", criticality: "medium", risk_score: 25, department: "HR", owner: "hr.admin2" },
    { hostname: "EM-DC-01", org_id: orgMap["EM"], asset_type: "server", os: "Windows Server 2022", ip_address: "10.50.0.10", agent_installed: true, status: "active", criticality: "critical", risk_score: 60, department: "IT", owner: "it.admin" },
    { hostname: "EM-FAC-PC06", org_id: orgMap["EM"], asset_type: "workstation", os: "Windows 10 Pro", ip_address: "10.50.2.106", agent_installed: true, status: "active", criticality: "low", risk_score: 15, department: "Facilities", owner: "facilities.mgr" },
    { hostname: "SP-ENG-WS07", org_id: orgMap["SP"], asset_type: "workstation", os: "Windows 11 Pro", ip_address: "172.16.8.107", agent_installed: true, status: "active", criticality: "high", risk_score: 50, department: "Engineering", owner: "j.lim" },
    { hostname: "SP-FIN-WS02", org_id: orgMap["SP"], asset_type: "workstation", os: "Windows 11 Pro", ip_address: "172.16.8.52", agent_installed: true, status: "active", criticality: "high", risk_score: 40, department: "Finance", owner: "k.wong" },
  ];

  const { data: assetData, error: assetErr } = await db
    .from("assets")
    .upsert(assets, { onConflict: "hostname" })
    .select();

  if (assetErr) { console.error("  Asset error:", assetErr.message); }
  else console.log("  Created", assetData!.length, "assets");

  // ─── Tickets ────────────────────────────────────────────────
  console.log("4. Tickets...");
  const tickets = [
    { external_key: "DAC-18158", org_id: orgMap["DG"], summary: "Ransomware encryption activity detected on DG-FIN-003", description: "Elastic SIEM rule triggered. Host DG-FIN-003 encrypted 847 files in 3 minutes.", priority: "P1", status: "escalated", source: "elastic_siem", assignee_id: userMap["ahmad.rizal@dacta.sg"], labels: ["ransomware", "incident"], mitre_techniques: ["T1486", "T1059.001"], affected_hostname: "DG-FIN-003", affected_ip: "10.21.0.69", affected_user: "yangpeng.lee" },
    { external_key: "DAC-18157", org_id: orgMap["DG"], summary: "Internal port scanning - 367 connections to 23 hosts", description: "Network anomaly from 10.21.0.69 to 23 hosts on ports 445, 139, 3389.", priority: "P1", status: "in_progress", source: "elastic_siem", assignee_id: userMap["ahmad.rizal@dacta.sg"], labels: ["lateral-movement"], mitre_techniques: ["T1046", "T1021.002"], affected_hostname: "DG-FIN-003", affected_ip: "10.21.0.69", affected_user: "yangpeng.lee" },
    { external_key: "DAC-18155", org_id: orgMap["NW"], summary: "Unsigned DLL sideload blocked by ThreatLocker", description: "ThreatLocker blocked unsigned DLL msedge_elf.dll.", priority: "P2", status: "open", source: "threatlocker", assignee_id: userMap["sarah.chen@dacta.sg"], labels: ["dll-sideload"], mitre_techniques: ["T1574.002"], affected_hostname: "NW-GAM-PC12", affected_ip: "192.168.5.112", affected_user: "dealer5" },
    { external_key: "DAC-18152", org_id: orgMap["EM"], summary: "Failed logins on EM-DC-01 (Event 4625 x 847)", description: "Password spray detected on domain controller.", priority: "P2", status: "open", source: "elastic_siem", assignee_id: null, labels: ["brute-force"], mitre_techniques: ["T1110.003"], affected_hostname: "EM-DC-01", affected_ip: "10.50.0.10", affected_user: "multiple" },
    { external_key: "DAC-18150", org_id: orgMap["SP"], summary: "Suspicious PowerShell download cradle", description: "Trend Vision One: encoded PowerShell downloading from external IP.", priority: "P2", status: "in_progress", source: "trend_vision_one", assignee_id: userMap["marcus.tan@dacta.sg"], labels: ["powershell"], mitre_techniques: ["T1059.001", "T1105"], affected_hostname: "SP-ENG-WS07", affected_ip: "172.16.8.107", affected_user: "j.lim" },
    { external_key: "DAC-18148", org_id: orgMap["NW"], summary: "DNS request to C2 domain blocked", description: "Heimdal blocked dynserv.net C2 domain.", priority: "P3", status: "open", source: "heimdal", assignee_id: null, labels: ["c2"], mitre_techniques: ["T1071.004"], affected_hostname: "NW-HR-PC03", affected_ip: "192.168.5.43", affected_user: "hr.admin2" },
    { external_key: "DAC-18145", org_id: orgMap["TF"], summary: "Impossible travel: Philippines to Nigeria", description: "M365 impossible travel for maria.santos.", priority: "P2", status: "open", source: "microsoft_365", assignee_id: null, labels: ["impossible-travel"], mitre_techniques: ["T1078.004"], affected_ip: "102.89.x.x", affected_user: "maria.santos" },
    { external_key: "DAC-18142", org_id: orgMap["DG"], summary: "FortiGate IPS - SQL injection attempt", description: "IPS signature for UNION SELECT injection.", priority: "P3", status: "in_progress", source: "fortinet", assignee_id: userMap["sarah.chen@dacta.sg"], labels: ["sql-injection"], mitre_techniques: ["T1190"], affected_hostname: "DG-WEB-01", affected_ip: "10.21.1.10" },
    { external_key: "DAC-18140", org_id: orgMap["EM"], summary: "Unauthorized app request: AnyDesk", description: "ThreatLocker blocked AnyDesk.exe.", priority: "P4", status: "open", source: "threatlocker", assignee_id: null, labels: ["shadow-it"], mitre_techniques: ["T1219"], affected_hostname: "EM-FAC-PC06", affected_ip: "10.50.2.106", affected_user: "facilities.mgr" },
    { external_key: "DAC-18138", org_id: orgMap["SP"], summary: "Data exfiltration to OneDrive (2.4GB)", description: "SP-FIN-WS02 uploaded 2.4GB in 20 min.", priority: "P3", status: "open", source: "elastic_siem", assignee_id: null, labels: ["exfiltration"], mitre_techniques: ["T1567.002"], affected_hostname: "SP-FIN-WS02", affected_ip: "172.16.8.52", affected_user: "k.wong" },
  ];

  const { data: ticketData, error: ticketErr } = await db
    .from("tickets")
    .upsert(tickets, { onConflict: "external_key" })
    .select();

  if (ticketErr) { console.error("  Ticket error:", ticketErr.message); }
  else console.log("  Created", ticketData!.length, "tickets");

  console.log("\nSeed complete!");
}

seed().catch(console.error);
