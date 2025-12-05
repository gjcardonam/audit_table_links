#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Audita LINKS dentro de TABLAS (Grafana "table" panels).
Soporta múltiples entornos independientes.
Autenticación Segura: Lee secretos desde variables de entorno (.env) para evitar exponerlos en Git.
"""

import os, sys, json, time, uuid, argparse
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qsl, parse_qs

import requests
from requests.auth import HTTPBasicAuth

# Cargar variables de entorno desde .env si existe
try:
    from dotenv import load_dotenv, find_dotenv
    load_dotenv(find_dotenv(), override=True)
except Exception:
    pass

# BD opcional
try:
    import psycopg2, psycopg2.extras
except Exception:
    psycopg2 = None

# ---------- util ----------

def progress_bar(done: int, total: int, prefix: str = "", width: int = 46) -> None:
    if total <= 0: total = 1
    ratio = max(0.0, min(1.0, done / total))
    filled = int(width * ratio)
    bar = "█" * filled + "░" * (width - filled)
    sys.stdout.write(f"\r{prefix} [{bar}] {done}/{total} ({ratio*100:5.1f}%)")
    sys.stdout.flush()

def load_json(path: str) -> dict:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"El archivo de configuración '{path}' no existe.")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

def fmt_sec(s: float) -> int:
    return int(s if s >= 0 else 0)

def norm(s: Optional[str]) -> str:
    return (s or "").strip().casefold()

def resolve_secret(val: Any) -> Any:
    """
    Si el valor es un string que empieza con 'ENV_', busca esa clave en las variables de entorno.
    Si la variable existe, retorna su valor. Si no, retorna el valor original.
    """
    if isinstance(val, str) and val.startswith("ENV_"):
        env_key = val[4:] # Quitamos el prefijo "ENV_"
        # Primero intenta con el nombre sin prefijo, luego con el valor completo por si acaso
        return os.getenv(env_key, os.getenv(val, val))
    return val

# ---------- config ----------

DEFAULT_LINK_TARGETS = {
    "Single-Axis": "Real Time: Single-Axis",
    "Multi-Axis": "Real Time: Multi-Axis",
    "Health Check": "Health Check",
    "Production History": "Production History",
}

def _bool_env_default(val, default_true=True):
    if isinstance(val, bool):
        return val
    if val is None:
        return default_true
    return str(val).lower() not in {"0", "false", "no"}

def _resolve_grafana_fields(env_block: dict) -> Dict[str, Any]:
    g = env_block.get("grafana", {}) if env_block else {}
    grafana_url = (g.get("url") or os.getenv("GRAFANA_URL", "")).rstrip("/")
    
    # Resolvemos secretos para usuario y contraseña
    grafana_user = resolve_secret(g.get("username", ""))
    grafana_pass = resolve_secret(g.get("password", ""))
    
    # Fallback a variables globales si no hay específicas
    if not grafana_user: grafana_user = os.getenv("GRAFANA_USERNAME", "")
    if not grafana_pass: grafana_pass = os.getenv("GRAFANA_PASSWORD", "")
    
    verify_ssl = _bool_env_default(os.getenv("VERIFY_SSL", g.get("verify_ssl", True)), True)

    companies_inline = g.get("companies_inline")
    companies_file = os.getenv("COMPANIES_FILE", g.get("companies_file"))

    return {
        "url": grafana_url,
        "username": grafana_user,
        "password": grafana_pass,
        "verify_ssl": verify_ssl,
        "companies_inline": companies_inline,
        "companies_file": companies_file,
    }

def _resolve_rules(cfg_rules: dict) -> Dict[str, Any]:
    r = cfg_rules or {}
    link_targets = r.get("link_targets") or DEFAULT_LINK_TARGETS
    ignore_folders = [s.lower() for s in r.get("ignore_folders", ["Test"])]
    return {
        "link_targets": link_targets,
        "ignore_folders": ignore_folders,
    }

def _resolve_db(cfg_db: dict) -> Dict[str, Any]:
    d = cfg_db or {}
    return {
        "enabled": bool(d.get("enabled", False)),
        "host": os.getenv("DB_HOST", d.get("host", "")),
        "port": int(os.getenv("DB_PORT", str(d.get("port", 5432)))),
        "name": os.getenv("DB_NAME", d.get("name", "postgres")),
        "schema": os.getenv("DB_SCHEMA", d.get("schema", "public")),
        "user": os.getenv("DB_USER", d.get("user", "")),
        "password": resolve_secret(d.get("password", "")), # Resolvemos password de BD
    }

def build_config(args) -> Dict[str, Any]:
    cfg = load_json(args.config)
    environments = cfg.get("environments", [])
    
    # Retrocompatibilidad
    if not environments and "grafana" in cfg: 
        env_name = cfg.get("env_name", os.getenv("ENV_NAME", "dev"))
        environments = [{"name": env_name, "grafana": cfg.get("grafana", {})}]

    envs_resolved = []
    for env in environments:
        name = env.get("name") or os.getenv("ENV_NAME", "dev")
        grafana = _resolve_grafana_fields(env)
        envs_resolved.append({"name": name, "grafana": grafana})

    rules = _resolve_rules(cfg.get("rules", {}))
    db = _resolve_db(cfg.get("db", {}))
    progress = {"bar_width": int(cfg.get("progress", {}).get("bar_width", 46))}

    out_cfg = cfg.get("output", {})
    env_write_json = os.getenv("WRITE_JSON")
    env_write_csv  = os.getenv("WRITE_CSV")

    write_json = _bool_env_default(env_write_json, True) if env_write_json is not None else _bool_env_default(out_cfg.get("write_json", True), True)
    write_csv = _bool_env_default(env_write_csv, True) if env_write_csv is not None else _bool_env_default(out_cfg.get("write_csv", True), True)

    return {"environments": envs_resolved, "rules": rules, "db": db, "progress": progress, "output": {"write_json": write_json, "write_csv": write_csv}}

# ---------- grafana http ----------

def make_base_session(verify_ssl: bool):
    """Crea una sesión base."""
    s = requests.Session()
    s.headers.update({"Accept": "application/json"})
    s.verify = verify_ssl
    return s

def switch_organization(session: requests.Session, base_url: str, org_id: int) -> None:
    """Solo usado para Auth básica (QA/Legacy)."""
    r = session.post(f"{base_url}/user/using/{org_id}")
    if r.status_code != 200:
        raise RuntimeError(f"Switch org {org_id} failed: {r.status_code} {r.text}")

def search_folders(session: requests.Session, base_url: str, q: str) -> List[Dict[str, Any]]:
    r = session.get(f"{base_url}/search", params={"type": "dash-folder", "query": q, "limit": 5000})
    r.raise_for_status()
    return r.json() or []

def search_dashboards_any(session: requests.Session, base_url: str) -> List[Dict[str, Any]]:
    r = session.get(f"{base_url}/search", params={"type": "dash-db", "limit": 5000})
    r.raise_for_status()
    return r.json() or []

def get_dashboard(session: requests.Session, base_url: str, uid: str) -> Dict[str, Any]:
    r = session.get(f"{base_url}/dashboards/uid/{uid}")
    r.raise_for_status()
    return r.json()

# ---------- helpers modelo ----------

def iter_all_panels(panels: List[Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
    if not panels: return
    for p in panels:
        yield p
        inner = p.get("panels")
        if isinstance(inner, list) and inner:
            yield from iter_all_panels(inner)

def find_company_folder(session, base_url: str, company_name: str) -> Optional[Dict[str, Any]]:
    for it in search_folders(session, base_url, company_name):
        if norm(it.get("title")) == norm(company_name):
            return it
    return None

def resolve_uid_in_company_folder(session, base_url: str, company_folder_title: str, expected_title: str) -> Optional[str]:
    r = session.get(f"{base_url}/search", params={"type": "dash-db", "query": expected_title, "limit": 5000})
    r.raise_for_status()
    for it in (r.json() or []):
        if norm(it.get("title")) == norm(expected_title) and norm(it.get("folderTitle")) == norm(company_folder_title):
            return it.get("uid")
    return None

def build_expected_uid_map_for_company(session, base_url: str, company_name: str, expected_titles: Set[str]) -> Tuple[Optional[str], Dict[str, Optional[str]]]:
    folder = find_company_folder(session, base_url, company_name)
    if not folder:
        return None, {t: None for t in expected_titles}
    folder_title = folder.get("title")
    mapping: Dict[str, Optional[str]] = {}
    for t in expected_titles:
        mapping[t] = resolve_uid_in_company_folder(session, base_url, folder_title, t)
    return folder_title, mapping

# ---------- extracción de links en TABLAS ----------

def extract_links_from_table_panel(panel: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not panel or (panel.get("type") not in ("table", "table-old")):
        return out
    field_cfg = panel.get("fieldConfig", {}) or {}
    overrides = field_cfg.get("overrides", []) or []
    for ovr in overrides:
        matcher = (ovr.get("matcher") or {}).copy()
        props = ovr.get("properties") or []
        for prop in props:
            if prop.get("id") == "links":
                links = prop.get("value") or []
                for ln in links:
                    out.append({
                        "matcher": matcher,
                        "property_id": "links",
                        "title": ln.get("title"),
                        "url": (ln.get("url") or "").strip(),
                    })
    return out

# ---------- validaciones ----------

def validate_query_params(u: Optional[str], dashboard_title: str) -> List[str]:
    issues: List[str] = []
    s = (u or "").strip()
    if not s: return issues
    parsed = urlparse(s if s.startswith("http") else ("/" + s.lstrip("/")))
    if not parsed.query: return issues
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    allowed_keys = {"var-nodeId", "from", "to", "var-var_wells"}
    
    for k, v in pairs:
        if k not in allowed_keys:
            issues.append("url_param_not_allowed")
            continue
        if k == "var-nodeId":
            if dashboard_title.strip() == "Setpoints" and v == "${nodeId}":
                continue
            if v != "${__value.raw}":
                issues.append("nodeId_value_not_allowed")
        if k == "var-var_wells":
            if v != "${__value.raw}":
                issues.append("var_wells_value_not_allowed")
    return list(dict.fromkeys(issues))

def extract_uid_from_grafana_url(u: str) -> Optional[str]:
    if not u: return None
    s = u.strip().lstrip("/")
    parsed = urlparse("/" + s)
    parts = [p for p in (parsed.path or s).split('/') if p]
    for i, seg in enumerate(parts):
        if seg in ("d", "d-solo") and i + 1 < len(parts):
            return parts[i + 1]
    return None

# ---------- BD ----------

DDL_RUNS = """
CREATE TABLE IF NOT EXISTS {schema}.table_links_audit_runs (
  run_id UUID PRIMARY KEY,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at   TIMESTAMPTZ,
  environment TEXT,
  org_count INTEGER,
  dashboard_count INTEGER,
  tables_checked INTEGER,
  links_checked INTEGER,
  violations_count INTEGER,
  elapsed_seconds INTEGER
);"""

DDL_VIOLS = """
CREATE TABLE IF NOT EXISTS {schema}.table_links_audit_violations (
  id BIGSERIAL PRIMARY KEY,
  run_id UUID REFERENCES {schema}.table_links_audit_runs(run_id) ON DELETE CASCADE,
  org TEXT, dashboard TEXT, dashboard_uid TEXT,
  folder_title TEXT, folder_id BIGINT, folder_url TEXT,
  panel_id BIGINT, panel_title TEXT,
  matcher_id TEXT, matcher_options TEXT,
  link_title TEXT, url TEXT,
  issue TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);"""

def db_connect(cfg_db: dict):
    if not psycopg2: raise RuntimeError("psycopg2 no está instalado y db.enabled=true")
    return psycopg2.connect(
        host=cfg_db["host"], port=cfg_db["port"], dbname=cfg_db["name"],
        user=cfg_db["user"], password=cfg_db["password"]
    )

def db_prepare(conn, schema: str):
    with conn.cursor() as cur:
        cur.execute(DDL_RUNS.format(schema=schema))
        cur.execute(DDL_VIOLS.format(schema=schema))
    conn.commit()

def db_insert_run_start(conn, schema: str, run_id, env_name: str, orgs: int, dashboards: int):
    with conn.cursor() as cur:
        cur.execute(f"INSERT INTO {schema}.table_links_audit_runs(run_id, environment, org_count, dashboard_count) VALUES (%s,%s,%s,%s)", (run_id, env_name, orgs, dashboards))
    conn.commit()

def db_update_run_end(conn, schema: str, run_id, tables_checked: int, links_checked: int, viols: int, elapsed: int):
    with conn.cursor() as cur:
        cur.execute(f"UPDATE {schema}.table_links_audit_runs SET ended_at=now(), tables_checked=%s, links_checked=%s, violations_count=%s, elapsed_seconds=%s WHERE run_id=%s", (tables_checked, links_checked, viols, elapsed, run_id))
    conn.commit()

def db_bulk_insert_violations(conn, schema: str, run_id, viols: List[Dict[str, Any]]):
    if not viols: return
    rows = [(run_id, v.get("org"), v.get("dashboard"), v.get("dashboard_uid"), v.get("folder_title"), v.get("folder_id"), v.get("folder_url"), v.get("panel_id"), v.get("panel_title"), v.get("matcher_id"), v.get("matcher_options"), v.get("link_title"), v.get("url"), v.get("issue")) for v in viols]
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(cur, f"INSERT INTO {schema}.table_links_audit_violations (run_id, org, dashboard, dashboard_uid, folder_title, folder_id, folder_url, panel_id, panel_title, matcher_id, matcher_options, link_title, url, issue) VALUES %s", rows, page_size=500)
    conn.commit()

# ---------- núcleo del auditor ----------

def run_for_environment(env_cfg: Dict[str, Any], rules: Dict[str, Any], db_cfg: Dict[str, Any], bar_width: int, output_cfg: Dict[str, Any]) -> Dict[str, Any]:
    g = env_cfg["grafana"]
    env_name = env_cfg["name"]
    
    if g.get("companies_inline"):
        companies = g["companies_inline"]
    elif g.get("companies_file"):
        companies = load_json(g["companies_file"])
    else:
        print(f"\n⚠ Skipping env '{env_name}': No companies defined (inline or file).")
        return {
            "summary": { "environment": env_name, "organizations": 0, "dashboards": 0, "tables_checked": 0, "links_checked": 0, "violations": 0, "elapsed_seconds": 0 },
            "violations": []
        }

    session = make_base_session(g["verify_ssl"])
    base_url = g["url"]

    # Credenciales globales (solo usadas como fallback o para QA legacy)
    global_user = g["username"]
    global_pass = g["password"]

    if db_cfg["enabled"]:
        conn = db_connect(db_cfg)
        db_prepare(conn, db_cfg["schema"])
        run_id = str(uuid.uuid4())
        db_insert_run_start(conn, db_cfg["schema"], run_id, env_name, len(companies), 0)
    else:
        conn, run_id = None, str(uuid.uuid4())

    start = time.time()
    tables_checked, links_checked = 0, 0
    violations: List[Dict[str, Any]] = []
    total_tasks, tasks_done = max(1, len(companies)), 0

    print(f"\nAuditor TABLAS (env={env_name}): {len(companies)} orgs")
    progress_bar(0, total_tasks, f"Progreso {env_name}", bar_width)

    for company in companies:
        # Resolver token: si empieza con ENV_, se busca en variables de entorno
        raw_token = company.get("token")
        token = resolve_secret(raw_token)
        
        # 1. AUTENTICACIÓN
        try:
            # LIMPIEZA PREVIA:
            session.headers.pop("Authorization", None)
            session.auth = None

            if token:
                # CASO 1: TOKEN (Service Account)
                session.headers.update({"Authorization": f"Bearer {token}"})
            
            elif global_user and global_pass:
                # CASO 2: USER/PASS (Legacy/QA)
                session.auth = HTTPBasicAuth(global_user, global_pass)
                
                # En modo usuario/password, a veces es necesario hacer switch org.
                if company.get("id"):
                    switch_organization(session, base_url, company["id"])
            else:
                # CASO 3: Sin credenciales válidas
                raise ValueError(f"No credentials (token or user/pass) for company {company.get('name')}")
        
        except Exception as e:
            # print(f"\nError Auth {company.get('name')}: {e}") 
            tasks_done += 1
            progress_bar(tasks_done, total_tasks, f"Progreso {env_name}", bar_width)
            continue

        # 2. PROCESAMIENTO
        try:
            expected_titles: Set[str] = set((rules["link_targets"] or {}).values())
            company_folder_title, expected_uid_map = build_expected_uid_map_for_company(session, base_url, company["name"], expected_titles)
            
            all_dashes = search_dashboards_any(session, base_url)
            dash_in_folder = [it for it in all_dashes if norm(it.get("folderTitle")) == norm(company_folder_title)] if company_folder_title else []

            if db_cfg["enabled"]:
                with conn.cursor() as cur:
                    cur.execute(f"UPDATE {db_cfg['schema']}.table_links_audit_runs SET dashboard_count=%s WHERE run_id=%s", (len(dash_in_folder), run_id))
                conn.commit()

            for meta in dash_in_folder:
                uid = meta.get("uid")
                if not uid: continue
                try:
                    payload = get_dashboard(session, base_url, uid)
                except Exception: continue
                
                dashboard = payload.get("dashboard") or {}
                dash_meta = payload.get("meta") or {}
                folder_title = (dash_meta.get("folderTitle") or "").strip().lower()
                if folder_title in (rules.get("ignore_folders") or []): continue

                for panel in iter_all_panels(dashboard.get("panels", []) or []):
                    if panel.get("type") not in ("table", "table-old"): continue
                    table_links = extract_links_from_table_panel(panel)
                    if not table_links: continue
                    
                    tables_checked += 1
                    for link in table_links:
                        links_checked += 1
                        issues = []
                        url, title = link.get("url", ""), (link.get("title") or "").strip()
                        dash_title = dashboard.get("title", "")
                        
                        issues.extend(validate_query_params(url, dash_title))
                        
                        if dash_title.strip() == "Daily ESP Status":
                            if title in ("Single-Axis", "Multi-Axis"):
                                parsed_q = urlparse(url if url.startswith("http") else ("/" + url.lstrip("/"))).query
                                q_keys = parse_qs(parsed_q).keys()
                                if "from" not in q_keys or "to" not in q_keys: issues.append("missing_time_params")

                        expected_title = (rules["link_targets"] or {}).get(title)
                        if expected_title:
                            if not company_folder_title: issues.append("company_folder_not_found")
                            else:
                                uid_in_url = extract_uid_from_grafana_url(url)
                                expected_uid = expected_uid_map.get(expected_title)
                                if not uid_in_url: issues.append("url_missing_uid")
                                elif not expected_uid: issues.append("target_dashboard_not_found")
                                elif uid_in_url == "${__dashboard.uid}": pass
                                elif uid_in_url != expected_uid: issues.append("target_uid_mismatch")

                        if issues:
                            m = link.get("matcher") or {}
                            violations.append({
                                "org": company.get("name"), "dashboard": dashboard.get("title"), "dashboard_uid": dashboard.get("uid") or dash_meta.get("uid"),
                                "folder_title": dash_meta.get("folderTitle"), "folder_id": dash_meta.get("folderId"), "folder_url": dash_meta.get("folderUrl"),
                                "panel_id": panel.get("id"), "panel_title": panel.get("title"),
                                "matcher_id": (str(m.get("id"))), "matcher_options": json.dumps(m.get("options"), ensure_ascii=False) if m.get("options") is not None else None,
                                "link_title": title, "url": url, "issue": ",".join(issues),
                            })
        except Exception as e:
            # print(f"Error processing company {company.get('name')}: {e}")
            pass
            
        tasks_done += 1
        progress_bar(tasks_done, total_tasks, f"Progreso {env_name}", bar_width)

    elapsed = fmt_sec(time.time() - start)
    result = {
        "summary": { "environment": env_name, "organizations": len(companies), "dashboards": None, "tables_checked": tables_checked, "links_checked": links_checked, "violations": len(violations), "elapsed_seconds": elapsed },
        "violations": violations,
    }

    if output_cfg.get("write_json", True): save_json(f"table_links_audit_{env_name}.json", result)
    if output_cfg.get("write_csv", True):
        try:
            import csv
            with open(f"table_links_audit_{env_name}.csv", "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["org", "dashboard", "dashboard_uid", "folder_title", "folder_id", "folder_url", "panel_id", "panel_title", "matcher_id", "matcher_options", "link_title", "url", "issue"])
                for v in violations: w.writerow([v.get("org"), v.get("dashboard"), v.get("dashboard_uid"), v.get("folder_title"), v.get("folder_id"), v.get("folder_url"), v.get("panel_id"), v.get("panel_title"), v.get("matcher_id"), v.get("matcher_options"), v.get("link_title"), v.get("url"), v.get("issue")])
        except Exception as e: print(f"\n⚠ No se pudo escribir CSV: {e}")

    if db_cfg["enabled"]:
        db_bulk_insert_violations(conn, db_cfg["schema"], run_id, violations)
        db_update_run_end(conn, db_cfg["schema"], run_id, tables_checked, links_checked, len(violations), elapsed)
        conn.close()

    print(f"\nOK {env_name} TABLAS | tables={tables_checked} links={links_checked} viols={len(violations)}")
    return result

# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="Audita LINKS en TABLAS (Grafana) para múltiples ambientes independientes.")
    ap.add_argument("-c", "--config", required=True, help="Ruta al JSON de configuración")
    args = ap.parse_args()
    cfg = build_config(args)
    
    all_results = {"summaries": [], "environments": {}}
    total_tasks, done = max(1, len(cfg["environments"])), 0

    for env in cfg["environments"]:
        res = run_for_environment(env, cfg["rules"], cfg["db"], cfg["progress"]["bar_width"], cfg["output"])
        all_results["summaries"].append(res["summary"])
        all_results["environments"][env["name"]] = res
        done += 1
        progress_bar(done, total_tasks, "Ambientes", cfg["progress"]["bar_width"])

    if cfg["output"].get("write_json", True):
        save_json("table_links_audit_all.json", all_results)
        print("\nResumen combinado escrito en table_links_audit_all.json")

if __name__ == "__main__":
    main()