#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Audita LINKS dentro de TABLAS (Grafana "table" panels) para múltiples ambientes y compañías.
- Recorre todas las organizations (companies) y todos los dashboards en la carpeta principal de cada compañía.
- Encuentra todos los paneles de tipo tabla y extrae los links definidos en field overrides (properties.id == "links").
- Valida:
    1) Que las URLs NO tengan parámetros de query (nada después de '?').
    2) Que, para ciertos títulos de botón, el UID del dashboard en la URL coincida con el UID del dashboard esperado
       (resuelto por nombre y dentro de la carpeta principal de la compañía).
- Exporta JSON/CSV por ambiente y (opcional) persiste hallazgos en PostgreSQL.

Ejemplo de config.json (mínimo):
{
  "environments": [
    {
      "name": "dev",
      "grafana": {
        "url": "https://grafana-dev.example.com",
        "username": "user",
        "password": "pass",
        "verify_ssl": true,
        "companies_file": "companies.json"
      }
    }
  ],
  "rules": {
    "link_targets": {
      "Single-Axis": "Real Time: Trends",
      "Multi-Axis": "Real Time: Multi-axis",
      "Health Check": "Health Check",
      "Production History": "Production History"
    },
    "ignore_folders": ["Test"]
  },
  "db": { "enabled": false, "schema": "public" },
  "progress": { "bar_width": 46 }
}

companies.json (ejemplo):
[
  {"id": 1, "name": "Akakus"},
  {"id": 2, "name": "Apache"}
]
"""

import os, sys, json, time, uuid, argparse
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
from requests.auth import HTTPBasicAuth

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
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

def fmt_sec(s: float) -> int:
    return int(s if s >= 0 else 0)

def norm(s: Optional[str]) -> str:
    return (s or "").strip().casefold()

# ---------- config ----------

DEFAULT_LINK_TARGETS = {
    "Single-Axis": "Real Time: Trends",
    "Multi-Axis": "Real Time: Multi-axis",
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
    grafana_user = os.getenv("GRAFANA_USERNAME", g.get("username", ""))
    grafana_pass = os.getenv("GRAFANA_PASSWORD", g.get("password", ""))
    verify_ssl = _bool_env_default(os.getenv("VERIFY_SSL", g.get("verify_ssl", True)), True)

    companies_inline = g.get("companies")
    companies_file = os.getenv("COMPANIES_FILE", g.get("companies_file", "companies.json"))

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
        "password": os.getenv("DB_PASSWORD", d.get("password", "")),
    }


def build_config(args) -> Dict[str, Any]:
    # .env opcional
    try:
        from dotenv import load_dotenv, find_dotenv
        load_dotenv(find_dotenv(), override=False)
    except Exception:
        pass

    cfg = load_json(args.config)

    # Retrocompatibilidad (formato viejo con un solo bloque):
    if "environments" not in cfg:
        env_name = cfg.get("env_name", os.getenv("ENV_NAME", "dev"))
        env_block = {"name": env_name, "grafana": cfg.get("grafana", {})}
        environments = [env_block]
    else:
        environments = cfg["environments"]

    envs_resolved = []
    for env in environments:
        name = env.get("name") or os.getenv("ENV_NAME", "dev")
        grafana = _resolve_grafana_fields(env)
        envs_resolved.append({"name": name, "grafana": grafana})

    rules = _resolve_rules(cfg.get("rules", {}))
    db = _resolve_db(cfg.get("db", {}))
    progress = {"bar_width": int(cfg.get("progress", {}).get("bar_width", 46))}

    return {"environments": envs_resolved, "rules": rules, "db": db, "progress": progress}

# ---------- grafana http ----------

def make_session(url: str, user: str, passwd: str, verify_ssl: bool):
    s = requests.Session()
    s.headers.update({"Accept": "application/json"})
    if user:
        s.auth = HTTPBasicAuth(user, passwd)
    s.verify = verify_ssl
    return s, url


def switch_organization(session: requests.Session, base_url: str, org_id: int) -> None:
    r = session.post(f"{base_url}/user/using/{org_id}")
    if r.status_code != 200:
        raise RuntimeError(f"Switch org {org_id} failed: {r.status_code} {r.text}")


def search_folders(session: requests.Session, base_url: str, q: str) -> List[Dict[str, Any]]:
    r = session.get(f"{base_url}/search", params={"type": "dash-folder", "query": q, "limit": 5000})
    r.raise_for_status()
    return r.json() or []


def search_dashboards_any(session: requests.Session, base_url: str) -> List[Dict[str, Any]]:
    """Busca TODOS los dashboards visibles (limit alto)"""
    r = session.get(f"{base_url}/search", params={"type": "dash-db", "limit": 5000})
    r.raise_for_status()
    return r.json() or []


def get_dashboard(session: requests.Session, base_url: str, uid: str) -> Dict[str, Any]:
    r = session.get(f"{base_url}/dashboards/uid/{uid}")
    r.raise_for_status()
    return r.json()

# ---------- helpers modelo ----------

def iter_all_panels(panels: List[Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
    if not panels:
        return
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
    """Devuelve una lista de objetos {matcher, property_id, title, url} para cada link encontrado en overrides."""
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

def validate_query_params(u: Optional[str]) -> List[str]:
    """Valida la query de la URL. Reglas:
    - Permitidos: var-nodeId=${__value.raw} (valor EXACTO), from=<cualquiera>, to=<cualquiera>
    - Cualquier otro parámetro -> 'url_param_not_allowed'
    - var-nodeId con valor distinto -> 'nodeId_value_not_allowed'
    Devuelve lista de issues (vacía si todo ok).
    """
    issues: List[str] = []
    s = (u or "").strip()
    if not s:
        return issues
    parsed = urlparse(s if s.startswith("http") else ("/" + s.lstrip("/")))
    if not parsed.query:
        return issues

    from urllib.parse import parse_qsl
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    allowed_keys = {"var-nodeId", "from", "to"}
    for k, v in pairs:
        if k not in allowed_keys:
            issues.append("url_param_not_allowed")
            continue
        if k == "var-nodeId" and v != "${__value.raw}":
            issues.append("nodeId_value_not_allowed")
    return list(dict.fromkeys(issues))  # dedup while preserving order


def extract_uid_from_grafana_url(u: str) -> Optional[str]:
    if not u:
        return None
    s = u.strip().lstrip("/")  # permite URLs relativas como "d/abc..."
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
    if not psycopg2:
        raise RuntimeError("psycopg2 no está instalado y db.enabled=true")
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
        cur.execute(
            f"INSERT INTO {schema}.table_links_audit_runs(run_id, environment, org_count, dashboard_count) VALUES (%s,%s,%s,%s)",
            (run_id, env_name, orgs, dashboards)
        )
    conn.commit()


def db_update_run_end(conn, schema: str, run_id, tables_checked: int, links_checked: int, viols: int, elapsed: int):
    with conn.cursor() as cur:
        cur.execute(
            f"UPDATE {schema}.table_links_audit_runs SET ended_at=now(), tables_checked=%s, links_checked=%s, violations_count=%s, elapsed_seconds=%s WHERE run_id=%s",
            (tables_checked, links_checked, viols, elapsed, run_id)
        )
    conn.commit()


def db_bulk_insert_violations(conn, schema: str, run_id, viols: List[Dict[str, Any]]):
    if not viols:
        return
    rows = [
        (
            run_id,
            v.get("org"), v.get("dashboard"), v.get("dashboard_uid"),
            v.get("folder_title"), v.get("folder_id"), v.get("folder_url"),
            v.get("panel_id"), v.get("panel_title"),
            v.get("matcher_id"), v.get("matcher_options"),
            v.get("link_title"), v.get("url"),
            v.get("issue"),
        )
        for v in viols
    ]
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            f"""INSERT INTO {schema}.table_links_audit_violations
                (run_id, org, dashboard, dashboard_uid, folder_title, folder_id, folder_url,
                 panel_id, panel_title, matcher_id, matcher_options, link_title, url, issue)
                VALUES %s""",
            rows,
            page_size=500,
        )
    conn.commit()

# ---------- núcleo del auditor ----------

def run_for_environment(env_cfg: Dict[str, Any], rules: Dict[str, Any], db_cfg: Dict[str, Any], bar_width: int) -> Dict[str, Any]:
    g = env_cfg["grafana"]
    env_name = env_cfg["name"]

    # Cargar compañías
    companies = g["companies_inline"] if g["companies_inline"] else load_json(g["companies_file"])

    # Session
    session, base_url = make_session(g["url"], g["username"], g["password"], g["verify_ssl"])

    # BD
    if db_cfg["enabled"]:
        conn = db_connect(db_cfg)
        db_prepare(conn, db_cfg["schema"])
        run_id = str(uuid.uuid4())
        # dashboards totales se aproxima después (cuando contemos por carpeta)
        db_insert_run_start(conn, db_cfg["schema"], run_id, env_name, len(companies), 0)
    else:
        conn = None
        run_id = str(uuid.uuid4())

    start = time.time()
    tables_checked = 0
    links_checked = 0
    violations: List[Dict[str, Any]] = []

    # Estimación de progreso: compañías * 1 (recorrido por carpeta completa)
    total_tasks = max(1, len(companies))
    tasks_done = 0

    print(f"\nAuditor TABLAS (env={env_name}): {len(companies)} orgs")
    progress_bar(0, total_tasks, f"Progreso {env_name}", bar_width)

    for company in companies:
        # cambiar de organización
        try:
            switch_organization(session, base_url, company["id"])
        except Exception:
            tasks_done += 1
            progress_bar(tasks_done, total_tasks, f"Progreso {env_name}", bar_width)
            continue

        # mapa "título esperado -> UID" dentro de la carpeta de la compañía
        expected_titles: Set[str] = set((rules["link_targets"] or {}).values())
        company_folder_title, expected_uid_map = build_expected_uid_map_for_company(
            session, base_url, company["name"], expected_titles
        )

        # listar dashboards en la carpeta principal de la compañía
        all_dashes = search_dashboards_any(session, base_url)
        dash_in_folder = [
            it for it in all_dashes
            if norm(it.get("folderTitle")) == norm(company_folder_title)
        ] if company_folder_title else []

        # por si queremos reflejar en BD cuántos dashboards se recorrieron (actualización rápida)
        if db_cfg["enabled"]:
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE {db_cfg['schema']}.table_links_audit_runs SET dashboard_count=%s WHERE run_id=%s",
                    (len(dash_in_folder), run_id),
                )
            conn.commit()

        for meta in dash_in_folder:
            uid = meta.get("uid")
            if not uid:
                continue
            try:
                payload = get_dashboard(session, base_url, uid)
            except Exception:
                continue

            dashboard = payload.get("dashboard") or {}
            dash_meta = payload.get("meta") or {}
            folder_title = (dash_meta.get("folderTitle") or "").strip().lower()
            if folder_title in (rules.get("ignore_folders") or []):
                continue

            for panel in iter_all_panels(dashboard.get("panels", []) or []):
                if panel.get("type") not in ("table", "table-old"):
                    continue

                table_links = extract_links_from_table_panel(panel)
                if not table_links:
                    continue

                tables_checked += 1

                for link in table_links:
                    links_checked += 1
                    issues = []

                    url = link.get("url", "")
                    title = (link.get("title") or "").strip()

                    # Regla 1: parámetros solo si son permitidos (var-nodeId=${__value.raw}, from, to)
                    issues.extend(validate_query_params(url))

                    # Regla 2: validar UID según botón → dashboard esperado
                    expected_title = (rules["link_targets"] or {}).get(title)
                    if expected_title:
                        if not company_folder_title:
                            issues.append("company_folder_not_found")
                        else:
                            uid_in_url = extract_uid_from_grafana_url(url)
                            expected_uid = expected_uid_map.get(expected_title)
                            if not uid_in_url:
                                issues.append("url_missing_uid")
                            elif not expected_uid:
                                issues.append("target_dashboard_not_found")
                            elif uid_in_url == "${__dashboard.uid}":
                                # Se permite explícitamente: apunta al mismo dashboard
                                pass
                            elif uid_in_url != expected_uid:
                                issues.append("target_uid_mismatch")

                    if issues:
                        m = link.get("matcher") or {}
                        viol = {
                            "org": company.get("name"),
                            "dashboard": dashboard.get("title"),
                            "dashboard_uid": dashboard.get("uid") or dash_meta.get("uid"),
                            "folder_title": dash_meta.get("folderTitle"),
                            "folder_id": dash_meta.get("folderId"),
                            "folder_url": dash_meta.get("folderUrl"),
                            "panel_id": panel.get("id"),
                            "panel_title": panel.get("title"),
                            "matcher_id": (m.get("id") if isinstance(m.get("id"), str) else str(m.get("id"))),
                            "matcher_options": json.dumps(m.get("options"), ensure_ascii=False) if m.get("options") is not None else None,
                            "link_title": title,
                            "url": url,
                            "issue": ",".join(issues),
                        }
                        violations.append(viol)

        tasks_done += 1
        progress_bar(tasks_done, total_tasks, f"Progreso {env_name}", bar_width)

    elapsed = fmt_sec(time.time() - start)

    result = {
        "summary": {
            "environment": env_name,
            "organizations": len(companies),
            "dashboards": None,  # se informó en BD por compañía; aquí no acumulamos global por simplicidad
            "tables_checked": tables_checked,
            "links_checked": links_checked,
            "violations": len(violations),
            "elapsed_seconds": elapsed,
        },
        "violations": violations,
    }

    # Outputs por ambiente
    save_json(f"table_links_audit_{env_name}.json", result)

    try:
        import csv
        with open(f"table_links_audit_{env_name}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([
                "org", "dashboard", "dashboard_uid", "folder_title", "folder_id", "folder_url",
                "panel_id", "panel_title", "matcher_id", "matcher_options",
                "link_title", "url", "issue",
            ])
            for v in violations:
                w.writerow([
                    v.get("org"), v.get("dashboard"), v.get("dashboard_uid"),
                    v.get("folder_title"), v.get("folder_id"), v.get("folder_url"),
                    v.get("panel_id"), v.get("panel_title"), v.get("matcher_id"), v.get("matcher_options"),
                    v.get("link_title"), v.get("url"), v.get("issue"),
                ])
    except Exception as e:
        print(f"\n⚠ No se pudo escribir table_links_audit_{env_name}.csv: {e}")

    # Persistencia BD
    if db_cfg["enabled"]:
        db_bulk_insert_violations(conn, db_cfg["schema"], run_id, violations)
        db_update_run_end(conn, db_cfg["schema"], run_id, tables_checked, links_checked, len(violations), elapsed)
        conn.close()

    print(f"\nOK {env_name} TABLAS | tables={tables_checked} links={links_checked} viols={len(violations)}")
    return result

# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="Audita LINKS en TABLAS (Grafana) en múltiples ambientes/compañías.")
    ap.add_argument("-c", "--config", required=True, help="Ruta al JSON de configuración")
    args = ap.parse_args()

    cfg = build_config(args)
    envs = cfg["environments"]
    rules = cfg["rules"]
    db_cfg = cfg["db"]
    barw = cfg["progress"]["bar_width"]

    all_results = {"summaries": [], "environments": {}}

    total_tasks = max(1, len(envs))
    done = 0

    for env in envs:
        res = run_for_environment(env, rules, db_cfg, barw)
        all_results["summaries"].append(res["summary"])
        all_results["environments"][env["name"]] = res
        done += 1
        progress_bar(done, total_tasks, "Ambientes", barw)

    save_json("table_links_audit_all.json", all_results)
    print("\nResumen combinado escrito en table_links_audit_all.json")


if __name__ == "__main__":
    main()
