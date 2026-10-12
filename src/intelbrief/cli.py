"""Command-line interface: `intelbrief ingest`, `intelbrief score`, `intelbrief brief`.

This is the only module that talks to the user directly. It turns settings into real
objects (database connection, HTTP session), calls the pipeline functions, and reports
the result. The pipeline modules themselves only log.
"""

import logging
from contextlib import closing

import typer

from intelbrief import config, db
from intelbrief.http import build_session
from intelbrief.ingest import cisa_kev

app = typer.Typer(help="IntelBrief: threat intelligence briefing pipeline.", no_args_is_help=True)


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug-level log output."),
) -> None:
    """Configure logging once, before any command runs."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


@app.command()
def ingest() -> None:
    """Pull public threat feeds into the local SQLite database."""
    settings = config.get_settings()
    session = build_session(settings.user_agent)

    with closing(db.connect(settings.db_path)) as conn:
        db.init_db(conn)
        try:
            written = cisa_kev.ingest_kev(
                conn,
                session,
                url=config.CISA_KEV_URL,
                cache_path=settings.cache_dir / "cisa_kev.json",
                timeout=settings.http_timeout_seconds,
            )
        except Exception as exc:
            # The failure is already recorded in ingest_runs; show a short message, not a traceback.
            typer.echo(f"CISA KEV ingest failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc

    typer.echo(f"CISA KEV: {written} entries stored in {settings.db_path}")


@app.command()
def score() -> None:
    """Match vulnerabilities to assets and compute priority scores (Phase 2)."""
    typer.echo("`score` is not implemented yet (planned for Phase 2).", err=True)
    raise typer.Exit(code=1)


@app.command()
def brief() -> None:
    """Generate today's AI-written briefing (Phase 3)."""
    typer.echo("`brief` is not implemented yet (planned for Phase 3).", err=True)
    raise typer.Exit(code=1)
