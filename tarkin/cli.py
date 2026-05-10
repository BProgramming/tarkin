from __future__ import annotations
import typer
import json
import zipfile
from importlib.metadata import version
from pathlib import Path
from typing import Optional

from .attach import attach, AttachError
from .detach import detach, DetachError
from .credentials import (
    CredentialsFile, DEFAULT_CREDENTIALS_PATH,
    check_connection, test_all_connections, ConnectionProfile,
)
from .inspect import inspect_database
from .model import GovernanceProject
from .yaml import YamlLoader
from .validate import SemanticValidator, ValidationError
from .serialize import Serializer
from .build import build, BuildError

app = typer.Typer(no_args_is_help=True, help="Tarkin: governance compiler for PostgreSQL.")


# =====================================================
# SHARED OPTIONS
# =====================================================

_credentials_option = typer.Option(
    None, "--credentials", "-c",
    help=f"Path to credentials.toml. Defaults to {DEFAULT_CREDENTIALS_PATH}.",
)

_profile_option = typer.Option(
    ..., "--profile", "-p",
    help="Named connection profile from credentials.toml.",
)

_output_option = typer.Option(
    None, "--output", "-o",
    help="Output file path.",
)


# =====================================================
# VERSION
# =====================================================

@app.command(name="version")
def show_version() -> None:
    """Show the installed Tarkin version."""
    print(version("tarkin"))


# =====================================================
# CONNECT — test a credentials profile
# =====================================================

@app.command(name="connect")
def test_connections(
    credentials: Optional[Path] = _credentials_option,
    profile: Optional[str] = typer.Option(None, "--profile", "-p",
        help="Profile to test. Omit to test all profiles."),
) -> None:
    """Test that credentials profiles can connect to their databases."""
    creds = _load_credentials(credentials)

    if creds:
        if profile:
            try:
                p = creds.get(profile)
                result = check_connection(p)
                print(result)
                if not result.success:
                    raise typer.Exit(1)
            except KeyError as exc:
                _die(str(exc))
        else:
            results = test_all_connections(creds)
            for r in results:
                print(r)
            if any(not r.success for r in results):
                raise typer.Exit(1)


# =====================================================
# INSPECT — inspect a live database → YAML
# =====================================================

@app.command(name="inspect")
def inspect_database_build_yaml(
    profile:     str            = _profile_option,
    output:      Optional[Path] = _output_option,
    credentials: Optional[Path] = _credentials_option,
    validate:    bool           = typer.Option(True, "--validate/--no-validate",
        help="Run semantic validation on the inspected model before writing."),
) -> None:
    """
    Inspect a live PostgreSQL database and emit a Tarkin governance YAML.

    Connects using the named profile from credentials.toml, captures the full
    database structure (schemas, tables, columns, indexes, foreign keys, sequences,
    views, functions, roles, and grants), and writes a governance YAML that can
    be edited and applied back with 'tarkin attach'.
    """
    creds = _load_credentials(credentials)
    if not creds:
        return

    prof = _resolve_profile(creds, profile)
    if not prof:
        return

    print(f"Connecting to {prof.safe_repr()}...", end="\r")
    result = check_connection(prof)
    if not result.success:
        _die(f"Connection failed: {result.error}")
        return
    print(f"Connecting to {prof.safe_repr()}... Done.\nConnected on PostgreSQL {result.server_version}.")

    db_user = result.db_user

    print("Inspecting database...", end="\r")
    try:
        proj = inspect_database(prof)
        print("Inspecting database... Done.")
    except Exception as exc:
        _die(f"Inspection failed: {exc}")
        return

    if proj:
        proj.database.profile = prof.profile

        role_names = {r.name for r in proj.roles}
        if db_user and db_user not in role_names:
            _warn(
                f"Connected as {db_user!r} but this user was not found in the database's "
                f"role list. The credentials profile may be using a role that exists outside "
                f"the standard pg_roles view, or may lack login privilege."
            )

        if validate:
            print("Validating inspected model...", end="\r")
            try:
                SemanticValidator.validate(proj)
                print("Validating inspected model... Passed.")
            except ValidationError as exc:
                _warn(f"Semantic validation found issues. Review before attaching:\n{exc}")

        yaml_str = Serializer.to_yaml_string(proj)

        if output is None:
            output = Path("out") / f"{prof.database}_model.yaml"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(yaml_str, encoding="utf-8")
        print(f"Written to {output}.")


# =====================================================
# VALIDATE — parse + validate a governance YAML
# =====================================================

@app.command(name="validate")
def validate_data_model(
    config: Path = typer.Argument(..., help="Path to governance YAML."),
) -> None:
    """Parse and semantically validate a Tarkin governance YAML."""
    _load_and_validate(config)
    print("Validation passed.")


# =====================================================
# BUILD — compile governance YAML to a build artifact
# =====================================================

@app.command(name="build")
def build_data_model_from_yaml(
    config:      Path           = typer.Argument(..., help="Path to governance YAML."),
    profile:     Optional[str]  = typer.Option(None, "--profile", "-p",
        help="Override the credentials profile in the YAML."),
    credentials: Optional[Path] = _credentials_option,
    output:      Optional[Path] = _output_option,
) -> None:
    """
    Compile a Tarkin governance YAML into a build artifact.

    Connects to the live database, inspects current state, generates the SQL
    needed to implement the governance model, and writes a zip artifact
    containing the SQL and build metadata to out/.
    """
    proj = _load_and_validate(config)
    if not proj:
        return

    creds = _load_credentials(credentials)
    if not creds:
        return

    profile_name = profile or proj.database.profile
    if not profile_name:
        _die("No credentials profile specified. Use --profile or set 'profile' in the YAML.")
        return

    prof = _resolve_profile(creds, profile_name)
    if not prof:
        return

    print(f"Connecting to {prof.safe_repr()}...", end="\r")
    result = check_connection(prof)
    if not result.success:
        _die(f"Connection failed: {result.error}")
        return
    print(f"Connecting to {prof.safe_repr()}... Done.\nConnected on PostgreSQL {result.server_version}.")

    try:
        zip_path = build(proj, prof, out_dir=output)
        print(f"Build complete: {zip_path}")
    except BuildError as exc:
        _die(str(exc))


# =====================================================
# ATTACH — execute a build artifact against a live database
# =====================================================

@app.command(name="attach")
def attach_to_database(
    build_path:  Optional[Path] = typer.Option(None, "--build", "-b",
        help="Path to build artifact zip. Defaults to latest in out/."),
    profile:     Optional[str]  = typer.Option(None, "--profile", "-p",
        help="Override the credentials profile in the build artifact."),
    credentials: Optional[Path] = _credentials_option,
) -> None:
    """
    Apply a Tarkin model to a live database.

    Verifies the database state matches the build, then executes the
    generated SQL inside a transaction. Rolls back on any failure.
    """
    creds = _load_credentials(credentials)
    if not creds:
        return

    # Read profile from artifact if not overridden
    if not profile:
        zip_path = build_path or _find_latest_artifact_path()
        if zip_path:
            with zipfile.ZipFile(zip_path) as zf:
                metadata = json.loads(zf.read("tarkin_build.json").decode())
                profile  = metadata.get("profile")

    if not profile:
        _die("No credentials profile specified. Use --profile or ensure the build artifact contains one.")
        return

    prof = _resolve_profile(creds, profile)
    if not prof:
        return

    print(f"Connecting to {prof.safe_repr()}...", end="\r")
    result = check_connection(prof)
    if not result.success:
        _die(f"Connection failed: {result.error}")
        return
    print(f"Connecting to {prof.safe_repr()}... Done.\nConnected on PostgreSQL {result.server_version}.")

    try:
        attach(prof, build_path=build_path)
    except AttachError as exc:
        _die(str(exc))


# =====================================================
# DETACH — remove Tarkin from a live database
# =====================================================

@app.command(name="detach")
def detach_from_database(
    profile:         Optional[str]  = typer.Option(None, "--profile", "-p",
        help="Credentials profile to use."),
    credentials:     Optional[Path] = _credentials_option,
    keep_versioning: bool           = typer.Option(False, "--keep-versioning", "-k",
        help="Retain versioning columns and history when detaching."),
    drop_versioning: bool           = typer.Option(False, "--drop-versioning", "-d",
        help="Drop versioning columns, retaining only current records."),
    no_warn:         bool           = typer.Option(False, "--no-warn", "-n",
        help="Suppress confirmation prompt when dropping versioning data."),
) -> None:
    """
    Remove a Tarkin governance model from a live database.

    If versioned tables exist, you must specify either --keep-versioning
    or --drop-versioning. Use --no-warn to suppress the confirmation
    prompt when dropping versioning data.
    """
    if keep_versioning and drop_versioning:
        _die("Cannot specify both --keep-versioning and --drop-versioning.")
        return

    creds = _load_credentials(credentials)
    if not creds:
        return

    if not profile:
        _die("No credentials profile specified. Use --profile.")
        return

    prof = _resolve_profile(creds, profile)
    if not prof:
        return

    print(f"Connecting to {prof.safe_repr()}...", end="\r")
    result = check_connection(prof)
    if not result.success:
        _die(f"Connection failed: {result.error}")
        return
    print(f"Connecting to {prof.safe_repr()}... Done.\nConnected on PostgreSQL {result.server_version}.")

    try:
        detach(
            prof,
            keep_versioning=keep_versioning,
            drop_versioning=drop_versioning,
            no_warn=no_warn,
        )
    except DetachError as exc:
        _die(str(exc))


# ==================================================================
# PURGE — remove all build artifacts from the Tarkin out/ directory
# ==================================================================


@app.command(name="purge")
def purge_output(
    no_warn: bool = typer.Option(False, "--no-warn", "-n",
        help="Skip confirmation prompt."),
) -> None:
    """Delete all build artifacts and output files from the out/ directory."""
    out_dir = Path("out")

    if not out_dir.exists() or not any(out_dir.iterdir()):
        print("Nothing to purge: directory out/ is empty or does not exist.")
        return

    if not no_warn:
        print("This will delete everything in the out/ directory.")
        response = input("Type 'y' to confirm: ").strip().casefold()
        if response != 'y':
            print("Purge cancelled.")
            return

    import shutil
    shutil.rmtree(out_dir)
    out_dir.mkdir()
    print("Directory out/ purged.")

# =====================================================
# INTERNAL HELPERS
# =====================================================

def _find_latest_artifact_path() -> Path | None:
    from .attach import OUT_DIR
    if not OUT_DIR.exists():
        return None
    artifacts: list[Path] = sorted((p for p in OUT_DIR.glob("tarkin_build_*.zip")), key=lambda p: p.name)
    return artifacts[-1] if artifacts else None

def _load_credentials(path: Optional[Path]) -> CredentialsFile | None:
    try:
        return CredentialsFile.load(path)
    except FileNotFoundError as exc:
        _die(str(exc))
    except ValueError as exc:
        _die(f"Invalid credentials file: {exc}.")


def _resolve_profile(creds: CredentialsFile, profile_name: str) -> ConnectionProfile | None:
    try:
        return creds.get(profile_name)
    except KeyError as exc:
        _die(str(exc))


def _load_and_validate(config: Path) -> GovernanceProject | None:
    if not config.exists():
        _die(f"File not found: {config}")
        return None

    print(f"Loading {config}...", end="\r")
    try:
        proj = YamlLoader.load(config)
    except Exception as exc:
        _die(f"Failed to parse {config}: {exc}")
        return None
    print(f"Loading {config}... Done.")

    if proj:
        print("Validating...", end="\r")
        try:
            SemanticValidator.validate(proj)
        except ValidationError as exc:
            _die(f"Validation failed:\n{exc}")
            return None
        print("Validating... Done.")
        return proj

    return None


def _die(msg: str) -> None:
    """Print an error and exit 1."""
    typer.echo(f"Error: {msg}", err=True)
    raise typer.Exit(1)


def _warn(msg: str) -> None:
    typer.echo(f"Warning: {msg}", err=True)


if __name__ == "__main__":
    app()
