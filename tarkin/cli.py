"""Tarkin command-line interface."""
from __future__ import annotations
import subprocess
import sys
import typer
import json
import zipfile
from importlib.metadata import version
from pathlib import Path
from typing import Optional

from .attach import attach, AttachError, OUT_DIR
from .detach import detach, DetachError
from .erase import erase_check, erase_apply, EraseError
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
from .diff import diff_projects, render_diff

app = typer.Typer(no_args_is_help=True, help="Tarkin: governance compiler for PostgreSQL.")


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


@app.command(name="help")
def show_help() -> None:
    """Alias for ``tarkin --help``."""
    subprocess.run([sys.argv[0], "--help"])


@app.command(name="version")
def show_version() -> None:
    """Show the installed Tarkin version and exit."""
    print(version("tarkin"))


@app.command(name="connect")
def test_connections(
    credentials: Optional[Path] = _credentials_option,
    profile:     Optional[str]  = typer.Option(
        None, "--profile", "-p",
        help="Profile to test. Omit to test all profiles.",
    ),
) -> None:
    """
    Test that one or more credentials profiles can connect to their databases.

    Without --profile, all profiles in the credentials file are tested.
    """
    creds = _load_credentials(credentials)

    if creds:
        if profile:
            try:
                p      = creds.get(profile)
                result = check_connection(p)
                print(result)
            except KeyError as exc:
                _die(str(exc))
        else:
            results = test_all_connections(creds)
            for r in results:
                print(r)


@app.command(name="inspect")
def inspect_database_build_yaml(
    profile:     str            = _profile_option,
    output:      Optional[Path] = _output_option,
    credentials: Optional[Path] = _credentials_option,
    validate:    bool           = typer.Option(
        True, "--validate/--no-validate",
        help="Run semantic validation on the inspected model before writing.",
    ),
) -> None:
    """
    Inspect a live PostgreSQL database and emit a Tarkin governance YAML.

    Connects using the named profile from credentials.toml, captures the full
    database structure (schemas, tables, columns, indexes, foreign keys,
    sequences, views, functions, roles, and grants), and writes a governance
    YAML to 'out/<database>_model.yaml' (or the path given by --output).

    The YAML can be edited and applied with 'tarkin build' + 'tarkin attach'.
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


@app.command(name="validate")
def validate_data_model(
    config: Path = typer.Argument(..., help="Path to governance YAML."),
) -> None:
    """Parse and semantically validate a Tarkin governance YAML."""
    _load_and_validate(config)
    print("Validation passed.")


@app.command(name="build")
def build_data_model_from_yaml(
    config:      Path           = typer.Argument(..., help="Path to governance YAML."),
    profile:     Optional[str]  = typer.Option(
        None, "--profile", "-p",
        help="Override the credentials profile specified in the YAML.",
    ),
    credentials: Optional[Path] = _credentials_option,
    output:      Optional[Path] = _output_option,
) -> None:
    """
    Compile a governance YAML into a build artifact.

    Connects to the live database, inspects its current state, generates the
    SQL needed to implement the governance model, and writes a .zip artifact
    to 'out/' (or the path given by --output).  The artifact contains the
    generated SQL and build metadata to be used by 'tarkin attach'.
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


@app.command(name="attach")
def attach_to_database(
    build_path:  Optional[Path] = typer.Option(
        None, "--build", "-b",
        help="Path to build artifact zip. Defaults to the latest artifact in out/.",
    ),
    profile:     Optional[str]  = typer.Option(
        None, "--profile", "-p",
        help="Override the credentials profile in the build artifact.",
    ),
    credentials: Optional[Path] = _credentials_option,
) -> None:
    """
    Apply a Tarkin build artifact to a live database.

    Verifies that the live database state matches the checksum recorded in the
    build artifact, then executes the generated SQL. The database can be restored
    to its pre-attach state with 'tarkin detach'.

    If --build is omitted, the most recent artifact in 'out/' is used.
    """
    creds = _load_credentials(credentials)
    if not creds:
        return

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

@app.command(name="detach")
def detach_from_database(
    profile:            Optional[str]  = typer.Option(
        None, "--profile", "-p",
        help="Credentials profile to use.",
    ),
    credentials:        Optional[Path] = _credentials_option,
    keep_versioning:    bool           = typer.Option(
        False, "--keep-versioning", "-k",
        help="Retain versioning columns and history when detaching.",
    ),
    drop_versioning:    bool           = typer.Option(
        False, "--drop-versioning", "-d",
        help="Drop versioning columns, retaining only current records.",
    ),
    no_warn:            bool           = typer.Option(
        False, "--no-warn", "-n",
        help="Suppress the confirmation prompt when dropping versioning data.",
    ),
    no_restore_grants:  bool           = typer.Option(
        False, "--no-restore-grants", "-g",
        help="Skip restoring prior database grants.",
    ),
) -> None:
    """
    Remove a Tarkin governance model from a live database.

    Reverses all changes made by 'tarkin attach': drops Tarkin-managed views
    and triggers, restores previously revoked grants, drops roles that Tarkin
    created, renames shadow schemas back to their original names, drops
    __META__, and resets the tarkin.hmac_key GUC.

    If versioned tables exist, one of --keep-versioning or --drop-versioning
    must be specified. Use --no-warn to suppress the confirmation prompt.
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
            keep_versioning   = keep_versioning,
            drop_versioning   = drop_versioning,
            no_warn           = no_warn,
            no_restore_grants = no_restore_grants,
        )
    except DetachError as exc:
        _die(str(exc))


@app.command(name="diff")
def diff_yaml(
    before:  Path           = typer.Argument(..., help="Path to the baseline governance YAML."),
    after:   Path           = typer.Argument(..., help="Path to the target governance YAML."),
    output:  Optional[Path] = _output_option,
) -> None:
    """
    Compare two governance YAMLs and report all differences.

    Produces a structured Markdown diff report written to
    'out/diff_<before>_<after>.md' (or the path given by --output).
    """
    before_proj = _load_and_validate(before)
    after_proj  = _load_and_validate(after)

    if not before_proj or not after_proj:
        return

    changes = diff_projects(before_proj, after_proj)

    if output is None:
        before_stem = before.stem
        after_stem  = after.stem
        output = Path("out") / f"diff_{before_stem}_{after_stem}.md"

    render_diff(changes, output)

    if changes:
        print(f"{len(changes)} change(s) detected. Report written to {output}.")
    else:
        print(f"No changes detected. Report written to {output}.")


@app.command(name="erase")
def erase_subject(
    profile:     str            = _profile_option,
    credentials: Optional[Path] = _credentials_option,
    column:      list[str]      = typer.Option(
        ..., "--column", "-col",
        help="Identifier column name to match on. Repeat for multiple columns.",
    ),
    value:       list[str]      = typer.Option(
        ..., "--value", "-val",
        help="Value corresponding to each --column (in the same order). Repeat for multiple values.",
    ),
    check:       bool           = typer.Option(
        False, "--check",
        help="Preview which rows would be affected without modifying any data.",
    ),
    apply:       bool           = typer.Option(
        False, "--apply",
        help="Execute the erasure and log the result to __META__.tarkin_erasures.",
    ),
    output:      Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Directory to write the result JSON. Defaults to 'out/'.",
    ),
) -> None:
    """
    Erase data subject records from a Tarkin-attached database.

    Calls __META__.tarkin_erase_check (with --check) or
    __META__.tarkin_erase_apply (with --apply) on the live database.

    --check previews the rows that would be affected and writes the result to
    a timestamped JSON in 'out/' (or --output).

    --apply executes the erasure according to each table's erase_strategy,
    logs the operation to __META__.tarkin_erasures, and writes a result JSON.

    Exactly one of --check or --apply must be specified.
    """
    if check == apply:
        _die("Specify exactly one of --check or --apply.")
        return

    if len(column) != len(value):
        _die(f"Provide the same number of --column and --value arguments ({len(column)} vs {len(value)}).")
        return

    creds = _load_credentials(credentials)
    if not creds:
        return

    prof = _resolve_profile(creds, profile)
    if not prof:
        return

    out_dir = output or Path("out")

    print(f"Connecting to {prof.safe_repr()}...", end="\r")
    result = check_connection(prof)
    if not result.success:
        _die(f"Connection failed: {result.error}")
        return
    print(f"Connecting to {prof.safe_repr()}... Done.")

    try:
        if check:
            rows = erase_check(prof, list(column), list(value), out_dir=out_dir)
            print(f"\nErase check results ({len(rows)} table(s) matched):")
            for row in rows:
                print(
                    f"  {row['schema_name']}.{row['table_name']}"
                    f"  strategy={row['erase_strategy']}"
                    f"  rows_matched={row['rows_matched']}"
                )
            if not rows:
                print("  No matching rows found.")
        else:
            rows = erase_apply(prof, list(column), list(value), out_dir=out_dir)
            print(f"\nErase apply results ({len(rows)} table(s) affected):")
            for row in rows:
                print(
                    f"  {row['schema_name']}.{row['table_name']}"
                    f"  strategy={row['erase_strategy']}"
                    f"  rows_affected={row['rows_affected']}"
                )
            if not rows:
                print("  No matching rows found.")
    except EraseError as exc:
        _die(str(exc))


@app.command(name="purge")
def purge_output(
    no_warn: bool = typer.Option(
        False, "--no-warn", "-n",
        help="Skip the confirmation prompt.",
    ),
) -> None:
    """
    Delete all build artifacts and output files from the 'out/' directory.

    Use --no-warn to skip the confirmation prompt.
    """
    out_dir = Path("out")

    if not out_dir.exists() or not any(out_dir.iterdir()):
        print("Nothing to purge: directory out/ is empty or does not exist.")
        return

    if not no_warn:
        print("This will delete everything in the out/ directory.")
        response = input("Type 'y' to confirm: ").strip().casefold()
        if response != "y":
            print("Purge cancelled.")
            return

    import shutil
    shutil.rmtree(out_dir)
    out_dir.mkdir()
    print("Directory out/ purged.")


def _find_latest_artifact_path() -> Path | None:
    """Return the path to the most recently created build artifact, or None."""
    if not OUT_DIR.exists():
        return None
    artifacts: list[Path] = sorted(
        (p for p in OUT_DIR.glob("tarkin_build_*.zip")),
        key=lambda p: p.name,
    )
    return artifacts[-1] if artifacts else None


def _load_credentials(path: Optional[Path]) -> CredentialsFile | None:
    """Load and return a credentials file, or die with an error."""
    try:
        return CredentialsFile.load(path)
    except FileNotFoundError as exc:
        _die(str(exc))
    except ValueError as exc:
        _die(f"Invalid credentials file: {exc}.")
    return None


def _resolve_profile(creds: CredentialsFile, profile_name: str) -> ConnectionProfile | None:
    """Resolve a named profile from a credentials file, or die with an error."""
    try:
        return creds.get(profile_name)
    except KeyError as exc:
        _die(str(exc))
    return None


def _load_and_validate(config: Path) -> GovernanceProject | None:
    """Load a governance YAML, validate it, and return the project, or die."""
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
    """Print an error message to stderr and exit with code 1."""
    typer.echo(f"Error: {msg}", err=True)
    raise typer.Exit(1)


def _warn(msg: str) -> None:
    """Print a warning message to stderr."""
    typer.echo(f"Warning: {msg}", err=True)


if __name__ == "__main__":
    app()
