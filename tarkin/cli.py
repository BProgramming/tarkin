from __future__ import annotations
import typer
from importlib.metadata import version
from pathlib import Path
from typing import Optional

from .credentials import (
    CredentialsFile, DEFAULT_CREDENTIALS_PATH,
    test_connection, test_all_connections, ConnectionProfile,
)
from .inspect import inspect_database
from .model import GovernanceProject, UserConfig
from .yaml import YamlLoader
from .validate import SemanticValidator, ValidationError
from .serialize import Serializer

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
                result = test_connection(p)
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
        _die(f"Credentials {credentials!r} not found.")
    else:
        prof  = _resolve_profile(creds, profile)

        if not prof:
            _die(f"Profile {profile!r} not found.")
        else:
            # Test connection first — fail fast with a clear message
            print(f"Connecting to {prof.safe_repr()}...", end="\r")
            result = test_connection(prof)
            if not result.success:
                _die(f"Connection failed: {result.error}")
            print(f"Connecting to {prof.safe_repr()}... Connected on PostgreSQL {result.server_version}.")

            # Validate the db user appears in the output yaml
            db_user = result.db_user

            print("Inspecting database...", end="\r")
            try:
                proj = inspect_database(prof)
                print("Inspecting database... Done.")
            except Exception as exc:
                proj = None
                _die(f"Inspection failed: {exc}")

            if proj:
                # Record which profile was used
                proj.database.profile = prof.profile

                # Confirm the connected user is present in the inspected users
                user_names = {u.username for u in proj.users}
                if db_user and db_user not in user_names:
                    _warn(
                        f"Connected as {db_user!r} but this user was not found in the database's "
                        f"user list. The credentials profile may be using a role that exists outside "
                        f"the standard pg_roles view, or may lack login privilege. "
                        f"Tarkin has recorded it in your YAML as an inactive placeholder."
                    )
                    proj.users.append(UserConfig(username=db_user, active=True, roles=[]))

                if validate:
                    print("Validating inspected model...", end="\r")
                    try:
                        SemanticValidator.validate(proj)
                        print("Validating inspected model... Passed.")
                    except ValidationError as exc:
                        # Validation errors on an inspected DB are warnings, not fatal —
                        # the live DB may have things Tarkin doesn't model yet.
                        _warn(f"Semantic validation found issues. Review before attaching:\n{exc}")

                yaml_str = Serializer.to_yaml_string(proj)

                if output is None:
                    output = Path(f"{prof.database}_model.yaml")
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
# BUILD — parse, validate, write canonical form
# =====================================================

@app.command(name="build")
def build_data_model_from_yaml(
    config: Path            = typer.Argument(..., help="Path to governance YAML."),
    output: Optional[Path]  = _output_option,
) -> None:
    """Parse a Tarkin YAML, validate it, and write the canonical form back out."""
    proj = _load_and_validate(config)

    if proj:
        if output is None:
            output = config.with_stem(config.stem + "_out")

        yaml_str = Serializer.to_yaml_string(proj)
        output.write_text(yaml_str, encoding="utf-8")
        print(f"Written to {output}")


# =====================================================
# ATTACH / DETACH — not yet implemented
# =====================================================

@app.command(name="attach")
def attach_to_database(
    config:      Path            = typer.Argument(..., help="Path to governance YAML."),
    profile:     Optional[str]   = typer.Option(None, "--profile", "-p",
        help="Override the credentials profile in the YAML."),
    credentials: Optional[Path]  = _credentials_option,
) -> None:
    """Apply a Tarkin governance model to a live database. (not yet implemented)"""
    raise NotImplementedError("attach is not yet implemented.")


@app.command(name="detach")
def detach_from_database(
    profile:     str            = _profile_option,
    credentials: Optional[Path] = _credentials_option,
) -> None:
    """Remove a Tarkin governance model from a live database. (not yet implemented)"""
    raise NotImplementedError("detach is not yet implemented.")


# =====================================================
# INTERNAL HELPERS
# =====================================================

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

    print(f"Loading {config}...", end="\r")
    try:
        proj = YamlLoader.load(config)
    except Exception as exc:
        proj = None
        _die(f"Failed to parse {config}: {exc}")
    print(f"Loading {config}... Done.")

    if proj:
        print("Validating...", end="\r")
        try:
            SemanticValidator.validate(proj)
        except ValidationError as exc:
            _die(f"Validation failed:\n{exc}")
        print("Validating... Done.")

        return proj
    else:
        return None


def _die(msg: str) -> None:
    """Print an error and exit 1."""
    typer.echo(f"Error: {msg}", err=True)
    raise typer.Exit(1)


def _warn(msg: str) -> None:
    typer.echo(f"Warning: {msg}", err=True)


if __name__ == "__main__":
    app()
