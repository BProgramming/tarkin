import typer

app = typer.Typer()

@app.command()
def version():
    """Show Tarkin version."""
    print("tarkin v0.0.1")

@app.command()
def apply():
    """Apply governance changes."""
    print("Applying governance...")

@app.command()
def validate():
    """Validate configuration."""
    print("Validating configuration...")

if __name__ == "__main__":
    app()
