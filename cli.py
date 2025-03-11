
import click
import tetracrypt

@click.group()
def cli():
    pass

@click.command()
def generate_key():
    """Generate a cryptographic key pair."""
    public_key, private_key = tetracrypt.generate_key()
    click.echo(f"Public Key: {public_key}\nPrivate Key: {private_key}")

@click.command()
@click.argument('message')
@click.argument('private_key')
def sign(message, private_key):
    """Sign a message."""
    signature = tetracrypt.sign_message(message, private_key)
    click.echo(f"Signature: {signature}")

@click.command()
@click.argument('message')
@click.argument('signature')
@click.argument('public_key')
def verify(message, signature, public_key):
    """Verify a signed message."""
    valid = tetracrypt.verify_signature(message, signature, public_key)
    click.echo("Verification successful" if valid else "Verification failed")

@click.command()
def benchmark():
    """Run performance benchmarks."""
    tetracrypt.run_benchmarks()

cli.add_command(generate_key)
cli.add_command(sign)
cli.add_command(verify)
cli.add_command(benchmark)

if __name__ == "__main__":
    cli()
