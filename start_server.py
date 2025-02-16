from pki_helpers import generate_private_key, generate_public_key
from pki_helpers import generate_csr, generate_private_key
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from pki_helpers import sign_csr
import subprocess
from server import app


def start_uwsgi():
    subprocess.run(["uwsgi", "--ini", "uwsgi.ini"])


if __name__ == "__main__":
    # Gerar a chave privada da CA
    private_key = generate_private_key("ca-private-key.pem", "secret_password")

    # Gerar a chave pública da CA
    generate_public_key(
        private_key,
        filename="ca-public-key.pem",
        country="BR",
        state="Brasília",
        locality="Brasília",
        org="Minha Autoridade Certificadora",
        hostname="meu-ca.com.br",
    )

    # Gerar a chave privada do servidor
    server_private_key = generate_private_key(
        "server-private-key.pem", "serverpassword"
    )

    # Criar CSR (Certificate Signing Request)
    generate_csr(
        server_private_key,
        filename="server-csr.pem",
        country="US",
        state="Maryland",
        locality="Baltimore",
        org="My Company",
        alt_names=["localhost"],
        hostname="my-site.com",
    )

    # Carregar CSR
    with open("server-csr.pem", "rb") as csr_file:
        csr = x509.load_pem_x509_csr(csr_file.read(), default_backend())

    # Carregar chave pública da CA
    with open("ca-public-key.pem", "rb") as ca_public_key_file:
        ca_public_key = x509.load_pem_x509_certificate(
            ca_public_key_file.read(), default_backend()
        )

    # Carregar chave privada da CA com senha fornecida diretamente
    with open("ca-private-key.pem", "rb") as ca_private_key_file:
        ca_private_key = serialization.load_pem_private_key(
            ca_private_key_file.read(),
            password=b"secret_password",  # Senha fornecida diretamente
            backend=default_backend(),
        )

    # Assinar CSR com a chave privada da CA
    sign_csr(csr, ca_public_key, ca_private_key, "server-public-key.pem")

    app.run(
        ssl_context=("server-public-key.pem", "server-private-key.pem"),
        host="0.0.0.0",
        port=5683,
    )
