# pki_helpers.py

# Importa bibliotecas necessárias para criptografia e manipulação de certificados
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID


def generate_private_key(filename: str, passphrase: str):
    """
    Gera uma chave privada RSA e a salva em um arquivo PEM com proteção por senha.

    Args:
        filename (str): Nome do arquivo onde a chave será salva.
        passphrase (str): Senha para criptografar a chave privada.

    Returns:
        private_key: Objeto da chave privada RSA.
    """
    # Gera uma chave privada RSA de 2048 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # Converte a senha para bytes UTF-8 e define o algoritmo de criptografia da chave
    utf8_pass = passphrase.encode("utf-8")
    algorithm = serialization.BestAvailableEncryption(utf8_pass)

    # Salva a chave privada no arquivo especificado em formato PEM
    with open(filename, "wb") as keyfile:
        keyfile.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=algorithm,
            )
        )

    return private_key


def generate_public_key(private_key, filename, **kwargs):
    """
    Gera um certificado digital autoassinado (CA) a partir de uma chave privada.

    Args:
        private_key: Chave privada utilizada para assinar o certificado.
        filename (str): Nome do arquivo onde o certificado será salvo.
        **kwargs: Informações sobre o dono do certificado (país, estado, cidade, organização, nome comum).

    Returns:
        public_key: Certificado gerado.
    """
    # Define os atributos do certificado (país, estado, cidade, etc.)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs["country"]),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, kwargs["state"]),
            x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs["locality"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, kwargs["org"]),
            x509.NameAttribute(NameOID.COMMON_NAME, kwargs["hostname"]),
        ]
    )

    # Como o certificado é autoassinado, o emissor é o próprio sujeito
    issuer = subject

    # Define a validade do certificado por 30 dias
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=30)

    # Constrói o certificado
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )

    # Assina o certificado com a chave privada
    public_key = builder.sign(private_key, hashes.SHA256(), default_backend())

    # Salva o certificado em um arquivo no formato PEM
    with open(filename, "wb") as certfile:
        certfile.write(public_key.public_bytes(serialization.Encoding.PEM))

    return public_key


def generate_csr(private_key, filename, **kwargs):
    """
    Gera um CSR (Certificate Signing Request) para solicitar um certificado.

    Args:
        private_key: Chave privada usada para assinar a CSR.
        filename (str): Nome do arquivo onde a CSR será salva.
        **kwargs: Informações do certificado (país, estado, cidade, organização, nome comum e nomes alternativos).

    Returns:
        csr: Objeto CSR gerado.
    """
    # Define os atributos do CSR (país, estado, cidade, etc.)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs["country"]),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, kwargs["state"]),
            x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs["locality"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, kwargs["org"]),
            x509.NameAttribute(NameOID.COMMON_NAME, kwargs["hostname"]),
        ]
    )

    # Gera os nomes alternativos (SAN - Subject Alternative Names)
    alt_names = []
    for name in kwargs.get("alt_names", []):
        alt_names.append(x509.DNSName(name))
    san = x509.SubjectAlternativeName(alt_names)

    # Constrói o CSR com os atributos e a extensão de nomes alternativos
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(san, critical=False)
    )

    # Assina o CSR com a chave privada e o algoritmo SHA256
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())

    # Salva o CSR em um arquivo no formato PEM
    with open(filename, "wb") as csrfile:
        csrfile.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr


def sign_csr(csr, ca_public_key, ca_private_key, new_filename):
    """
    Assina um CSR com a chave privada da CA e gera um certificado assinado.

    Args:
        csr: O CSR a ser assinado.
        ca_public_key: Certificado da CA que assina o CSR.
        ca_private_key: Chave privada da CA usada para assinar o CSR.
        new_filename (str): Nome do arquivo onde o certificado gerado será salvo.

    Returns:
        public_key: Certificado assinado gerado.
    """
    # Define o período de validade do certificado gerado (30 dias)
    valid_from = datetime.utcnow()
    valid_until = valid_from + timedelta(days=30)

    # Constrói o certificado com os dados do CSR
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)  # Nome do certificado será o do CSR
        .issuer_name(ca_public_key.subject)  # O emissor será a CA
        .public_key(csr.public_key())  # Usa a chave pública do CSR
        .serial_number(x509.random_serial_number())  # Número de série único
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
    )

    # Copia todas as extensões do CSR para o certificado gerado
    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)

    # Assina o certificado com a chave privada da CA
    public_key = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    # Salva o certificado gerado em um arquivo no formato PEM
    with open(new_filename, "wb") as keyfile:
        keyfile.write(public_key.public_bytes(serialization.Encoding.PEM))
