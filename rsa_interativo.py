from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# --- Funções Auxiliares ---
# no cmd = cd C:\Users\marcos96\Downloads
# python rsa_interativo.py
"""Siga as instruções do menu:
Primeiro passo obrigatório: Escolha a opção 5 para gerar as chaves.
O programa exibirá as chaves pública e privada.
Depois: Escolha a opção 6, digite uma mensagem secreta e pressione Enter.
O programa mostrará o texto original e o texto encriptado em bytes.
Finalmente: Escolha a opção 7. O programa usará a chave privada para decriptar
a última mensagem e mostrará que o texto decriptado é idêntico ao original.
Você pode gerar novas chaves (opção 5) a qualquer momento. Note que ao fazer isso,
você só poderá decriptar mensagens que foram encriptadas com a nova chave pública.
"""
def gerar_chaves():
    """
    Gera um novo par de chaves RSA (privada e pública) e as exibe no formato PEM.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Serializa as chaves para o formato PEM para poderem ser exibidas/salvas
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Requisito 0: A geração das chaves (mostrar as chaves geradas)
    print("--- 0. Geração das Chaves ---")
    print("\n[SUCESSO] Novas chaves foram geradas.\n")
    print("Chave Privada (guarde com segurança):")
    print(private_pem.decode('utf-8'))
    print("Chave Pública (pode ser compartilhada):")
    print(public_pem.decode('utf-8'))
    
    return private_key, public_key

def encriptar_mensagem(public_key, mensagem_original):
    """
    Encripta uma mensagem usando a chave pública fornecida.
    """
    # Converte a mensagem de string para bytes, pois a criptografia opera em bytes
    mensagem_bytes = mensagem_original.encode('utf-8')
    
    ciphertext = public_key.encrypt(
        mensagem_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decriptar_mensagem(private_key, ciphertext):
    """
    Decripta uma mensagem (bytes) usando a chave privada fornecida.
    """
    plaintext_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Converte os bytes decriptados de volta para string
    return plaintext_bytes.decode('utf-8')

def mostrar_menu():
    """
    Exibe o menu de opções para o usuário.
    """
    print("\n" + "="*40)
    print("   ATIVIDADE DE CRIPTOGRAFIA RSA")
    print("="*40)
    print("4. Escolha uma das opções abaixo:")
    print("   5. Gerar novo par de chaves")
    print("   6. Encriptar uma mensagem")
    print("   7. Decriptar a última mensagem")
    print("   0. Sair do programa")
    print("-"*40)

# --- Programa Principal ---

if __name__ == "__main__":
    private_key = None
    public_key = None
    ultima_mensagem_encriptada = None

    print("Bem-vindo ao exemplo prático de RSA!")
    print("Para começar, gere um par de chaves na opção 5.")

    while True:
        mostrar_menu()
        escolha = input("Digite sua escolha: ")

        if escolha == '5':
            # Requisito 5: Gerar novas chaves
            private_key, public_key = gerar_chaves()

        elif escolha == '6':
            # Requisito 6: Encriptar uma mensagem digitada pelo usuário
            if public_key is None:
                print("\n[ERRO] Você precisa gerar as chaves primeiro! (Escolha a opção 5).")
                continue
            
            mensagem = input("Digite a mensagem que deseja encriptar: ")
            
            # Requisito 1: O texto original
            print("\n--- Processo de Encriptação ---")
            print(f"1. Texto Original: {mensagem}")
            
            ultima_mensagem_encriptada = encriptar_mensagem(public_key, mensagem)
            
            # Requisito 2: O texto encriptado (bytes)
            print(f"2. Texto Encriptado (bytes): {ultima_mensagem_encriptada}")
            print("\n[SUCESSO] Mensagem encriptada e armazenada.")

        elif escolha == '7':
            # Requisito 7: Decriptar a mensagem
            if private_key is None:
                print("\n[ERRO] Nenhuma chave privada foi gerada para decriptar. (Escolha a opção 5).")
                continue
            if ultima_mensagem_encriptada is None:
                print("\n[ERRO] Nenhuma mensagem foi encriptada ainda. (Escolha a opção 6).")
                continue

            print("\n--- Processo de Decriptação ---")
            print(f"Decriptando a mensagem: {ultima_mensagem_encriptada}")
            
            mensagem_decriptada = decriptar_mensagem(private_key, ultima_mensagem_encriptada)

            # Requisito 3: O texto decriptado (igual ao original)
            print(f"3. Texto Decriptado: {mensagem_decriptada}")
            print("\n[SUCESSO] Mensagem decriptada com êxito.")

        elif escolha == '0':
            print("\nSaindo do programa. Obrigado!")
            break

        else:
            print("\n[ERRO] Opção inválida. Por favor, tente novamente.")
