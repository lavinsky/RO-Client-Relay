"""Teste offline de relay/traffic_safety.py: a fronteira de credenciais. Garante que nenhum usuário/senha
do socket de login chega ao consumidor ou ao log, que tráfego HTTP (token/config) nunca é tratado
como pacote RO, e que o jogo normal passa intacto. É a barreira mais sensível do software."""
import _boot  # noqa: F401  (põe o repo no sys.path)
from relay.traffic_safety import (client_packet_to_feed, is_game_sock, is_login_sock, looks_like_http,
                          redact_login, sanitize)

# --- classificação de sockets -----------------------------------------------------------------
assert is_login_sock('127.0.0.1:6900') and is_login_sock('10.0.0.1:3000')
assert not is_login_sock('127.0.0.1:5121')             # socket de jogo
assert is_game_sock('1.2.3.4:5121') and not is_game_sock('1.2.3.4:3000') and not is_game_sock('1.2.3.4:6700')
print('classificação de sockets ok')

# --- looks_like_http: bytes HTTP/token não são pacotes RO -------------------------------------
for h in (b'POST /login', b'GET /x', b'HTTP/1.1', b'PUT /a', b'HEAD /', b'--boundary'):
    assert looks_like_http(h), h
assert not looks_like_http(bytes.fromhex('64000a00'))  # 0x0064 login RO: não é HTTP
assert not looks_like_http(b'\x5f\x03\x00')            # 035f andar
assert not looks_like_http(b'')
print('looks_like_http ok')

# --- redact_login: 0x0064 mantém só id/versão/clienttype; resto do login vira None ------------
login = b'\x64\x00' + (1234).to_bytes(4, 'little') + b'meu_usuario'.ljust(24, b'\0') + \
        b'minha_senha_secreta'.ljust(24, b'\0') + b'\x11'      # 55 bytes: ZC pedido de login
assert len(login) == 55
limpo = redact_login(login)
assert limpo is not None and len(limpo) == 55
assert limpo[:6] == login[:6]                          # id + versão preservados
assert limpo[6:54] == bytes(48)                        # usuário e senha zerados
assert limpo[54:] == login[54:]                        # clienttype preservado
assert b'meu_usuario' not in limpo and b'minha_senha_secreta' not in limpo
assert redact_login(b'\x64\x00' + bytes(10)) is None   # tamanho errado: nunca alimentado
assert redact_login(b'\x00\x02' + bytes(53)) is None   # outro id no socket de login: nunca alimentado
print('redact_login ok')

# --- client_packet_to_feed: o portão único do que o consumidor pode ver -----------------------
game = bytes.fromhex('3704d935960607')                 # ataque, socket de jogo
assert client_packet_to_feed('1.2.3.4:5121', game) == game   # jogo passa intacto
assert client_packet_to_feed('1.2.3.4:6900', login)[6:54] == bytes(48)   # login redigido
assert client_packet_to_feed('1.2.3.4:6900', game) is None   # send não-0064 no login: barrado
assert client_packet_to_feed('1.2.3.4:6900', b'POST /auth') is None      # HTTP no login: barrado
assert client_packet_to_feed('1.2.3.4:5121', b'POST /auth') is None      # HTTP mesmo no jogo: barrado
assert client_packet_to_feed('1.2.3.4:5121', b'') is None    # vazio: barrado
print('client_packet_to_feed ok')

# --- sanitize: o que vai para o log/console não pode carregar credenciais ---------------------
m = sanitize({'tag': 'SEND', 'sock': '1.2.3.4:6900', 'C': login.hex(), 'P': login.hex()})
assert m['C'].endswith('..redacted') and m['P'].endswith('..redacted')
assert 'meu_usuario'.encode().hex() not in m['C']
m2 = sanitize({'tag': 'RECV-HTTP', 'sock': '1.2.3.4:3000', 'C': b'HTTP/1.1 200 OK token=abc'.hex()})
assert m2['C'].endswith('..redacted')                  # HTTP redigido por conteúdo
m3 = sanitize({'tag': 'SEND', 'sock': '1.2.3.4:5121', 'C': game.hex()})
assert m3['C'] == game.hex()                           # send de jogo normal: intacto no log
m4 = sanitize({'tag': 'RECV', 'sock': '1.2.3.4:5121', 'C': b'POSTlike'.hex()})
assert m4['C'].endswith('..redacted')                  # qualquer coisa com cara de HTTP é redigida
print('sanitize ok')
print('ALL PASS')
