# ☁️ s3-demo — Prova de Conceito (POC) de Autenticação JWT com S3 & Multi-Tier Caching

Esta aplicação demonstra a integração prática da biblioteca **`auth-lib`** em um ecossistema **Quarkus 3.17.7 (Java 21)** de alto desempenho, utilizando **Amazon S3 / LocalStack** para distribuição e rotação dinâmica de chaves públicas (**JWKS**) sem impacto no caminho crítico de validação (*zero-latency / hot-path memory validation*).

---

## 🏗️ Arquitetura da Solução

```
                    ┌─────────────────────────┐
                    │     Cliente HTTP        │
                    └───────────┬─────────────┘
                                │ Bearer Token
                                ▼
                    ┌─────────────────────────┐
                    │      AuthService        │
                    └───────────┬─────────────┘
                                │ Introspect
                                ▼
            ┌─────────────────────────────────────────┐
            │       Level 1: InMemory Cache (L1)      │ ──► [HIT] Validação em sub-microsegundos (RAM)
            └───────────────────┬─────────────────────┘
                                │ (MISS)
                                ▼
            ┌─────────────────────────────────────────┐
            │   Level 2: MemoryPolling Cache (L2)     │ ──► [HIT] RAM sincronizada via Polling
            └───────────────────┬─────────────────────┘
                                │ (MISS)
                                ▼
            ┌─────────────────────────────────────────┐
            │    Level 3: S3AsyncSource Fallback (L3) │ ──► [FALLBACK] I/O Assíncrono no S3 via S3BucketReader
            └───────────────────┬─────────────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │      LocalStack S3      │
                    │   (auth-bucket/jwks)    │
                    └─────────────────────────┘
```

---

## ⚡ Componentes e Responsabilidades

| Componente | Responsabilidade | I/O no Caminho Crítico? |
| :--- | :--- | :--- |
| **[S3BucketReader](file:///home/jefferson/IdeaProjects/auth-lib/s3-demo/src/main/java/knin/auth/jwt/demo/S3BucketReader.java)** | Responsabilidade única de comunicação com a AWS SDK v2 (`getObjectBytes` e `headObject`). | Somente sob demanda |
| **[MemoryPolling](file:///home/jefferson/IdeaProjects/auth-lib/s3-demo/src/main/java/knin/auth/jwt/demo/MemoryPolling.java)** | Polling em background a cada 10s via `HeadObject` (ETag). Atualiza a RAM atômica (`AtomicReference`) quando detecta nova chave no S3. | ❌ **Não (Zero I/O)** |
| **[S3AsyncSource](file:///home/jefferson/IdeaProjects/auth-lib/s3-demo/src/main/java/knin/auth/jwt/demo/S3AsyncSource.java)** | Fallback de Nível 3 para recuperação just-in-time no S3 caso uma chave ainda não esteja no cache em RAM. | ⚠️ Apenas em miss total |
| **[JwtSigner](file:///home/jefferson/IdeaProjects/auth-lib/s3-demo/src/main/java/knin/auth/jwt/demo/JwtSigner.java)** | Assinatura de tokens JWT utilizando a chave privada RSA (carregada com suporte a hot-reload). | ❌ Não |

---

## 🚀 Como Executar a POC

### Pré-requisitos

- **Java 21**
- **Maven 3.9+**
- **Docker & Docker Compose** (para o LocalStack)
- **Python 3** (com `cryptography` e `requests` para o script de rotação)

---

### 1. Iniciar o LocalStack (S3 Local)

```bash
docker compose up -d
```

---

### 2. Gerar Chaves RSA e Publicar JWKS no S3

Execute o script de automação para gerar o par de chaves RSA 2048, calcular o KID RFC 7638 e publicar no bucket S3:

```bash
python3 s3-demo/scripts/generate_keys_and_upload_s3.py
```

*Saída esperada:*

```text
[+] Active Private Key saved to external secret mount: .../secrets/private_key.pem
[+] New Active RFC 7638 KID: 'RtF_RltMeaPRS5wA6O9q4O0960tWE8660AQBqo5xGuY'
[+] Successfully uploaded rotated JWKS to S3! (status 200)
```

---

### 3. Iniciar o Servidor Quarkus

```bash
mvn quarkus:dev -f s3-demo/pom.xml
```

A aplicação estará disponível em `http://localhost:8080`.

---

## 📡 Endpoints da API

### 1. Gerar Token JWT Assinado

```bash
curl -X POST http://localhost:8080/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "usuario-demo@empresa.com",
    "scopes": ["read", "write", "admin"],
    "expirationMillis": 3600000
  }'
```

*Resposta:*

```json
{
  "token": "eyJraWQiOiJSdEZfUmx0TWVhUFJTNXdB...",
  "kid": "RtF_RltMeaPRS5wA6O9q4O0960tWE8660AQBqo5xGuY",
  "subject": "usuario-demo@empresa.com",
  "scopes": ["read", "write", "admin"]
}
```

---

### 2. Validar Token JWT (Introspecção)

```bash
curl -X POST http://localhost:8080/api/auth/verify \
  -H "Authorization: Bearer <SEU_JWT_AQUI>"
```

*Resposta de Sucesso:*

```json
{
  "valid": true,
  "hasRequiredScope": true,
  "kid": "RtF_RltMeaPRS5wA6O9q4O0960tWE8660AQBqo5xGuY",
  "scopes": ["read", "write", "admin"],
  "formattedJwt": "JWT { ... }",
  "message": "Token is valid and authorized"
}
```

---

### 3. Consultar JWKS Público

```bash
curl http://localhost:8080/.well-known/jwks.json
```

---

## 🔄 Testando Rotação de Chaves em Tempo Real (Zero Downtime)

1. Gere um token com a chave atual e valide-o.
2. Execute o script de rotação novamente:

   ```bash
   python3 s3-demo/scripts/generate_keys_and_upload_s3.py
   ```

3. O `MemoryPolling` detectará o novo ETag no S3 em poucos segundos.
4. Tokens gerados com a chave anterior **continuam válidos** (o JWKS mantém a chave anterior no array `keys`), enquanto novos tokens com a nova chave passam a ser aceitos imediatamente.

---

## 🧪 Bateria de Testes Automatizados

Para executar os testes de integração, carga e rotação automática:

```bash
mvn clean test -f s3-demo/pom.xml
```
