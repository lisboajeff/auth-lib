# 🔐 auth-lib

Uma biblioteca Java moderna, reativa, não-bloqueante e de alto desempenho para validação, introspecção e recuperação encadeada de chaves criptográficas (JWKS / JWT), construída sobre o padrão **Monádico (`Result<T>`)** e **Chain of Responsibility**.

---

## 🚀 Destaques da Arquitetura

- ⚡ **100% Assíncrona & Não-Bloqueante**: Operações baseadas em `CompletableFuture` com suporte nativo a pipelines reativos.
- 🛡️ **Padrão Monádico (`Result<T>`)**: Elimina completamente o uso de exceções em tempo de execução para controle de fluxo. Retornos previsíveis e tipados (`SuccessResult`, `FailedResult`, `EmptyResult`).
- 🔗 **Cadeia de Resolução Multinível (`TableChain<E>`)**:
  - Resolução hierárquica de chaves criptográficas (ex: L1 Cache local ➔ L2 RAM Polling ➔ L3 Storage / S3 / REST).
  - Deduplicação de requisições concorrentes em voo (*in-flight request coalescing*).
  - Retroalimentação automática de cache (*back-propagation / set*).
- 📜 **Abstração de Log Desacoplada (`Log`)**: Zero dependências de frameworks externos de log (Logback, SLF4J, Log4j). Totalmente acoplável via Lambdas ou Method References (`logger::info`).
- 🧩 **Suporte a Múltiplos Formatos de Token**: Suporta tanto JWTs padrão RFC 7519 (3 partes) quanto tokens customizados legados (4 partes).

---

## 📦 Instalação

Adicione a dependência ao seu `pom.xml`:

```xml
<dependency>
    <groupId>knin.auth.jwt</groupId>
    <artifactId>auth-lib</artifactId>
    <version>0.0.1</version>
</dependency>
```

---

## 🏛️ Estrutura e Componentes Principais

```
knin.auth.jwt
├── adapter
│   ├── retriever
│   │   ├── InMemory.java          # L1 Cache em RAM com ConcurrentHashMap e sincronização
│   │   ├── Source.java            # Interface de provedor de dados de chaves
│   │   └── SourceChain.java       # Elo da cadeia que conecta um Source ao próximo nível
│   └── validate
│       ├── TokenHandleProxy.java  # Extração de KID, decode e validação criptográfica
│       └── TokenUtil.java         # Parser e validador de claims e assinaturas
├── domain
│   ├── logging
│   │   └── Log.java               # Interface pura e funcional de logging
│   ├── result
│   │   ├── Result.java            # Mônada principal (success, failed, empty)
│   │   ├── SuccessResult.java     # Resultado com valor computado
│   │   ├── FailedResult.java      # Resultado com falha/exceção capturada
│   │   └── EmptyResult.java       # Resultado vazio (sem valor / não encontrado)
│   ├── retriever
│   │   ├── Chain.java             # Contrato funcional de recuperação
│   │   ├── JsonWebKeys.java       # Abstração de chaves públicas carregadas
│   │   ├── Keys.java              # Interface de consulta por KID
│   │   └── TableChain.java        # Estrutura base da Chain of Responsibility
│   └── validate
│       ├── JWT.java               # Wrapper de Token validado
│       ├── Token.java             # Contrato de claims, scopes e expiração
│       └── TokenHandle.java       # Parser de headers e validação de assinatura
├── factory
│   └── AuthFactory.java           # Fábrica unificada para construção da cadeia e Introspect
└── option
    ├── Introspect.java            # Ponto de entrada de validação e introspecção
    └── Introspection.java         # Resultado da introspecção (token, status, claims)
```

---

## 💡 Guia de Uso

### 1. Construção da Cadeia de Autenticação

Utilize a [AuthFactory](file:///home/jefferson/IdeaProjects/auth-lib/src/main/java/knin/auth/jwt/factory/AuthFactory.java) para montar a cadeia com os níveis desejados:

```java
import knin.auth.jwt.factory.AuthFactory;
import knin.auth.jwt.option.Introspect;
import knin.auth.jwt.domain.retriever.TableChain;
import knin.auth.jwt.domain.validate.TokenHandle;

AuthFactory authFactory = new AuthFactory();
TokenHandle tokenHandle = authFactory.createTokenHandle();

// Nível 2: Provedor assíncrono customizado (Ex: MemoryPolling, Redis, Banco, etc.)
TableChain<String> l2SourceChain = authFactory.createSource(tokenHandle, customSource);

// Nível 1 + Introspect: Cria o L1 InMemory automaticamente e entrega o Introspect
Introspect introspect = authFactory.createIntrospect(tokenHandle, l2SourceChain, System.out::println);
```

---

### 2. Validação e Introspecção de Tokens

A chamada ao método `introspect(jwt)` retorna um `CompletableFuture<Result<Introspection>>`:

```java
introspect.introspect(rawJwtToken)
    .thenAccept(result -> {
        if (result.isSuccess() && result.get().hasToken()) {
            Token token = result.get().token();
            System.out.println("Token Válido!");
            System.out.println("Subject: " + token.getSubject());
            System.out.println("Scopes: " + token.getScopes());
            System.out.println("Possui scope 'admin'? " + token.hasScope("admin"));
        } else if (result.isEmpty()) {
            System.out.println("Chave pública (KID) não encontrada na cadeia de confiança.");
        } else if (result.isError()) {
            System.err.println("Erro na validação do token: " + result.exception().getMessage());
        }
    });
```

---

### 3. O Domínio Monádico `Result<T>`

A mônada `Result<T>` permite encadeamentos seguros e expressivos com composição não-bloqueante:

```java
Result<String> resultado = Result.success("meu.token.jwt")
    .flatMap(token -> tokenHandle.getKid(token)) // Extrai o KID
    .recover(ex -> "kid-padrao");                // Fallback caso falhe

// Operações Assíncronas Funcionais:
CompletableFuture<Result<JsonWebKeys>> keysFuture = Result.success("kid-123")
    .mapFuture(kid -> keys.get(kid));
```

---

### 4. Plugando seu Próprio Mecanismo de Log (`Log`)

A interface [Log](file:///home/jefferson/IdeaProjects/auth-lib/src/main/java/knin/auth/jwt/domain/logging/Log.java) é uma `@FunctionalInterface`. Você pode passar qualquer logger:

```java
// SLF4J
org.slf4j.Logger slf4jLogger = LoggerFactory.getLogger("Auth");
authFactory.createIntrospect(tokenHandle, chain, slf4jLogger::info);

// JBoss Logging / Quarkus
org.jboss.logging.Logger jbossLogger = Logger.getLogger("Auth");
authFactory.createIntrospect(tokenHandle, chain, jbossLogger::info);

// Sem logs (No-Op)
authFactory.createIntrospect(tokenHandle, chain, Log.noop());
```

---

## 🧪 Executando os Testes Unitários

A biblioteca possui suíte abrangente cobrindo pipelines monádicos, concorrência, rotação e expiração:

```bash
mvn clean test
```

---

## 📄 Licença

Distribuído sob licença MIT / Proprietária Knin.
