# 🔐 auth-lib

[![CI - Build & Test](https://github.com/lisboajeff/auth-lib/actions/workflows/ci.yml/badge.svg)](https://github.com/lisboajeff/auth-lib/actions/workflows/ci.yml)
![Java](https://img.shields.io/badge/Java-21-orange.svg?logo=openjdk)
![Tests](https://img.shields.io/badge/Tests-Passing%20(68%20unit%20%2B%209%20integration)-brightgreen)
![Coverage](https://img.shields.io/badge/Coverage-JaCoCo-blue)
![License](https://img.shields.io/badge/License-MIT-green.svg)

Uma biblioteca Java moderna, reativa, não-bloqueante e de alto desempenho para validação, introspecção e recuperação encadeada de chaves criptográficas (JWKS / JWT), construída sobre o padrão **Monádico (`Result<T>`)** e **Chain of Responsibility**.

---

## 🚀 Destaques da Arquitetura

- ⚡ **100% Assíncrona & Não-Bloqueante**: Operações baseadas em `CompletableFuture` com suporte nativo a pipelines reativos.
- 🛡️ **Padrão Monádico (`Result<T>`)**: Elimina o uso de runtime exceptions para controle de fluxo. Retornos previsíveis e tipados (`SuccessResult`, `FailedResult`, `EmptyResult`).
- 🔗 **Cadeia de Resolução Multinível (`TableChain<E>`)**:
  - Resolução hierárquica de chaves criptográficas (ex: L1 Cache local ➔ L2 RAM Polling ➔ L3 Storage / S3 / REST).
  - Deduplicação de requisições concorrentes em voo (*in-flight request coalescing* via `ConcurrentHashMap`).
  - Retroalimentação automática de cache (*back-propagation / set*).
- 📜 **Abstração de Log Desacoplada (`Log`)**: Zero dependências de frameworks externos de log (Logback, SLF4J, Log4j). Totalmente plugável via Lambdas ou Method References (`logger::info`).
- 🧩 **Suporte a Múltiplos Formatos de Token**: Suporta tanto JWTs padrão RFC 7519 (3 partes) quanto tokens customizados (4 partes).

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
│   │   ├── Source.java            # Interface de provedor de dados de chaves (fetchData)
│   │   └── SourceChain.java       # Elo da cadeia que conecta um Source ao próximo nível
│   └── validate
│       ├── TokenHandleProxy.java  # Extração de KID, decode e validação criptográfica
│       ├── TokenSplit.java        # Splitter e parser de estrutura do JWT
│       └── TokenUtil.java         # Parser e validador de claims e assinaturas
├── domain
│   ├── logging
│   │   └── Log.java               # Interface funcional e pura de logging (zero dependências)
│   ├── result
│   │   ├── Result.java            # Mônada principal (success, failed, empty, flatMap, mapFuture, Ok, Error)
│   │   ├── SuccessResult.java     # Resultado com valor computado
│   │   ├── FailedResult.java      # Resultado com falha/ResultException
│   │   ├── EmptyResult.java       # Resultado vazio (sem valor / não encontrado)
│   │   └── ResultException.java   # Exceção base de falha no domínio monádico
│   ├── retriever
│   │   ├── Chain.java             # Contrato funcional de recuperação assíncrona
│   │   ├── JsonWebKeys.java       # Abstração de chaves públicas carregadas
│   │   ├── Keys.java              # Interface de consulta por KID
│   │   └── TableChain.java        # Estrutura base da Chain of Responsibility
│   └── validate
│       ├── JWT.java               # Wrapper de Token validado
│       ├── Token.java             # Contrato de claims, scopes e expiração
│       ├── TokenData.java         # Claims e headers decodificados
│       └── TokenHandle.java       # Parser de headers e validação de assinatura
├── factory
│   └── AuthFactory.java           # Fábrica unificada para construção da cadeia e Introspect
└── option
    ├── Introspect.java            # Ponto de entrada de validação e introspecção
    ├── IntrospectImpl.java        # Implementação interna de Introspection
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

// Nível 3: Provedor de Fallback (ex: I/O sob demanda no S3 ou REST)
TableChain<String> l3Fallback = authFactory.createSource(tokenHandle, s3Source);

// Nível 2: Provedor de Cache em RAM (ex: sincronizado via Polling) apontando para o Nível 3
TableChain<String> l2MemoryPolling = authFactory.createSource(tokenHandle, memoryPollingSource, l3Fallback);

// Nível 1 + Introspect: Cria o L1 InMemory automaticamente e entrega o Introspect
Introspect introspect = authFactory.createIntrospect(tokenHandle, l2MemoryPolling, System.out::println);
```

---

### 2. Validação e Introspecção de Tokens

O método `introspect(jwt)` retorna um `CompletableFuture<Result<Introspection>>`:

```java
introspect.introspect(rawJwtToken)
    .thenAccept(result -> {
        if (result.hasResult() && result.get().hasToken()) {
            Token token = result.get().token();
            System.out.println("Token Válido!");
            System.out.println("Subject: " + token.getSubject());
            System.out.println("Scopes: " + token.getScopes());
            System.out.println("Possui scope 'admin'? " + token.hasScope("admin"));
        } else if (result.isEmpty()) {
            System.out.println("Chave pública (KID) não encontrada na cadeia de confiança.");
        } else if (result.isError()) {
            result.Error(ex -> System.err.println("Erro na validação do token: " + ex.getMessage()));
        }
    });
```

---

### 3. A Mônada `Result<Data>`

A interface [Result](file:///home/jefferson/IdeaProjects/auth-lib/src/main/java/knin/auth/jwt/domain/result/Result.java) fornece operadores monádicos para composição funcional síncrona e assíncrona:

#### Métodos de Criação:
- `Result.of(data)`: Retorna `Result.success(data)` se `data != null`, ou `Result.empty()` se `data == null`.
- `Result.success(data)`: Cria uma instância de `SuccessResult`.
- `Result.failed(exception)`: Cria uma instância de `FailedResult` encapsulando uma `ResultException`.
- `Result.empty()`: Retorna a instância singleton de `EmptyResult`.

#### Métodos de Inspeção e Extração:
- `boolean hasResult()`: Retorna `true` se contiver um dado válido e não vazio.
- `boolean isError()`: Retorna `true` se for uma falha.
- `boolean isEmpty()`: Retorna `true` se estiver vazio.
- `Data get()`: Retorna o dado contido (ou `null` se vazio/erro).

#### Operadores Funcionais:
- **`flatMap(Function<Data, Result<Other>>)`**: Transforma o valor encadeando outra operação que retorna `Result`:
  ```java
  Result<TokenData> tokenDataResult = tokenHandle.getKid(rawJwt)
      .flatMap(kid -> tokenHandle.decode(jsonWebKeys, rawJwt));
  ```

- **`flatMapOrElse(Function<Data, Result<Other>>, Supplier<Result<Other>>)`**: Mapeia o valor ou executa um fornecedor alternativo se estiver vazio:
  ```java
  Result<Introspection> introspection = tokenResult
      .flatMapOrElse(
          token -> Result.success(new IntrospectImpl(token)),
          () -> Result.success(new IntrospectImpl())
      );
  ```

- **`mapFuture(Function<Data, CompletableFuture<Result<Other>>>)`**: Compõe operações assíncronas de forma limpa:
  ```java
  CompletableFuture<Result<Introspection>> future = tokenHandle.getKid(rawJwt)
      .mapFuture(kid -> keys.get(kid))
      .thenApply(keysResult -> keysResult.flatMap(keys -> tokenHandle.decode(keys, rawJwt)...));
  ```

- **`Ok(Consumer<Data>)`** e **`Error(Consumer<ResultException>)`**: Efeitos colaterais fluentes:
  ```java
  result
      .Ok(data -> System.out.println("Processado com sucesso: " + data))
      .Error(ex -> System.err.println("Ocorreu uma falha: " + ex.getMessage()));
  ```

---

### 4. Plugando seu Próprio Mecanismo de Log (`Log`)

A interface [Log](file:///home/jefferson/IdeaProjects/auth-lib/src/main/java/knin/auth/jwt/domain/logging/Log.java) é uma `@FunctionalInterface`. Você pode passar qualquer logger via method reference:

```java
// SLF4J
org.slf4j.Logger slf4j = LoggerFactory.getLogger("Auth");
authFactory.createIntrospect(tokenHandle, chain, slf4j::info);

// JBoss Logging / Quarkus
org.jboss.logging.Logger jboss = Logger.getLogger("Auth");
authFactory.createIntrospect(tokenHandle, chain, jboss::info);

// Console direto
authFactory.createIntrospect(tokenHandle, chain, Log.systemOut());

// Sem logs (Default / No-Op)
authFactory.createIntrospect(tokenHandle, chain, Log.noop());
```

---

## 🧪 Executando os Testes Unitários

A biblioteca possui cobertura completa de testes unitários e de integração:

```bash
mvn clean test
```

---

## 📄 Licença

Distribuído sob licença MIT / Proprietária Knin.
