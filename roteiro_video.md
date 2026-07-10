# Roteiro — Vídeo: Protocolo Kerberos em Java

---

## ABERTURA (0:00 – 0:45)

**[Tela: título animado "Protocolo Kerberos — Autenticação Distribuída"]**

> "Olá! Neste vídeo vou explicar como funciona o protocolo Kerberos, um dos mecanismos de autenticação mais importantes em redes distribuídas — e ainda vou mostrar uma implementação real em Java usando Sockets.
>
> O Kerberos resolve um problema clássico: como provar para vários servidores que você é quem diz ser, **sem enviar sua senha pela rede em nenhum momento**?
>
> A resposta envolve **chaves simétricas, tickets e carimbos de tempo** — e é exatamente isso que vamos ver agora."

---

## BLOCO 1 — Arquitetura: os quatro atores (0:45 – 2:00)

**[Tela: diagrama com 4 caixas — Cliente, AS, TGS, Servidor]**

> "O Kerberos tem quatro participantes. Primeiro, o **Cliente** — no nosso código, o usuário `Pedro`. Ele quer acessar um serviço, mas precisa provar quem é.
>
> Segundo, o **AS — Authentication Server** — ele conhece a senha de todos os usuários e do próprio TGS. É a raiz de confiança do sistema.
>
> Terceiro, o **TGS — Ticket Granting Server** — ele emite permissões específicas para cada serviço, sem precisar consultar o AS de novo.
>
> Quarto, o **Servidor de Serviço** — no código chamamos de `Servidor`. Ele só aceita clientes que apresentem um ticket válido.
>
> Repara que cada um escuta em uma porta diferente: AS na 4999, TGS na 4998 e o Servidor na 4997."

---

## BLOCO 2 — As chaves de longo prazo (2:00 – 2:50)

**[Tela: trecho de `FuncaoDerivacaoChave.java` e `ASRepository.java`]**

> "Antes de qualquer troca de mensagens, cada participante tem uma **chave de longo prazo** — derivada da sua senha usando uma função de derivação de chave, a KDF.
>
> No código, isso é feito assim: `derivarChave(senha, 'unb.br')`. O salt `unb.br` garante que a mesma senha em domínios diferentes gere chaves diferentes.
>
> O AS conhece a chave do Cliente — `K_c` — e a chave do TGS — `K_tgs`. Nenhuma dessas chaves trafega pela rede. Elas só existem em memória, no repositório do AS."

---

## BLOCO 3 — Fase A: Cliente fala com o AS (2:50 – 5:30)

**[Tela: diagrama destacando a seta Cliente → AS → Cliente]**

### Mensagem 1 — O pedido inicial

> "A primeira mensagem é simples e vai **em claro** pela rede. O cliente envia três campos: seu próprio identificador `ID_C`, o identificador do TGS `ID_TGS`, e um **timestamp** `TS1`.
>
> O timestamp é crucial — ele serve para detectar ataques de repetição. Uma mensagem velha demais é automaticamente rejeitada."

**[Tela: método `escreveMensagem1` do Cliente.java]**

```java
saida.writeUTF(cliente.getID_C());   // "Pedro"
saida.writeUTF(cliente.getID_tgs()); // "TGS@TRABALHOSEC"
saida.writeLong(System.currentTimeMillis());
```

### Mensagem 2 — A resposta do AS

> "O AS recebe isso, sorteia uma **chave de sessão** aleatória chamada `K_c,tgs` — ela vai ser usada entre o cliente e o TGS. Depois, ele monta dois blocos.
>
> O primeiro é o **Ticket_TGS**: contém `K_c,tgs`, o ID do cliente, o endereço IP e o timestamp. Esse bloco é **cifrado com `K_tgs`** — só o TGS consegue ler.
>
> O segundo é a **mensagem ao cliente**: contém `K_c,tgs`, o ID do TGS, o timestamp e o Ticket_TGS opaco. Esse bloco é **cifrado com `K_c`** — só o cliente consegue decifrar."

**[Tela: método `montarMensagem2` do AS.java, destacando as duas chamadas a `Cifra.cifrar`]**

> "Perceba a elegância: o AS nunca envia `K_c,tgs` em claro. O cliente só acessa essa chave porque conhece sua própria senha. E o Ticket_TGS é um 'envelope lacrado' que o cliente carrega mas não consegue abrir."

---

## BLOCO 4 — Fase B: Cliente fala com o TGS (5:30 – 8:00)

**[Tela: diagrama destacando Cliente → TGS → Cliente]**

### Mensagem 3 — Pedindo acesso ao serviço

> "Agora o cliente quer acessar o Servidor. Ele manda três coisas ao TGS: o ID do serviço desejado `ID_V`, o Ticket_TGS opaco que recebeu do AS, e um **Autenticador**.
>
> O Autenticador é novidade. Ele é criado na hora pelo cliente e contém `ID_C`, o endereço IP e um novo timestamp `TS3` — **cifrado com `K_c,tgs`**. É a prova de que o cliente que está enviando o ticket é o mesmo que o AS autorizou."

### Verificação no TGS

> "O TGS recebe isso e faz três verificações:
>
> Primeiro, decifra o Ticket_TGS com sua própria chave `K_tgs` e extrai `K_c,tgs`, `ID_C` e `AD_C`.
>
> Segundo, usa essa `K_c,tgs` para decifrar o Autenticador e extrai `ID_C` e `AD_C` de lá também.
>
> Terceiro, **compara os dados dos dois**: se `ID_C` e `AD_C` batem, o cliente é legítimo — só quem tem `K_c,tgs` consegue montar um autenticador válido."

**[Tela: métodos `comparaAutenticadorETicket` e `verificarValidadeTicket_tgs` do Tgs.java]**

> "Repara também na validação de tempo: o ticket só é aceito se foi emitido há menos de **5 minutos**. Isso bloqueia ataques de replay — capturar um ticket antigo e tentar reutilizá-lo não funciona."

### Mensagem 4 — O TGS responde

> "O TGS sorteia uma nova chave de sessão, `K_c,v`, para usar entre cliente e servidor. Monta o **Ticket_V** cifrado com a chave do servidor `K_v`, e devolve ao cliente a mensagem 4 — tudo cifrado com `K_c,tgs`."

---

## BLOCO 5 — Fase C: Cliente fala com o Servidor (8:00 – 10:30)

**[Tela: diagrama destacando Cliente → Servidor → Cliente]**

### Mensagem 5 — Apresentando-se ao serviço

> "O cliente repete o padrão: envia o ID do serviço, o Ticket_V opaco e um novo Autenticador — desta vez cifrado com `K_c,v`."

### Verificação no Servidor

> "O servidor decifra o Ticket_V com sua chave `K_v`, extrai `K_c,v`, depois usa essa chave para decifrar o Autenticador. Se ID e IP batem, o cliente é autêntico."

### Mensagem 6 — Autenticação mútua

> "E aqui acontece algo especial: o servidor devolve `TS5 + 1` — o timestamp do autenticador incrementado em 1, cifrado com `K_c,v`.
>
> Isso é **autenticação mútua**: o cliente só aceita essa resposta se o servidor realmente decifrou o autenticador corretamente. O servidor prova que conhece `K_c,v`, e portanto que é legítimo."

**[Tela: método `leMensagem6` do Cliente.java]**

---

## BLOCO 6 — Chat cifrado (10:30 – 11:30)

**[Tela: código do método `chat` nos dois lados]**

> "Depois de toda essa dança de autenticação, cliente e servidor compartilham `K_c,v` — uma chave de sessão efêmera, gerada só para essa conexão.
>
> Qualquer mensagem trocada a partir daqui é cifrada com ela. Duas threads rodam em paralelo: uma para enviar, outra para receber. Quando o cliente digita `SAIR`, a sessão encerra."

---

## BLOCO 7 — Por que Kerberos? (11:30 – 12:30)

**[Tela: tabela comparativa]**

> "Vamos recapitular os problemas que o Kerberos resolve:
>
> **Senha nunca trafega na rede** — o cliente prova identidade por criptografia, não por senha.
>
> **Single Sign-On** — o cliente autentica uma vez no AS e pode acessar vários serviços com o mesmo Ticket_TGS, sem redigitar a senha.
>
> **Proteção contra replay** — os timestamps e o tempo de vida dos tickets invalidam mensagens antigas capturadas.
>
> **Autenticação mútua** — cliente e servidor se autenticam mutuamente na mensagem 6."

---

## ENCERRAMENTO (12:30 – 13:00)

> "O que implementamos aqui é uma versão simplificada do Kerberos versão 5, com criptografia simétrica AES, derivação de chave com KDF e comunicação por Sockets TCP em Java.
>
> Se quiser se aprofundar, o RFC 4120 descreve o protocolo completo. O código deste projeto está no repositório linkado na descrição.
>
> Qualquer dúvida, comenta abaixo. Até o próximo vídeo!"

---

## Estrutura de telas sugerida

| Segmento    | Recurso visual                                                              |
|-------------|-----------------------------------------------------------------------------|
| Abertura    | Título animado + logo Kerberos                                              |
| Bloco 1     | Diagrama dos 4 participantes com portas                                     |
| Bloco 2     | Diagrama de chaves + trecho de código                                       |
| Blocos 3–5  | Diagrama de sequência (as 6 mensagens) com zoom no código de cada uma       |
| Bloco 6     | Terminal rodando lado a lado (cliente e servidor)                           |
| Bloco 7     | Slide de tabela resumo                                                      |
| Encerramento| Tela do repositório                                                         |