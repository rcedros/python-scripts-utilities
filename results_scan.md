# Relatório de Vulnerabilidades - Scan Automático

**Data do Relatório:** 21/12/2025
**Status:** Análise Concluída
**Aplicação:** uol.com.br
---

**Vulnerabilidade:** Missing HSTS Header  

**CVE/Risco:** Não há CVE específica para a ausência de HSTS, porém o risco é classificado como **ALTO**. A falta desse header está associada a vulnerabilidades de **Man‑in‑the‑Middle (MitM)** e, indiretamente, a falhas listadas no **OWASP Top 10 2021** (A01 – Broken Access Control, A03 – Injection, A07 – Cross‑Site Scripting) por permitir downgrade de conexão e captura de cookies/credenciais.  

**Exploração:**  
Um atacante que consiga posicionar‑se entre o usuário e o servidor (por exemplo, via Wi‑Fi público, ARP spoofing ou comprometimento de roteador) pode forçar a navegação para a versão **HTTP** do site, já que o navegador não tem instrução de “sempre usar HTTPS”. Assim, o atacante intercepta e modifica o tráfego (cookies de sessão, credenciais, dados pessoais), realizando um ataque **Man‑in‑the‑Middle** ou de **downgrade protocol**.  

**Mitigação:**  
Adicionar o header **Strict‑Transport‑Security (HSTS)** com um `max‑age` de, no mínimo, **31536000 segundos** (1 ano) e incluir as diretivas `includeSubDomains` e `preload`.  

Exemplos de configuração:

- **Apache (httpd.conf ou .htaccess)**
  ```apache
  Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"
  ```

- **Nginx (nginx.conf ou bloco server)**
  ```nginx
  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\";
  ```

- **IIS (web.config)**
  ```xml
  <system.webServer>
      <httpProtocol>
          <customHeaders>
              <add name=\"Strict-Transport-Security\" value=\"max-age=31536000; includeSubDomains; preload\" />
          </customHeaders>
      </httpProtocol>
  </system.webServer>
  ```

**Passos adicionais recomendados**

1. **Teste** a presença do header após a mudança usando ferramentas como `curl -I https://uol.com.br` ou scanners de segurança (e.g., OWASP ZAP, Qualys SSL Labs).  
2. **Habilite o preload list** submetendo o domínio ao [HSTS preload list](https://hstspreload.org/) para garantir que navegadores modernos sempre iniciem a conexão via HTTPS.  
3. **Combine** o HSTS com outros security headers (Content‑Security‑Policy, X‑Frame‑Options, X‑Content‑Type‑Options, Referrer‑Policy) para uma postura de defesa em profundidade.  

Implementando o header conforme acima, o risco de ataques MitM será drasticamente reduzido, alinhando o site às boas práticas de segurança de transporte.,**Vulnerabilidade:** Missing **X‑Content‑Type‑Options** header (nosniff)  

**CVE/Risco:** Não há CVE específica para a ausência desse header, porém a falha se enquadra na **OWASP Top 10 2021 – A07:2021 – “Security Misconfiguration”** (e pode facilitar ataques de XSS ao permitir *MIME‑sniffing*).  

**Exploração:**  
- O navegador, ao receber um recurso (ex.: HTML, JavaScript, CSS, JSON) sem o header `X‑Content‑Type‑Options: nosniff`, pode “sniffar” o tipo MIME real do conteúdo.  
- Um atacante pode então servir um arquivo com extensão segura (por exemplo, `image.png`) mas cujo corpo contém código JavaScript ou HTML mal‑icioso.  
- Se o navegador interpretar o conteúdo como script em vez de imagem, o código será executado no contexto da vítima, possibilitando **Cross‑Site Scripting (XSS)**, **drive‑by downloads** ou **ataques de injeção de conteúdo**.  

**Mitigação (configuração recomendada):**  

*Adicionar o header em todas as respostas HTTP do site.*  

- **Apache** (arquivo `.htaccess` ou configuração do VirtualHost):  
  ```apache
  Header always set X-Content-Type-Options \"nosniff\"
  ```

- **Nginx** (bloco `server` ou `location`):  
  ```nginx
  add_header X-Content-Type-Options \"nosniff\" always;
  ```

- **IIS** (web.config):  
  ```xml
  <system.webServer>
      <httpProtocol>
          <customHeaders>
              <add name=\"X-Content-Type-Options\" value=\"nosniff\" />
          </customHeaders>
      </httpProtocol>
  </system.webServer>
  ```

- **Node.js/Express** (middleware):  
  ```javascript
  app.use((req, res, next) => {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      next();
  });
  ```

**Impacto da correção:**  
Com o header `nosniff` habilitado, o navegador obedecerá estritamente o `Content-Type` declarado pelo servidor, impedindo que arquivos sejam reinterpretados como scripts ou outros tipos de conteúdo. Isso reduz significativamente a superfície de ataque para XSS e outras injeções baseadas em MIME‑sniffing.  

**Recomendação adicional (boas práticas de security headers):**  
Embora o foco seja o `X‑Content‑Type‑Options`, vale revisar e garantir a presença e correta configuração dos seguintes headers, pois a ausência ou má‑configuração deles também pode gerar vulnerabilidades de nível médio a alto:

| Header | Valor recomendado |
|--------|-------------------|
| **Strict-Transport-Security (HSTS)** | `max-age=31536000; includeSubDomains; preload` |
| **Content‑Security‑Policy (CSP)** | Política restritiva que permita apenas recursos confiáveis (ex.: `default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';` ) |
| **X‑Frame‑Options** | `DENY` ou `SAMEORIGIN` |
| **Referrer‑Policy** | `no-referrer-when-downgrade` ou `strict-origin-when-cross-origin` |

Implementar todos esses headers em conjunto eleva a postura de segurança do site e diminui a probabilidade de exploração por atacantes.,**Vulnerabilidade:** Missing **X‑Frame‑Options** Header  

**CVE/Risco:** Não há CVE específica para a ausência desse header, porém a falha é classificada como **alto risco** e está associada às categorias **A07:2021 – Cross‑Site Scripting (XSS)** e **A03:2021 – Broken Access Control** do OWASP Top 10.  

**Exploração:**  
Um atacante pode criar uma página mal‑intencionada que incorpora o site **uol.com.br** dentro de um `<iframe`. Como o site não envia o header **X‑Frame‑Options**, o navegador permite o framing. O atacante então pode sobrepor botões ou formulários legítimos, induzindo o usuário a clicar em elementos invisíveis ou a submeter dados sensíveis (ataque de *clickjacking*).  

**Mitigação:**  
Adicionar o header **X‑Frame‑Options** à resposta HTTP do servidor, escolhendo a política mais adequada ao negócio:

```http
# Bloqueia qualquer framing
X-Frame-Options: DENY
```

ou

```http
# Permite framing apenas a partir da mesma origem (uol.com.br)
X-Frame-Options: SAMEORIGIN
```

*Recomendação adicional:*  
- Verificar se há necessidade real de permitir framing; caso não haja, prefira **DENY**.  
- Testar a aplicação após a mudança para garantir que funcionalidades legítimas não sejam impactadas.  

---  

**Resumo da análise**  
- **Tipo:** Missing Header  
- **Severidade:** HIGH  
- **Detalhe:** Falta o header X‑Frame‑Options  
- **Remediação sugerida:** Adicionar `DENY` ou `SAMEORIGIN` conforme a política de uso.  ,**Vulnerabilidade:** Missing Content‑Security‑Policy (CSP) header  

**CVE/Risco:** N/A – Classificação de risco **MEDIUM** (OWASP A5 – Security Misconfiguration / A7 – Cross‑Site Scripting)  

**Exploração:**  
Sem um CSP, o navegador aceita qualquer recurso (scripts, estilos, frames, etc.) que o site carregue. Um atacante que consiga injetar conteúdo (por exemplo, via Reflected XSS, parâmetros de URL manipulados ou campos de formulário) pode inserir `<script>` mal‑icioso ou carregar scripts externos. O código mal‑icioso será executado no contexto da página da UOL, permitindo roubo de cookies, hijacking de sessão, phishing ou download de malware.  

**Mitigação (exemplo de cabeçalho CSP recomendado):**  

```http
Content-Security-Policy: 
  default-src 'self'; 
  script-src 'self' https://cdn.uol.com.br https://cdnjs.cloudflare.com; 
  style-src  'self' 'unsafe-inline' https://fonts.googleapis.com; 
  img-src    'self' data: https://*.uol.com.br; 
  font-src   'self' https://fonts.gstatic.com; 
  connect-src 'self'; 
  object-src 'none'; 
  frame-ancestors 'self'; 
  base-uri 'self'; 
  form-action 'self';
```

**Pontos de atenção na implementação**

1. **Inicie com uma política restritiva** (`default-src 'self'`) e vá adicionando exceções apenas para recursos realmente necessários.  
2. **Evite `'unsafe-inline'`** sempre que possível; prefira hashes ou nonces para scripts/estilos inline.  
3. **Teste a política** em modo *report‑only* antes de aplicá‑la em produção, para identificar quebras legítimas:  

```http
Content-Security-Policy-Report-Only: <mesma política acima>; report-uri https://csp-report.uol.com.br/report
```  

4. **Atualize periodicamente** a lista de domínios confiáveis (CDNs, APIs, etc.) e remova quaisquer fontes que não estejam mais em uso.  

Implementando o cabeçalho CSP acima (ou uma variação adequada ao ambiente da UOL) o risco de exploração de XSS será drasticamente reduzido, atendendo à recomendação de “Implement strong CSP” e alinhando o site às boas práticas de segurança de cabeçalhos HTTP.,**Vulnerabilidade:** Missing **Referrer‑Policy** Header  

**CVE/Risco:** – (não há CVE específica para ausência de cabeçalhos) – **Nível:** LOW (conforme o relatório) – **OWASP Top 10:** A5 2021 – *Security Misconfiguration* (também relacionado ao A6 2017 – *Security Misconfiguration*).  

---

### Exploração  
A ausência do cabeçalho **Referrer‑Policy** permite que o navegador envie o valor completo do cabeçalho **Referer** sempre que o usuário navega para outro domínio.  

* Se a página contém URLs sensíveis, parâmetros de consulta (ex.: `?token=abc123`) ou caminhos que revelam a estrutura interna da aplicação, esses dados são enviados ao site de destino.  
* Um atacante que controla o site de destino (ou um site mal‑intencionado que o usuário visita) pode registrar o cabeçalho **Referer** e obter informações que poderiam ser usadas para:  
  * Reconhecimento de recursos internos,  
  * Phishing direcionado,  
  * Força‑bruta de tokens ou credenciais que foram expostos na URL.  

Embora o risco seja classificado como **LOW**, a exposição de informações de referência pode ser combinada com outras vulnerabilidades para ampliar o impacto.

---

### Mitigação  

**Adicionar o cabeçalho Referrer‑Policy com o valor recomendado:**  

```http
Referrer-Policy: strict-origin-when-cross-origin
```

**O que esse valor faz:**  

* **Same‑origin requests** – envia o referer completo (origem + caminho + query).  
* **Cross‑origin requests** – envia **apenas a origem** (ex.: `https://www.uol.com.br`).  
* **Requests de downgrade (HTTPS → HTTP)** – não envia nenhum referer.  

Isso impede a divulgação de caminhos e parâmetros sensíveis ao navegar para domínios externos, reduzindo a superfície de informação que um atacante pode coletar.

---

### Como aplicar (exemplos por servidor)

| Servidor / Framework | Configuração |
|----------------------|--------------|
| **Apache** | `Header set Referrer-Policy \"strict-origin-when-cross-origin\"` |
| **Nginx** | `add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;` |
| **IIS** | No *web.config*: `<httpProtocol><customHeaders><add name=\"Referrer-Policy\" value=\"strict-origin-when-cross-origin\" /></customHeaders></httpProtocol>` |
| **Express (Node.js)** | `app.use((req, res, next) => { res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin'); next(); });` |
| **Spring Boot** | `@Bean public FilterRegistrationBean<HeaderWriterFilter> securityHeaders() { HeaderWriterFilter filter = new HeaderWriterFilter(new ReferrerPolicyHeaderWriter(\"strict-origin-when-cross-origin\")); ... }` |

---

### Recomendações adicionais de Security Headers (para elevar a postura de segurança)

Embora o foco seja o **Referrer‑Policy**, vale a pena validar a presença e a configuração correta dos demais cabeçalhos de segurança recomendados pelo OWASP:

| Header | Valor recomendado | Por quê |
|--------|-------------------|---------|
| **Strict-Transport-Security (HSTS)** | `max-age=31536000; includeSubDomains; preload` | Força uso de HTTPS e protege contra downgrade attacks. |
| **Content‑Security‑Policy (CSP)** | Política restritiva que permite apenas fontes confiáveis (ex.: `default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';`) | Mitiga XSS e injeção de conteúdo. |
| **X‑Frame‑Options** | `DENY` ou `SAMEORIGIN` | Prevê clickjacking. |
| **X‑Content‑Type‑Options** | `nosniff` | Impede que o navegador faça “sniffing” de MIME types. |
| **Permissions‑Policy** | Configurar de acordo com funcionalidades usadas (ex.: `geolocation=()`) | Controla APIs de navegador expostas ao site. |

---

### Resumo rápido (formato solicitado)

```
Vulnerabilidade: Missing Referrer-Policy Header
CVE/Risco: - / LOW (OWASP A5 2021 – Security Misconfiguration)
Exploração: Sem a política, o navegador envia o referer completo para sites externos, expondo URLs, parâmetros e possivelmente tokens ou informações internas que podem ser coletadas por um atacante.
Mitigação: 
Referrer-Policy: strict-origin-when-cross-origin
```

Implementando o cabeçalho acima (e revisando os demais security headers) o site **uol.com.br** reduzirá significativamente o risco de vazamento de informações via referer e melhorará sua postura geral de segurança.,**Vulnerabilidade:** Missing Permissions‑Policy Header  

**CVE/Risco:** LOW (classificação de risco – não há CVE associada a um header ausente)  

**Exploração:**  
Sem o cabeçalho **Permissions‑Policy**, o navegador permite que a página utilize recursos avançados (camera, microfone, geolocation, etc.) sem restrições explícitas. Um atacante que consiga injetar ou executar código JavaScript na página poderia, por exemplo, solicitar acesso à câmera ou à localização do usuário e, se o usuário conceder permissão, obter informações sensíveis ou gravar áudio/vídeo sem que o desenvolvedor tenha previsto essa possibilidade.  

**Mitigação (exemplo de configuração):**  

```http
Permissions-Policy: camera=(), geolocation=(), microphone=(), fullscreen=(), vibrate=()
```

* Cada diretiva lista os recursos que devem ser desativados (ou, alternativamente, pode‑se especificar origens permitidas, e.g., `camera=(\"self\")`).  
* Adicione o cabeçalho acima (ou ajuste as diretivas conforme a necessidade da aplicação) nas respostas HTTP do servidor (por exemplo, via configuração do Apache, Nginx, ou no código da aplicação).  

Implementando o cabeçalho, a aplicação controla explicitamente quais APIs do navegador podem ser usadas, reduzindo a superfície de ataque relacionada a recursos sensíveis.,**Análise de SSL/TLS – uol.com.br (porta 443)**  

A partir do JSON fornecido, foram identificados os seguintes pontos críticos de segurança na camada TLS/SSL:

| Item | Estado encontrado | Comentário |
|------|-------------------|------------|
| **Protocolos habilitados** | TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3 | TLS 1.0 e TLS 1.1 são protocolos obsoletos e vulneráveis. |
| **Fallback** | suportado (`@supported=\"1\"`) | Permite downgrade de versão, aumentando a superfície de ataque. |
| **Renegociação** | suportada e segura (`@secure=\"1\"`) | Não há problema imediato, mas a presença de fallback pode ser explorada em conjunto. |
| **Compressão** | desativada (`@supported=\"0\"`) | Boa prática – impede ataques como CRIME. |
| **Heartbleed** | não vulnerável em nenhuma versão | OK. |
| **Certificado** | RSA 2048, SHA‑256, válido até 03 Jan 2026, não auto‑assinado | Certificado está em dia. |
| **Headers de segurança HTTP** | Não há informação no JSON | Não é possível validar; recomenda‑se a implementação. |

---

## Vulnerabilidade 1 – Suporte a TLS 1.0 e TLS 1.1 (Protocolos obsoletos)

- **Vulnerabilidade:** Uso de protocolos TLS 1.0 e TLS 1.1, que já não recebem mais atualizações de segurança e são suscetíveis a ataques de downgrade, BEAST, POODLE e Sweet32.  
- **CVE / Risco:**  
  - **CVE‑2014‑8730** – Vulnerabilidade de downgrade em TLS 1.0.  
  - **CVE‑2016‑2107** – Ataque Sweet32 (cifras de bloco de 64 bits em TLS 1.0/1.1).  
  - **OWASP Top 10 – A02:2021 (Cryptographic Failures).**  
- **Exploração:** Um atacante pode forçar a negociação para TLS 1.0/1.1 (usando o fallback habilitado) e, em seguida, explorar vulnerabilidades conhecidas para descriptografar ou modificar o tráfego.  
- **Mitigação (exemplo Nginx):**  
  ```nginx
  # Desabilita protocolos antigos
  ssl_protocols TLSv1.2 TLSv1.3;

  # Opcional: desabilita fallback se o servidor suportar
  ssl_prefer_server_ciphers on;
  ```

  **Exemplo Apache:**  
  ```apache
  SSLProtocol TLSv1.2 TLSv1.3
  ```

---

## Vulnerabilidade 2 – Fallback habilitado (downgrade)

- **Vulnerabilidade:** O campo `fallback` está marcado como suportado (`@supported=\"1\"`), permitindo que o cliente “caia” para uma versão inferior do protocolo caso a negociação falhe.  
- **CVE / Risco:**  
  - **CVE‑2015‑0204** – TLS_FALLBACK_SCSV não implementado permite downgrade.  
  - **OWASP Top 10 – A02:2021 (Cryptographic Failures).**  
- **Exploração:** Um atacante pode provocar falhas artificiais na negociação TLS para que o servidor aceite uma versão mais fraca (ex.: TLS 1.0) e, então, explorar vulnerabilidades dessa versão.  
- **Mitigação:**  
  - Habilitar o mecanismo **TLS_FALLBACK_SCSV** (geralmente já incluído nas bibliotecas modernas).  
  - Desativar explicitamente o fallback, se a pilha de TLS permitir.  
  - Exemplo (OpenSSL/LibreSSL):  
    ```bash
    # Não há parâmetro direto; basta remover suporte a versões antigas (ver Vulnerabilidade 1)
    ```

---

## Vulnerabilidade 3 – Ausência de Headers de Segurança HTTP (não detectado no JSON)

- **Vulnerabilidade:** Não há dados sobre os cabeçalhos de segurança (HSTS, CSP, X‑Frame‑Options, etc.). A falta desses cabeçalhos pode expor a aplicação a ataques de click‑jacking, XSS, e forçar conexões não‑seguras.  
- **CVE / Risco:** Não há CVE específica, mas está relacionado ao **OWASP Top 10 – A05:2021 (Security Misconfiguration)**.  
- **Exploração:** Um atacante pode injetar scripts maliciosos ou forçar o carregamento de recursos externos se o CSP estiver ausente; pode também embutir a página em frames de terceiros se X‑Frame‑Options não estiver definido.  
- **Mitigação (exemplo Apache):**  
  ```apache
  # HSTS – força HTTPS e previne downgrade
  Header always set Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\"

  # CSP – política de origem restrita
  Header always set Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';\"

  # X‑Frame‑Options – impede click‑jacking
  Header always set X-Frame-Options \"SAMEORIGIN\"

  # X‑Content‑Type‑Options – impede MIME sniffing
  Header always set X-Content-Type-Options \"nosniff\"

  # Referrer‑Policy – controla o Referer enviado
  Header always set Referrer-Policy \"strict-origin-when-cross-origin\"
  ```

---

## Vulnerabilidade 4 – Verificação de Cifras (não listadas)

- **Observação:** O JSON não detalha as suites de cifra negociadas. Mesmo com TLS 1.2/1.3 habilitados, é essencial garantir que apenas cifras modernas (AEAD, ECDHE) sejam permitidas e que cifras de bloco de 64 bits (ex.: 3DES, RC4) estejam excluídas.  
- **Mitigação (exemplo Nginx):**  
  ```nginx
  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:
               ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:
               DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
  ssl_prefer_server_ciphers on;
  ```

---

## Resumo das Recomendações

1. **Desativar TLS 1.0 e TLS 1.1** – mantenha apenas TLS 1.2 e TLS 1.3.  
2. **Remover suporte a fallback** ou garantir que o mecanismo TLS_FALLBACK_SCSV esteja ativo.  
3. **Implementar cabeçalhos de segurança HTTP** (HSTS, CSP, X‑Frame‑Options, X‑Content‑Type‑Options, Referrer‑Policy).  
4. **Revisar e restringir as suites de cifra** para apenas algoritmos AEAD e ECDHE.  
5. **Manter o certificado atualizado** (já está válido até 2026, mas monitorar renovação).  

Seguindo essas ações, o site uol.com.br reduzirá significativamente a superfície de ataque na camada de transporte e alinhará sua postura de segurança com as melhores práticas recomendadas pelo OWASP e pelos padrões da indústria."
