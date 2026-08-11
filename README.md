# homeOS

**Painel self-hosted para organizar e controlar a sua casa** — um mapa customizável dos cômodos, integração completa com o Home Assistant, geladeira, lista de compras, rotinas, afazeres e notas. Feito pra rodar 24/7 num servidor caseiro (um notebook velho serve) e virar o "tablet da casa" numa tela de toque na parede.

> Interface 100% em português, tema claro/escuro, instalável como PWA e otimizada pra modo quiosque.

---

## Índice

- [Visão geral](#visão-geral)
- [Funcionalidades](#funcionalidades)
- [Stack e arquitetura](#stack-e-arquitetura)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Rodando localmente](#rodando-localmente)
- [Deploy em produção (Docker)](#deploy-em-produção-docker)
- [Integração com o Home Assistant](#integração-com-o-home-assistant)
- [Configuração (variáveis de ambiente)](#configuração-variáveis-de-ambiente)
- [Servidor caseiro e modo quiosque](#servidor-caseiro-e-modo-quiosque)
- [Backup](#backup)
- [Acesso remoto (Tailscale)](#acesso-remoto-tailscale)
- [Segurança](#segurança)
- [PWA](#pwa)
- [Roadmap](#roadmap)
- [Licença](#licença)

---

## Visão geral

O **homeOS** é um dashboard doméstico onde a tela inicial é um **mapa em SVG da sua casa**: você desenha os cômodos, arrasta, redimensiona e vincula dispositivos do Home Assistant a cada ambiente. A partir daí controla luzes, ar-condicionado, TV, tomadas, fechaduras, câmeras e acompanha sensores — tudo num painel pensado pra ficar sempre ligado numa tela de toque.

Além do controle da casa, ele agrega o "miolo" da organização doméstica: **geladeira** (inventário com validade), **lista de compras**, **rotinas**, **afazeres recorrentes** e **notas**. Cada usuário tem sua conta e seu estado é sincronizado pelo servidor, então dá pra configurar do PC/celular e o painel na parede reflete tudo.

---

## Funcionalidades

### Mapa da casa
- Editor de planta em **SVG**: adicionar, renomear, mover e **redimensionar cômodos por qualquer canto**.
- **Pan** (arrastar) e **zoom** (pinça no toque / scroll no desktop), com botão de centralizar/resetar.
- Trava de grade pra evitar edição acidental.
- **Desfazer exclusão** de cômodo (com toast "Desfazer" por alguns segundos).
- **Pins de dispositivo** no mapa que refletem o estado atual:
  - **Toque longo** liga/desliga (luz, tomada, ventilador) direto no mapa, sem abrir o cômodo.
  - **Arraste entre cômodos** move o dispositivo (sem desvincular/revincular).
  - Sem estado ao vivo, o pin mostra um ícone compacto do dispositivo.

### Integração com o Home Assistant
- Proxy autenticado por usuário — o token do HA fica no servidor, **nunca vai pro navegador**.
- Suporte a: **light** (brilho e cor RGB), **switch**, **climate/ar** (modos, temperatura), **fan**, **cover**, **media_player**, **lock**, **vacuum**, **humidifier**, **binary_sensor**, **sensor** e **camera**.
- **Sincronização** de dispositivos: detecta novos, sugere cômodo por nome e sinaliza "órfãos" (que sumiram do HA).
- **Câmeras**: card com imagem que atualiza sozinha (snapshot via `camera_proxy`).
- **Sensores**: separados dos controles num bloco compacto; os "graficáveis" (temperatura, umidade, energia, etc.) abrem **histórico** de 24h/7 dias ao tocar.
- **Clima**: pill no cabeçalho (condição + temperatura) a partir da entidade `weather.*`.
- **Banner "HA offline"**: aviso claro quando o painel perde contato com o Home Assistant.
- **"Apagar tudo"**: botão mestre pra desligar todas as luzes/tomadas da casa (com confirmação) ou só de um cômodo.

### Energia
- Pill de **consumo agora** (soma dos sensores de potência) e **custo estimado do mês** (energia × tarifa configurável).

### Organização doméstica
- **Geladeira**: inventário por local (prateleiras, porta, gavetas, freezer…) com **validade** e envio de item pra lista de compras.
- **Lista de compras**: itens por categoria, marcar comprado, limpar comprados.
- **Rotinas**: manuais ou **agendadas por horário**, com ações em vários dispositivos.
- **Afazeres recorrentes**: tarefas domésticas com "quem faz" e "a cada N dias", destacando as atrasadas.
- **Notas**: editor com formatação (negrito, itálico, listas) por cômodo.
- **Tarefas por cômodo** com prioridade.

### Painel / quiosque
- **Modo quiosque**: alvos de toque maiores e edição travada (o painel vira só controle, ninguém bagunça a planta).
- **Modo descanso (protetor de tela)**: relógio grande, data, clima, temperatura interna e próxima rotina; volta ao tocar.
- **Escurecer à noite**: camada que reduz o brilho da tela conforme o horário (mais um script de backlight real no host — veja `DEPLOY.md`).
- **Seletor de apps**: alterna entre o homeOS e outro dashboard (iframe) por botão flutuante ou **swipe de 3 dedos**.

### Saúde do servidor
- Pill de **temperatura da CPU** e card de **saúde** (uptime, RAM, disco, carga, temperatura) lidos do host.
- **Alertas** por toast quando CPU ≥ 85 °C, disco ≥ 90 % ou RAM ≥ 92 %.

### Conta e experiência
- **Login/senha** por usuário (hash **scrypt**, sessão em cookie HttpOnly), estado sincronizado pelo servidor.
- **Avatar** gerado das iniciais do nome.
- **Ícones SVG minimalistas** em toda a interface, tema **claro/escuro** e scrollbars estilizadas.
- Modais e toasts customizados (sem `alert()`/`confirm()` nativos).
- **PWA** instalável (Windows/Android/desktop), com service worker e shell offline.

---

## Stack e arquitetura

```
[Dispositivos da casa] ⟷ [Home Assistant] ⟷ [homeOS (Node/Express + SQLite)] ⟷ Navegador / PWA / Quiosque
```

- **Frontend**: um único `index.html` em **JavaScript puro** (sem frameworks), SVG pro mapa, CSS com variáveis pra tema. Sem dependências externas em runtime (CSP-friendly).
- **Backend**: **Node.js + Express**, banco **SQLite** via `better-sqlite3`. Autenticação com **scrypt** e cookies de sessão. Estado de cada usuário guardado como JSON.
- **Integração HA**: endpoints `/api/ha/*` fazem proxy autenticado pro Home Assistant (states, history, services, camera).
- **PWA**: `manifest.webmanifest` + `sw.js` (cache do shell, network-first pra navegação).
- **Deploy**: Docker + `docker-compose.prod.yml` (Home Assistant + homeOS na mesma rede do host).

---

## Estrutura do projeto

```
.
├── index.html              # Frontend inteiro (UI, mapa, HA, PWA)
├── server.js               # Backend Express + SQLite (auth, estado, proxy HA)
├── sw.js                   # Service worker (PWA)
├── manifest.webmanifest    # Manifesto PWA
├── generate-icons.js       # Gera os ícones PNG do PWA (Node puro)
├── icon-*.png              # Ícones do app (192/512, normal e maskable)
├── package.json            # Dependências e scripts
├── Dockerfile              # Imagem de produção (node:20-bookworm-slim)
├── docker-compose.prod.yml # HA + homeOS em produção
├── docker-compose.yml      # Compose de desenvolvimento
└── DEPLOY.md               # Guia completo do servidor caseiro/quiosque
```

Arquivos de dados/segredo ficam **fora do Git** e são bloqueados de download pelo servidor: `.env`, `data.db*`, `ha-config/`.

---

## Rodando localmente

Pré-requisitos: **Node.js 20+**.

```bash
git clone https://github.com/guilhvic/homeOS.git
cd homeOS
npm install

# opcional: crie um .env (veja a seção de configuração)
echo "PORT=3030" > .env

npm start        # ou: npm run dev  (reinicia ao salvar)
```

Acesse **http://localhost:3030**, crie uma conta e comece a montar o mapa. Sem Home Assistant configurado, o app funciona normalmente — só não mostra dispositivos.

---

## Deploy em produção (Docker)

O `docker-compose.prod.yml` sobe **Home Assistant + homeOS** juntos, ambos em `network_mode: host` (o HA precisa da rede do host pra descobrir dispositivos; o homeOS fala com o HA em `http://localhost:8123`).

```bash
git clone https://github.com/guilhvic/homeOS.git
cd homeOS
mkdir -p data ha-config
docker compose -f docker-compose.prod.yml up -d --build
```

- homeOS: `http://IP_DO_SERVIDOR:3030`
- Home Assistant: `http://IP_DO_SERVIDOR:8123`

Atualizar depois de novas mudanças:

```bash
cd homeOS && git pull && docker compose -f docker-compose.prod.yml up -d --build
```

O guia passo a passo (Ubuntu/Xubuntu, não suspender ao fechar a tampa, religar após queda de luz, etc.) está no **[DEPLOY.md](DEPLOY.md)**.

---

## Integração com o Home Assistant

1. No **Home Assistant**, adicione seus dispositivos (Settings → Devices & Services).
2. Gere um **Long-Lived Access Token** (avatar → Security → Create Token).
3. No **homeOS**, aba **Perfil → Home Assistant**:
   - URL: `http://localhost:8123` (ou o IP/URL do seu HA)
   - Token: cole o token
4. Salve e use o botão **sincronizar** no mapa. Vincule cada dispositivo a um cômodo.

O token é guardado **por usuário** no servidor e usado só no proxy — o navegador nunca o vê.

---

## Configuração (variáveis de ambiente)

Definidas via `.env` (dev) ou no `docker-compose.prod.yml` (produção):

| Variável        | Padrão            | Descrição                                                                 |
|-----------------|-------------------|---------------------------------------------------------------------------|
| `PORT`          | `3000`            | Porta do servidor (produção usa `3030`).                                  |
| `DB_PATH`       | `./data.db`       | Caminho do banco SQLite (produção: `/data/data.db`, volume Docker).       |
| `COOKIE_SECURE` | —                 | `1` faz o cookie de sessão só trafegar por **HTTPS** (ligue após ter TLS).|
| `HA_URL`        | —                 | (Opcional) URL do HA pra semear o primeiro usuário.                       |
| `HA_TOKEN`      | —                 | (Opcional) Token do HA pra semear o primeiro usuário.                     |
| `NODE_ENV`      | —                 | `production` em produção.                                                  |
| `TZ`            | —                 | Fuso horário (ex: `America/Sao_Paulo`).                                    |

---

## Servidor caseiro e modo quiosque

O homeOS foi feito pra virar um painel de parede. O **[DEPLOY.md](DEPLOY.md)** cobre a instalação num notebook antigo com Ubuntu/Xubuntu. Em resumo, o quiosque usa:

- **Chromium em modo `--kiosk`** apontando pra `http://localhost:3030`, iniciado no autologin (LightDM) + autostart do XFCE.
- **Auto-rotação de tela** (pra 2-em-1): script que lê o acelerômetro (`/sys/bus/iio/devices`) e gira tela + toque via `xrandr`/`xinput`.
- **Brilho por horário**: script que ajusta o backlight real (`/sys/class/backlight`) conforme a hora, subindo no autostart.
- Dentro do app, **Modo quiosque** (Perfil) deixa os alvos de toque grandes e trava a edição.

---

## Backup

Os dados que importam são o banco do homeOS (`data/data.db`) e a config do HA (`ha-config/`). Um backup diário simples com rotação (mantém 14 dias):

```bash
cat > ~/backup-homeos.sh <<'EOF'
#!/bin/bash
set -e
SRC=/home/USUARIO/homeOS
DEST=/home/USUARIO/homeOS-backups
mkdir -p "$DEST"
STAMP=$(date +%F_%H%M)
docker exec homeos node -e "const db=require('better-sqlite3')('/data/data.db'); db.pragma('wal_checkpoint(TRUNCATE)'); db.close();" 2>/dev/null || true
tar czf "$DEST/homeos-$STAMP.tar.gz" -C "$SRC" data
ls -1t "$DEST"/homeos-*.tar.gz | tail -n +15 | xargs -r rm -f
EOF
chmod +x ~/backup-homeos.sh

# cron diário às 3h
( crontab -l 2>/dev/null | grep -v backup-homeos.sh; echo "0 3 * * * /home/USUARIO/backup-homeos.sh" ) | crontab -
```

Restaurar: pare o container, extraia o `.tar.gz` sobre a pasta e suba de novo.

---

## Acesso remoto (Tailscale)

Pra acessar de fora de casa com **HTTPS** e sem expor nada na internet pública:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
# ative MagicDNS + HTTPS Certificates no painel do Tailscale
sudo tailscale serve --bg http://localhost:3030
```

Você recebe uma URL fixa `https://nome.SEU-TAILNET.ts.net` que funciona de qualquer aparelho logado na mesma conta Tailscale — e independe do IP local mudar. Detalhes no `DEPLOY.md`.

---

## Segurança

- Senhas com **scrypt**; sessão em **cookie HttpOnly** (`SameSite=Lax`), com opção `Secure` via `COOKIE_SECURE=1`.
- Token do Home Assistant **por usuário**, usado só no proxy do servidor — nunca exposto ao cliente.
- Middleware bloqueia download de arquivos sensíveis (`.env`, `data.db`, `server.js`, `ha-config/`).
- Nada é exposto à internet pública no deploy recomendado (acesso remoto só via Tailscale).

> Este é um projeto pessoal/MVP. Use senhas fortes e mantenha o acesso restrito à sua rede/Tailscale.

---

## PWA

O homeOS é instalável como app (Windows, Android, desktops) com ícone próprio e funcionamento offline do shell. Basta abrir no navegador e usar "Instalar app". Em produção com HTTPS (Tailscale), a instalação no celular funciona direto.

---

## Roadmap

Ideias em aberto:

- Cenas rápidas (botões "Sair", "Cinema", "Dormir").
- Presença por `device_tracker` (moradores + visitantes).
- Histórico de energia e quebra de consumo por cômodo (com *utility meters* no HA).
- Notificações push no celular (via HA companion ou ntfy).
- Barra de favoritos e câmeras em tela cheia.

---

## Licença

Projeto pessoal, sem licença definida no momento. Sinta-se à vontade pra estudar e adaptar.

---

Feito com carinho pra transformar um notebook velho no cérebro da casa.
