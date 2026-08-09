# Deploy do homeOS num servidor de casa (notebook + Ubuntu)

Guia pra rodar **homeOS + Home Assistant** num notebook antigo (ex: Pentium N3530,
8GB), acessível de qualquer lugar via **Tailscale** com HTTPS. Custo: R$ 0/mês.

Arquitetura:

```
[Dispositivos da casa] ⟷ [Notebook Ubuntu: HA + homeOS (Docker)] ⟷ Tailscale (HTTPS) ⟷ seus aparelhos
```

---

## 1. Instalar o Ubuntu Server

1. Baixe o **Ubuntu Server 24.04 LTS** e grave num pendrive com o
   [Rufus](https://rufus.ie) (Windows) ou Balena Etcher.
2. Dê boot pelo pendrive e siga a instalação (idioma, teclado, rede).
   - Marque **"Install OpenSSH server"** pra acessar remoto depois.
   - Não precisa de interface gráfica.
3. Anote o usuário/senha que você criar.

> ⚠️ **Bay Trail (N3530)**: alguns notebooks dessa geração têm CPU 64-bit mas
> **UEFI 32-bit**, e o instalador 64-bit pode não dar boot. Se travar no boot,
> procure "Ubuntu bootia32.efi Bay Trail" — é um arquivo que se copia pro
> pendrive e resolve. Alternativa: ativar "Legacy/CSM boot" na BIOS.

Depois de instalar, descubra o IP do note (`ip a`) e acesse do seu PC:

```bash
ssh SEU_USUARIO@IP_DO_NOTEBOOK
```

---

## 2. Configurar o notebook pra ser servidor 24/7

**Não suspender ao fechar a tampa:**

```bash
sudo nano /etc/systemd/logind.conf
```

Descomente/ajuste estas linhas:

```
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
```

Salve (Ctrl+O, Enter, Ctrl+X) e aplique:

```bash
sudo systemctl restart systemd-logind
```

**Ligar sozinho após queda de luz:** entre na BIOS/UEFI (F2/Del no boot) e
ative algo como **"Restore on AC Power Loss" → Power On**. A bateria do note
ainda funciona como um mini-nobreak pra quedas rápidas.

---

## 3. Instalar Docker

```bash
sudo apt update && sudo apt install -y git
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
```

Saia e entre de novo no SSH (pro grupo `docker` valer):

```bash
exit
ssh SEU_USUARIO@IP_DO_NOTEBOOK
docker --version   # confirma
```

---

## 4. Baixar e subir o homeOS + HA

```bash
git clone https://github.com/guilhvic/homeOS.git
cd homeOS
mkdir -p data ha-config
```

**(Opcional) Migrar seus dados atuais:** se quiser levar os cômodos, geladeira
e lista que você já criou, copie o `data.db` da sua máquina atual pra `./data/`
(via `scp`). Senão, começa do zero.

Suba tudo:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

- Primeira vez demora alguns minutos (baixa o HA + builda o homeOS).
- HA fica em `http://IP_DO_NOTEBOOK:8123`
- homeOS fica em `http://IP_DO_NOTEBOOK:3030`

> Ver logs: `docker compose -f docker-compose.prod.yml logs -f`

---

## 5. Acesso de qualquer lugar com HTTPS (Tailscale)

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

Ele mostra um link — abra no navegador e faça login (Google/GitHub/email).
Isso conecta o notebook à sua rede privada Tailscale.

**Ativar HTTPS** (uma vez, no painel):
1. Vá em [login.tailscale.com/admin/dns](https://login.tailscale.com/admin/dns)
2. Ative **MagicDNS** e depois **HTTPS Certificates**.

**Expor o homeOS com HTTPS:**

```bash
sudo tailscale serve --bg http://localhost:3030
```

Pronto — o comando mostra a URL final, algo como:

```
https://note.SEU-TAILNET.ts.net
```

Instale o app **Tailscale** no seu celular/PC, faça login na mesma conta, e
acesse essa URL de qualquer lugar. Nada fica exposto na internet pública.

> 💡 Como o cookie de sessão é **Secure** em produção, **acesse sempre pela URL
> `https://...ts.net`** — o login não persiste em `http://` puro (é de propósito).

---

## 6. Conectar o homeOS ao Home Assistant

1. Acesse o **HA** (`http://IP_DO_NOTEBOOK:8123`) e crie a conta / adicione seus
   dispositivos (Settings → Devices & Services).
2. Gere um token: avatar (canto inferior esquerdo) → **Security** →
   **Create Token**.
3. No **homeOS**, aba **Perfil → Home Assistant**:
   - URL: `http://localhost:8123`
   - Token: cole o token
4. Salvar. Os dispositivos aparecem na sincronização (botão 🔄).

---

## 7. Manutenção

**Atualizar o homeOS** (quando eu subir mudanças no GitHub):

```bash
cd ~/homeOS
git pull
docker compose -f docker-compose.prod.yml up -d --build
```

**Atualizar o Home Assistant:**

```bash
docker compose -f docker-compose.prod.yml pull homeassistant
docker compose -f docker-compose.prod.yml up -d
```

**Backup** (o que importa são estas duas pastas):
- `./data/data.db` — suas contas, cômodos, geladeira, listas
- `./ha-config/` — config e histórico do Home Assistant

```bash
tar czf backup-$(date +%F).tar.gz data ha-config
```

Guarde esse `.tar.gz` num pendrive ou na nuvem de vez em quando.

---

## Segurança (resumo)

- Nada exposto na internet pública — só seus aparelhos no Tailscale alcançam.
- Cookie de sessão `Secure` + HTTPS via Tailscale.
- `.env`, `data.db` e afins já bloqueados de download pelo servidor.
- Se um dia você quiser um **link público** (sem app Tailscale), aí sim vale
  trocar pro **Cloudflare Tunnel + domínio** e adicionar rate-limiting no login.
