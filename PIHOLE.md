# Pi-hole no servidor de casa

Bloqueio de anúncios e rastreadores para **todos** os aparelhos da rede, via DNS.
Roda em Docker ao lado do homeOS/Home Assistant, sem interferir neles.

> Todos os comandos rodam **no servidor** (via SSH pelo Tailscale, por ex.), na
> pasta do projeto (`~/homeOS`), como o usuário `gui`.

---

## 1. Liberar a porta 53 (systemd-resolved)

O Xubuntu já usa a porta 53 para DNS (`systemd-resolved`). O Pi-hole precisa dela.
Libere o "stub listener" mantendo o host ainda capaz de resolver nomes:

```bash
sudo sed -i 's/^#\?DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

Confira que a 53 ficou livre (não deve aparecer nada em `0.0.0.0:53` além do que você vai subir):

```bash
sudo ss -luntp | grep ':53 '
```

## 2. Definir a senha do painel (no .env)

O `.env` é ignorado pelo git (não vai pro repositório público). Adicione uma linha:

```bash
echo "PIHOLE_PASSWORD=troque-esta-senha" >> ~/homeOS/.env
```

## 3. Subir o Pi-hole

```bash
cd ~/homeOS
git pull
docker compose -f docker-compose.pihole.yml up -d
docker logs -f pihole   # Ctrl+C para sair; espere "FTL started"
```

Painel: **http://\<IP-do-servidor\>/admin** — entre com a senha do `.env`.
(Descubra o IP com `hostname -I`.)

## 4. Fazer os aparelhos usarem o Pi-hole

Escolha **uma** das opções:

- **Rede toda (recomendado):** no seu **roteador**, em DNS do DHCP, coloque o IP do
  servidor como servidor DNS primário. Todos os aparelhos passam a filtrar
  automaticamente. (Deixe um DNS secundário público, ex. 1.1.1.1, como rede de segurança.)
- **Só um aparelho:** configure o DNS manual do celular/PC para o IP do servidor.

Teste: abra `http://<IP>/admin`, aba **Query Log** — deve aparecer o tráfego DNS,
com bloqueios marcados em vermelho.

## 5. Manutenção

```bash
# Atualizar as listas de bloqueio
docker exec pihole pihole -g

# Atualizar a imagem do Pi-hole
cd ~/homeOS
docker compose -f docker-compose.pihole.yml pull
docker compose -f docker-compose.pihole.yml up -d

# Trocar a senha do painel
docker exec -it pihole pihole setpassword
```

---

## Notas e cuidados

- **Ponto único de falha de DNS:** se o servidor cair, a internet "some" para quem
  usa só o Pi-hole. Por isso o DNS secundário público no passo 4 é importante.
- **Acesso remoto:** dá para expor o painel pelo Tailscale
  (`tailscale serve --bg 80`), mas **não** exponha a porta 53 na internet pública.
- **Conflito de porta 80:** hoje o homeOS usa a 3030 e o HA a 8123, então a 80 está
  livre para o painel. Se um dia precisar mudar, dá para configurar outra porta web
  no Pi-hole (`FTLCONF_webserver_port`).
- **Persistência:** tudo fica em `~/homeOS/pihole/etc-pihole/` (fora do container).
