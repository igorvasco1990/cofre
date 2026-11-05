# Cofre: gerenciador de senhas offline (PWA)

Funciona no Android e no iPhone. As senhas ficam **só no aparelho**, cifradas com a senha mestra (PBKDF2-SHA256 com 600 mil iterações + AES-256-GCM). O app não tem nenhuma chamada de rede: o CSP `connect-src 'none'` bloqueia qualquer envio de dados, mesmo que alguém tente.

## 1. Publicar uma vez (precisa de HTTPS)

O navegador só libera criptografia e modo offline em endereços `https://`. O jeito mais simples e gratuito é o **GitHub Pages**:

1. Crie um repositório (pode ser privado no GitHub Pro, ou público: o código não contém senha nenhuma).
2. Suba todos os arquivos desta pasta (`index.html`, `app.js`, `style.css`, `sw.js`, `manifest.webmanifest`, `icons/`).
3. Vá em *Settings → Pages → Branch: main / root → Save*.
4. Em 1 ou 2 minutos fica disponível em `https://SEU-USUARIO.github.io/NOME-DO-REPO/`.

Depois de instalado, o app abre sem internet. O site serve só para entregar o código; os dados nunca vão para ele.

## 2. Instalar no celular

- **Android (Chrome):** abra o endereço, toque em ⋮ e depois em **Instalar app** (ou *Adicionar à tela inicial*).
- **iPhone (Safari):** abra o endereço, toque em **Compartilhar** e depois em **Adicionar à Tela de Início**.

No iPhone, crie o cofre **dentro do app instalado**, não na aba do Safari. Os dois guardam dados separados.

## 3. Passar as senhas de um celular para o outro

1. No celular de origem, vá em ⚙︎, depois em **Exportar backup criptografado**.
2. Leve o arquivo `.json` até o outro celular (AirDrop, cabo, pendrive, app Arquivos…).
3. No outro celular, use **Restaurar de um backup** (na primeira vez) ou ⚙︎ → **Importar backup (mesclar)**.
4. Digite a senha mestra usada quando o backup foi feito.

A importação junta as senhas: entradas novas são adicionadas e, quando a mesma entrada existe nos dois, fica a versão editada por último. Exclusões **não** são levadas para o outro aparelho.

## Funções

- Busca por nome, usuário ou site; botão 📋 copia a senha direto da lista
- Gerador de senhas (8 a 40 caracteres, aleatoriedade criptográfica)
- Bloqueio automático ao sair do app ou por inatividade (configurável)
- Limpeza automática da área de transferência (melhor esforço: o iOS pode não permitir quando o app está em segundo plano)
- Troca de senha mestra, aviso de backup pendente e opção de apagar o cofre

## Cuidados

- **Não existe recuperação da senha mestra.** Esqueceu, perdeu o cofre.
- **Faça backup regularmente.** Se o celular for perdido ou você limpar os dados do navegador, só o backup salva. Guarde uma cópia fora do celular.
- Para atualizar o app, altere o código e mude `CACHE` em `sw.js` (ex.: `cofre-v1.0.1`). Os celulares baixam a versão nova quando abrirem o app com internet. Os dados não são afetados.
