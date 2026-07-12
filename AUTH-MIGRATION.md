# VM Agro - implantação do Supabase Auth

## Arquivos

- `publicacao-hastaagro/index.html`: login, cadastro, recuperação, sessão, matriz de permissões e painel de usuários.
- `supabase-schema.sql`: organizações, perfis, vínculos, permissões, auditoria, RLS e migração do armazenamento existente.
- `supabase/functions/admin-users/index.ts`: operações administrativas protegidas pela `service_role`.
- `.env.example`: variáveis públicas necessárias no build.

## 1. Variáveis do Vercel

Configure em **Settings > Environment Variables**:

```text
VITE_SUPABASE_URL=https://SEU_PROJETO.supabase.co
VITE_SUPABASE_ANON_KEY=SUA_CHAVE_ANON_PUBLICA
```

Nunca coloque `SUPABASE_SERVICE_ROLE_KEY` no HTML, no Vercel público ou em `supabase-config.js`.

## 2. Banco e RLS

No SQL Editor do Supabase, execute todo o arquivo `supabase-schema.sql`.

Ele cria:

- `organizations`
- `profiles`
- `organization_members`
- `user_permissions`
- `audit_logs`
- atualização segura de `vm_agro_data`
- gatilho de novos usuários pendentes
- proteção do último Master
- políticas RLS por organização e função

## 3. Edge Function administrativa

Com o Supabase CLI autenticado na pasta do projeto:

```bash
supabase functions deploy admin-users
```

No ambiente da função, o Supabase fornece `SUPABASE_URL`, `SUPABASE_ANON_KEY` e `SUPABASE_SERVICE_ROLE_KEY`. A `service_role` permanece somente no servidor.

## 4. Primeiro Master

1. Publique e crie a conta do proprietário na nova tela de cadastro.
2. Confirme o e-mail, se a confirmação estiver habilitada.
3. No final de `supabase-schema.sql`, copie o bloco **PRIMEIRO MASTER**.
4. Substitua `SEU_EMAIL_MASTER` pelo e-mail cadastrado e execute o bloco.
5. Saia e entre novamente.

O sistema impede que o último Master ativo seja bloqueado, removido ou rebaixado.

## 5. Dados existentes

Antes de migrar, faça uma exportação de segurança pelo relatório/backup atual.

Há duas formas seguras de trazer os dados locais:

1. Ao primeiro login ativo na organização vazia, a aplicação envia o cache local existente para `vm_agro_data` usando o `organization_id`.
2. Para linhas que já estejam no Supabase sem organização, execute o bloco **MIGRAÇÃO DOS DADOS JSON EXISTENTES** no final do SQL.

Os nomes das chaves existentes (`config`, `lotes`, `futuros` e dados financeiros) são preservados. Nenhuma fórmula da calculadora foi alterada.

## 6. Migração dos usuários antigos

Senhas antigas gravadas no HTML não são importadas. Isso é intencional: senhas não podem ser copiadas para o Supabase Auth.

Para cada usuário antigo:

1. Use **Configurações > Usuários e acessos > Adicionar usuário**; ou peça que ele crie a própria conta.
2. Aprove o cadastro.
3. Defina a função correta.
4. O usuário cria/redefine a senha pelo e-mail seguro do Supabase.

## 7. Matriz padrão

- **Master**: acesso total e administração de segurança.
- **Administrador**: operação completa e usuários abaixo de Administrador.
- **Gestor**: lotes completos, realizado, frete, relatórios e B3 somente leitura por padrão.
- **Editor**: cria e edita lotes próprios/atribuídos.
- **Visualizador**: somente leitura dos dados permitidos.
- **Operador B3**: B3 e dados de hedge, sem acesso operacional amplo.

Permissões adicionais podem ser concedidas no painel. As ações administrativas são auditadas.

## 8. Configuração do Supabase Auth

Em **Authentication > URL Configuration**:

- defina o domínio publicado como `Site URL`;
- inclua o domínio de produção e os endereços locais usados em desenvolvimento em `Redirect URLs`;
- configure o provedor de e-mail e os templates de convite/recuperação.

## Checklist de publicação

- SQL executado sem erro.
- Primeiro Master ativo.
- Edge Function `admin-users` publicada.
- variáveis `VITE_SUPABASE_URL` e `VITE_SUPABASE_ANON_KEY` configuradas.
- URLs de redirecionamento cadastradas.
- login, logout, recuperação e persistência de sessão testados.
- usuário pendente não acessa a aplicação.
- Visualizador não consegue gravar.
- Editor vê somente lotes próprios/atribuídos.
- Administrador não consegue alterar Master.
