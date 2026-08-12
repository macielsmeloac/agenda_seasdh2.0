# API Agenda Social SEASDH

## Executar

1. Instale Node.js 18 ou superior.
2. No terminal desta pasta, defina variáveis de ambiente (ou use os valores provisórios) e execute `node server.js`.
3. A API estará em `http://localhost:3000`.

O arquivo `data.json` é criado automaticamente na primeira execução. Para produção, substitua essa persistência por PostgreSQL e mantenha `JWT_SECRET` e a senha administrativa fora do código.

## Endpoints

- `POST /api/auth/register` — cria usuário comum.
- `POST /api/auth/login` — retorna JWT.
- `GET /api/auth/me` — perfil autenticado.
- `GET|POST /api/events`, `PUT|DELETE /api/events/:id` — CRUD de eventos com RBAC.
- `GET|POST|PUT|DELETE /api/users` — administração de usuários (ADMIN).
- `GET /api/audit-logs?startDate=AAAA-MM-DD&endDate=AAAA-MM-DD` — auditoria (ADMIN).

Envie `Authorization: Bearer <token>` nas rotas protegidas.
