Projeto de Câmbio e Alertas
Descrição
Esta aplicação permite aos utilizadores seguir a evolução de taxas de câmbio em tempo real e definir alertas para serem notificados via WhatsApp quando uma taxa atinge um valor desejado. A aplicação conta com um sistema de autenticação, um painel de administração e funcionalidades exclusivas para utilizadores premium.

Fases do Projeto (Roadmap)
Fase 1 (MVP): Implementação de funcionalidades básicas como comparação de taxas, dados de fontes transparentes, um alerta limitado por utilizador e um histórico de 7 dias.

Fase 2 (Monetização): Expansão das funcionalidades para utilizadores premium, incluindo alertas ilimitados e histórico expandido.

Fase 3 (Expansão): Introdução de uma API para negócios e funcionalidades de comunidade.

Fase 4 (Escala): Expansão regional para outros países africanos.

Estrutura do Projeto
server.js: Ficheiro principal do servidor Node.js que contém todas as rotas da API.

models/userModel.js: Define o esquema e o modelo para os utilizadores.

models/alertModel.js: Define o esquema e o modelo para os alertas.

Endpoints da API
Autenticação
POST /api/auth/register: Regista um novo utilizador.

POST /api/auth/login: Autentica um utilizador.

Taxas de Câmbio
GET /api/rates: Retorna as taxas de câmbio.

Para utilizadores não autenticados ou básicos: Retorna as taxas dos últimos 3 dias.

Para utilizadores premium: Retorna o histórico completo de taxas.

Endpoints de Alertas
POST /api/alerts: Cria um novo alerta para o utilizador autenticado.

Para utilizadores não premium: Apenas pode ter 1 alerta ativo. Se tentar criar um segundo, será negado com um erro 403.

Para utilizadores premium: Pode criar alertas ilimitados.

GET /api/alerts: Retorna todos os alertas definidos pelo utilizador autenticado.

DELETE /api/alerts/:id: Apaga um alerta específico.

Painel de Administração
POST /api/admin/upgrade-to-premium: Apenas para administradores. Atualiza um utilizador para premium.

POST /api/admin/update-rates: Apenas para administradores. Atualiza as taxas de câmbio.

Como Executar
Certifica-te de que o MongoDB está a correr localmente.

Abre o terminal e executa node server.js para iniciar o servidor.

O servidor irá correr em http://192.168.89.7:5000.

O script createAdmin.js pode ser executado manualmente para criar ou atualizar a conta de administrador inicial.