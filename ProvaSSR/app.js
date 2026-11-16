import express from 'express';
import session from 'express-session';
import bcrypt from 'bcrypt';
import path from 'path';
import { fileURLToPath } from 'url';
import pool from './db.js';
import { verificarAutenticacao } from './middlewares/auth.js';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));

// RN04 — Sessão com expiração por inatividade (1 hora)
app.use(session({
    secret: process.env.SESSION_SECRET || 'chave_secreta_pediatria_passos',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 3600000,   // 1 hora em ms
        httpOnly: true,
        sameSite: 'lax'
    }
}));

// ─── Helpers ─────────────────────────────────────────────────────────────────
const asyncRoute = (handler) => (req, res, next) =>
    Promise.resolve(handler(req, res, next)).catch(next);

const campo = (obj, nome) =>
    typeof obj?.[nome] === 'string' ? obj[nome].trim() : '';

const normalizarCpf = (cpf) => cpf.replace(/\D/g, '');

const hashCpf = (cpf) => bcrypt.hash(normalizarCpf(cpf), 10);

const idValido = (valor) => {
    const id = Number(valor);
    return /^[1-9]\d*$/.test(String(valor ?? '')) && Number.isSafeInteger(id) ? id : null;
};

const mensagem = (req) => {
    const atual = req.session.mensagem;
    delete req.session.mensagem;
    return atual || null;
};

const avisar = (req, tipo, texto) => {
    req.session.mensagem = { tipo, texto };
};

const excluirRegistro = async (req, query, parametros, textoVinculo) => {
    try {
        return await pool.query(query, parametros);
    } catch (erro) {
        if (erro.code !== '23503') throw erro;
        avisar(req, 'erro', textoVinculo);
        return null;
    }
};

// ─── AUTENTICAÇÃO (RN03, RN04) ────────────────────────────────────────────────
// RN03: Valida credenciais contra banco de dados
app.get('/login', (req, res) => {
    if (req.session.usuario) return res.redirect('/responsaveis');
    res.render('login', { erro: null });
});

app.post('/login', asyncRoute(async (req, res) => {
    const cpf = campo(req.body, 'cpf').replace(/\D/g, '');
    const senha = typeof req.body?.senha === 'string' ? req.body.senha : '';

    const usuarios = cpf && senha
        ? (await pool.query('SELECT id, nome, senha, cpf_hash FROM usuarios')).rows
        : [];
    let usuario = null;
    for (const candidato of usuarios) {
        if (await bcrypt.compare(cpf, candidato.cpf_hash)) {
            usuario = candidato;
            break;
        }
    }

    // RN03: Mensagem amigável em caso de falha
    if (!usuario || !(await bcrypt.compare(senha, usuario.senha))) {
        return res.status(401).render('login', {
            erro: 'CPF ou senha inválidos. Verifique seus dados e tente novamente.'
        });
    }

    // RN04: Regenera sessão após login bem-sucedido
    await new Promise((resolve, reject) => {
        req.session.regenerate((err) => err ? reject(err) : resolve());
    });
    req.session.usuario = { id: usuario.id, nome: usuario.nome };
    res.redirect('/responsaveis');
}));

// RN04: Encerramento de sessão (logout)
app.get('/logout', (req, res, next) => {
    req.session.destroy((err) => {
        if (err) return next(err);
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

// ─── DASHBOARD (RN05) ─────────────────────────────────────────────────────────
// RN05: Página inicial pós-login com nome do usuário e menu de navegação
app.get('/dashboard', verificarAutenticacao, (req, res) => {
    res.render('dashboard', {
        usuario: req.session.usuario,
        mensagem: mensagem(req)
    });
});

// Redireciona raiz
app.get('/', (req, res) =>
    res.redirect(req.session.usuario ? '/responsaveis' : '/login')
);

// ─── MÓDULO DE RESPONSÁVEIS (RN06) ───────────────────────────────────────────
// RN06: Busca dinâmica por nome ou CPF
app.get('/responsaveis', verificarAutenticacao, asyncRoute(async (req, res) => {
    const busca = campo(req.query, 'busca');
    const responsaveis = (await pool.query(
        `SELECT id, nome, cpf, telefone, email
         FROM responsaveis
         WHERE nome ILIKE $1 OR regexp_replace(cpf, '[^0-9]', '', 'g') ILIKE $2
         ORDER BY nome`,
        [`%${busca}%`, `%${busca.replace(/\D/g, '')}%`]
    )).rows;
    res.render('responsaveis', {
        responsaveis, busca,
        usuario: req.session.usuario,
        mensagem: mensagem(req)
    });
}));

app.get('/responsaveis/novo', verificarAutenticacao, (req, res) => {
    res.render('novo-responsavel', {
        usuario: req.session.usuario,
        dados: {},
        mensagem: mensagem(req)
    });
});

// RN02: Hash do CPF antes de gravar (LGPD)
app.post('/responsaveis/novo', verificarAutenticacao, asyncRoute(async (req, res) => {
    const dados = {
        nome: campo(req.body, 'nome'),
        cpf: campo(req.body, 'cpf'),
        telefone: campo(req.body, 'telefone'),
        email: campo(req.body, 'email')
    };

    if (!dados.nome || !dados.cpf) {
        return res.status(400).render('novo-responsavel', {
            usuario: req.session.usuario, dados,
            mensagem: { tipo: 'erro', texto: 'Nome e CPF são obrigatórios.' }
        });
    }

    // RN02: CPF gravado também como hash bcrypt (LGPD)
    const cpfSomenteDigitos = dados.cpf.replace(/\D/g, '');
    const cpfHash = await bcrypt.hash(cpfSomenteDigitos, 10);

    await pool.query(
        `INSERT INTO responsaveis (nome, cpf, cpf_hash, telefone, email)
         VALUES ($1, $2, $3, $4, $5)`,
        [dados.nome, dados.cpf, cpfHash, dados.telefone || null, dados.email || null]
    );
    avisar(req, 'sucesso', 'Responsável cadastrado com sucesso.');
    res.redirect('/responsaveis');
}));

app.get('/responsaveis/editar/:id', verificarAutenticacao, asyncRoute(async (req, res) => {
    const id = idValido(req.params.id);
    if (!id) return res.status(400).send('ID inválido.');
    const resp = (await pool.query(
        'SELECT id, nome, cpf, telefone, email FROM responsaveis WHERE id = $1',
        [id]
    )).rows[0];
    if (!resp) return res.status(404).send('Responsável não encontrado.');
    res.render('editar-responsavel', {
        responsavel: resp,
        usuario: req.session.usuario,
        mensagem: mensagem(req)
    });
}));

app.post('/responsaveis/editar/:id', verificarAutenticacao, asyncRoute(async (req, res) => {
    const id = idValido(req.params.id);
    if (!id) return res.status(400).send('ID inválido.');
    const dados = {
        nome: campo(req.body, 'nome'),
        cpf: campo(req.body, 'cpf'),
        telefone: campo(req.body, 'telefone'),
        email: campo(req.body, 'email')
    };

    if (!dados.nome || !dados.cpf) {
        const resp = (await pool.query(
            'SELECT id, nome, cpf, telefone, email FROM responsaveis WHERE id = $1', [id]
        )).rows[0];
        if (!resp) return res.status(404).send('Responsável não encontrado.');
        return res.status(400).render('editar-responsavel', {
            responsavel: { ...resp, ...dados },
            usuario: req.session.usuario,
            mensagem: { tipo: 'erro', texto: 'Nome e CPF são obrigatórios.' }
        });
    }

    // RN02: Atualiza o hash do CPF junto com o CPF legível
    const cpfSomenteDigitos = dados.cpf.replace(/\D/g, '');
    const cpfHash = await bcrypt.hash(cpfSomenteDigitos, 10);

    const resultado = await pool.query(
        `UPDATE responsaveis SET nome = $1, cpf = $2, cpf_hash = $3,
         telefone = $4, email = $5 WHERE id = $6`,
        [dados.nome, dados.cpf, cpfHash, dados.telefone || null, dados.email || null, id]
    );
    if (!resultado.rowCount) return res.status(404).send('Responsável não encontrado.');
    avisar(req, 'sucesso', 'Responsável atualizado com sucesso.');
    res.redirect('/responsaveis');
}));

app.post('/responsaveis/deletar/:id', verificarAutenticacao, asyncRoute(async (req, res) => {
    const id = idValido(req.params.id);
    if (!id) return res.status(400).send('ID inválido.');
    const resultado = await excluirRegistro(
        req,
        'DELETE FROM responsaveis WHERE id = $1',
        [id],
        'Não é possível excluir este responsável porque existem crianças vinculadas.'
    );
    if (!resultado) return res.redirect('/responsaveis');
    if (!resultado.rowCount) return res.status(404).send('Responsável não encontrado.');
    avisar(req, 'sucesso', 'Responsável excluído com sucesso.');
    res.redirect('/responsaveis');
}));

// ─── MÓDULO DE CRIANÇAS (RN07) ───────────────────────────────────────────────
// RN07: Cadastro exige vínculo com responsável existente
app.get('/criancas', verificarAutenticacao, asyncRoute(async (req, res) => {
    const criancas = (await pool.query(
        `SELECT c.id, c.nome, c.data_nascimento,
                r.nome AS nome_responsavel, r.id AS responsavel_id
         FROM criancas c
         JOIN responsaveis r ON r.id = c.responsavel_id
         ORDER BY c.nome`
    )).rows;
    res.render('criancas', {
        criancas,
        usuario: req.session.usuario,
        mensagem: mensagem(req)
    });
}));

app.get('/criancas/nova', verificarAutenticacao, asyncRoute(async (req, res) => {
    const responsaveis = (await pool.query(
        'SELECT id, nome FROM responsaveis ORDER BY nome'
    )).rows;
    res.render('nova-crianca', {
        responsaveis,
        usuario: req.session.usuario,
        dados: {},
        mensagem: mensagem(req)
    });
}));

app.post('/criancas/nova', verificarAutenticacao, asyncRoute(async (req, res) => {
    const dados = {
        nome: campo(req.body, 'nome'),
        data_nascimento: campo(req.body, 'data_nascimento'),
        responsavel_id: campo(req.body, 'responsavel_id')
    };
    const respId = idValido(dados.responsavel_id);

    if (!dados.nome || !dados.data_nascimento || !respId) {
        const responsaveis = (await pool.query(
            'SELECT id, nome FROM responsaveis ORDER BY nome'
        )).rows;
        return res.status(400).render('nova-crianca', {
            responsaveis, usuario: req.session.usuario, dados,
            mensagem: { tipo: 'erro', texto: 'Preencha nome, data de nascimento e selecione um responsável.' }
        });
    }

    await pool.query(
        'INSERT INTO criancas (nome, data_nascimento, responsavel_id) VALUES ($1, $2, $3)',
        [dados.nome, dados.data_nascimento, respId]
    );
    avisar(req, 'sucesso', 'Criança cadastrada com sucesso.');
    res.redirect('/criancas');
}));

app.get('/criancas/editar/:id', verificarAutenticacao, asyncRoute(async (req, res) => {
    const id = idValido(req.params.id);
    if (!id) return res.status(400).send('ID inválido.');
    const [crianca, responsaveis] = await Promise.all([
        pool.query(
            'SELECT id, nome, data_nascimento, responsavel_id FROM criancas WHERE id = $1',
            [id]
        ),
        pool.query('SELECT id, nome FROM responsaveis ORDER BY nome')
    ]);
    if (!crianca.rows[0]) return res.status(404).send('Criança não encontrada.');
    res.render('editar-crianca', {
        crianca: crianca.rows[0],
        responsaveis: responsaveis.rows,
        usuario: req.session.usuario,
        mensagem: mensagem(req)
    });
}));

app.post('/criancas/editar/:id', verificarAutenticacao, asyncRoute(async (req, res) => {
    const id = idValido(req.params.id);
    if (!id) return res.status(400).send('ID inválido.');
    const dados = {
        nome: campo(req.body, 'nome'),
        data_nascimento: campo(req.body, 'data_nascimento'),
        responsavel_id: campo(req.body, 'responsavel_id')
    };
    const respId = idValido(dados.responsavel_id);

    if (!dados.nome || !dados.data_nascimento || !respId) {
        const [crianca, responsaveis] = await Promise.all([
            pool.query('SELECT id, nome, data_nascimento, responsavel_id FROM criancas WHERE id = $1', [id]),
            pool.query('SELECT id, nome FROM responsaveis ORDER BY nome')
        ]);
        if (!crianca.rows[0]) return res.status(404).send('Criança não encontrada.');
        return res.status(400).render('editar-crianca', {
            crianca: { ...crianca.rows[0], ...dados },
            responsaveis: responsaveis.rows,
            usuario: req.session.usuario,
            mensagem: { tipo: 'erro', texto: 'Preencha todos os campos obrigatórios.' }
        });
    }

    const resultado = await pool.query(
        'UPDATE criancas SET nome = $1, data_nascimento = $2, responsavel_id = $3 WHERE id = $4',
        [dados.nome, dados.data_nascimento, respId, id]
    );
    if (!resultado.rowCount) return res.status(404).send('Criança não encontrada.');
    avisar(req, 'sucesso', 'Dados da criança atualizados com sucesso.');
    res.redirect('/criancas');
}));

app.post('/criancas/deletar/:id', verificarAutenticacao, asyncRoute(async (req, res) => {
    const id = idValido(req.params.id);
    if (!id) return res.status(400).send('ID inválido.');
    const resultado = await excluirRegistro(
        req,
        'DELETE FROM criancas WHERE id = $1',
        [id],
        'Não é possível excluir esta criança porque existem agendamentos vinculados.'
    );
    if (!resultado) return res.redirect('/criancas');
    if (!resultado.rowCount) return res.status(404).send('Criança não encontrada.');
    avisar(req, 'sucesso', 'Criança excluída com sucesso.');
    res.redirect('/criancas');
}));

// ─── MÓDULO DE AGENDAMENTOS (RN08) ───────────────────────────────────────────
// RN08: JOIN entre agendamentos, crianças e responsáveis, ordenado por data_consulta
app.get('/agendamentos', verificarAutenticacao, asyncRoute(async (req, res) => {
    const agendamentos = (await pool.query(
        `SELECT a.id, a.data_consulta, a.hora_consulta, a.medico, a.observacoes,
                c.nome       AS nome_crianca,
                c.data_nascimento,
                r.nome       AS nome_responsavel,
                r.telefone   AS telefone_responsavel
         FROM agendamentos a
         JOIN criancas    c ON c.id = a.crianca_id
         JOIN responsaveis r ON r.id = c.responsavel_id
         ORDER BY a.data_consulta ASC, a.hora_consulta ASC`
    )).rows;
    res.render('agendamentos', {
        agendamentos,
        usuario: req.session.usuario,
        mensagem: mensagem(req)
    });
}));

app.get('/agendamentos/novo', verificarAutenticacao, asyncRoute(async (req, res) => {
    const criancas = (await pool.query(
        `SELECT c.id, c.nome AS nome_crianca, r.nome AS nome_responsavel
         FROM criancas c JOIN responsaveis r ON r.id = c.responsavel_id
         ORDER BY c.nome`
    )).rows;
    res.render('novo-agendamento', {
        criancas,
        usuario: req.session.usuario,
        dados: {},
        mensagem: mensagem(req)
    });
}));

app.post('/agendamentos/novo', verificarAutenticacao, asyncRoute(async (req, res) => {
    const dados = {
        crianca_id: campo(req.body, 'crianca_id'),
        cpf: campo(req.body, 'cpf'),
        data_consulta: campo(req.body, 'data_consulta'),
        hora_consulta: campo(req.body, 'hora_consulta'),
        medico: campo(req.body, 'medico'),
        observacoes: campo(req.body, 'observacoes')
    };
    const criancaId = idValido(dados.crianca_id);
    const cpf = normalizarCpf(dados.cpf);

    if (!criancaId || !dados.data_consulta || !/^\d{11}$/.test(cpf)) {
        const criancas = (await pool.query(
            `SELECT c.id, c.nome AS nome_crianca, r.nome AS nome_responsavel
             FROM criancas c JOIN responsaveis r ON r.id = c.responsavel_id ORDER BY c.nome`
        )).rows;
        return res.status(400).render('novo-agendamento', {
            criancas, usuario: req.session.usuario, dados,
            mensagem: {
                tipo: 'erro',
                texto: 'Selecione a criança, informe um CPF com 11 dígitos e a data da consulta.'
            }
        });
    }

    const responsavel = (await pool.query(
        `SELECT r.cpf_hash
         FROM criancas c JOIN responsaveis r ON r.id = c.responsavel_id
         WHERE c.id = $1`,
        [criancaId]
    )).rows[0];
    if (!responsavel || !(await bcrypt.compare(cpf, responsavel.cpf_hash))) {
        const criancas = (await pool.query(
            `SELECT c.id, c.nome AS nome_crianca, r.nome AS nome_responsavel
             FROM criancas c JOIN responsaveis r ON r.id = c.responsavel_id ORDER BY c.nome`
        )).rows;
        return res.status(400).render('novo-agendamento', {
            criancas, usuario: req.session.usuario, dados,
            mensagem: {
                tipo: 'erro',
                texto: 'O CPF informado não corresponde ao responsável da criança selecionada.'
            }
        });
    }

    const cpfHash = await hashCpf(cpf);
    await pool.query(
        `INSERT INTO agendamentos (crianca_id, cpf_hash, data_consulta, hora_consulta, medico, observacoes)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
            criancaId,
            cpfHash,
            dados.data_consulta,
            dados.hora_consulta || null,
            dados.medico || null,
            dados.observacoes || null
        ]
    );
    avisar(req, 'sucesso', 'Agendamento criado com sucesso.');
    res.redirect('/agendamentos');
}));

// Remarcação de agendamento (atualiza data/hora)
app.get('/agendamentos/editar/:id', verificarAutenticacao, asyncRoute(async (req, res) => {
    const id = idValido(req.params.id);
    if (!id) return res.status(400).send('ID inválido.');
    const agendamento = (await pool.query(
        `SELECT a.id, a.data_consulta, a.hora_consulta, a.medico, a.observacoes, a.crianca_id,
                c.nome AS nome_crianca, r.nome AS nome_responsavel
         FROM agendamentos a
         JOIN criancas c ON c.id = a.crianca_id
         JOIN responsaveis r ON r.id = c.responsavel_id
         WHERE a.id = $1`,
        [id]
    )).rows[0];
    if (!agendamento) return res.status(404).send('Agendamento não encontrado.');
    res.render('editar-agendamento', {
        agendamento,
        usuario: req.session.usuario,
        mensagem: mensagem(req)
    });
}));

app.post('/agendamentos/editar/:id', verificarAutenticacao, asyncRoute(async (req, res) => {
    const id = idValido(req.params.id);
    if (!id) return res.status(400).send('ID inválido.');
    const dados = {
        data_consulta: campo(req.body, 'data_consulta'),
        hora_consulta: campo(req.body, 'hora_consulta'),
        medico: campo(req.body, 'medico'),
        observacoes: campo(req.body, 'observacoes')
    };

    if (!dados.data_consulta) {
        const agendamento = (await pool.query(
            `SELECT a.id, a.data_consulta, a.hora_consulta, a.medico, a.observacoes, a.crianca_id,
                    c.nome AS nome_crianca, r.nome AS nome_responsavel
             FROM agendamentos a
             JOIN criancas c ON c.id = a.crianca_id
             JOIN responsaveis r ON r.id = c.responsavel_id
             WHERE a.id = $1`, [id]
        )).rows[0];
        if (!agendamento) return res.status(404).send('Agendamento não encontrado.');
        return res.status(400).render('editar-agendamento', {
            agendamento: { ...agendamento, ...dados },
            usuario: req.session.usuario,
            mensagem: { tipo: 'erro', texto: 'Informe a data da consulta.' }
        });
    }

    const resultado = await pool.query(
        `UPDATE agendamentos SET data_consulta = $1, hora_consulta = $2,
         medico = $3, observacoes = $4 WHERE id = $5`,
        [dados.data_consulta, dados.hora_consulta || null, dados.medico || null, dados.observacoes || null, id]
    );
    if (!resultado.rowCount) return res.status(404).send('Agendamento não encontrado.');
    avisar(req, 'sucesso', 'Agendamento remarcado com sucesso.');
    res.redirect('/agendamentos');
}));

app.post('/agendamentos/deletar/:id', verificarAutenticacao, asyncRoute(async (req, res) => {
    const id = idValido(req.params.id);
    if (!id) return res.status(400).send('ID inválido.');
    const resultado = await excluirRegistro(
        req,
        'DELETE FROM agendamentos WHERE id = $1',
        [id],
        'Não é possível cancelar este agendamento porque existem registros vinculados.'
    );
    if (!resultado) return res.redirect('/agendamentos');
    if (!resultado.rowCount) return res.status(404).send('Agendamento não encontrado.');
    avisar(req, 'sucesso', 'Agendamento cancelado com sucesso.');
    res.redirect('/agendamentos');
}));

// ─── ERROS ───────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).send('Página não encontrada.'));
app.use((erro, req, res, next) => {
    console.error('Erro na aplicação:', erro);
    if (res.headersSent) return next(erro);
    if (erro.code === '23505') return res.status(409).send('Já existe um registro com esse CPF.');
    if (erro.code === '23503') return res.status(409).send('Não é possível excluir: existem registros vinculados.');
    res.status(500).send('Erro interno no servidor.');
});

app.listen(process.env.PORT || 3000, () => {
    console.log(`Sistema Pediátrico rodando em http://localhost:${process.env.PORT || 3000}`);
});
