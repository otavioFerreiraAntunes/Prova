import bcrypt from 'bcrypt';
import pool from './db.js';

try {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const colunas = (await client.query(
            `SELECT column_name FROM information_schema.columns
             WHERE table_schema = current_schema() AND table_name = 'usuarios'`
        )).rows.map((coluna) => coluna.column_name);

        if (!colunas.length) throw new Error('Tabela usuarios não encontrada.');
        if (!colunas.includes('cpf_hash')) {
            await client.query('ALTER TABLE usuarios ADD COLUMN cpf_hash VARCHAR(255)');
        }

        if (colunas.includes('cpf')) {
            const registros = (await client.query('SELECT id, cpf FROM usuarios')).rows;
            for (const registro of registros) {
                const cpf = String(registro.cpf).replace(/\D/g, '');
                if (!/^\d{11}$/.test(cpf)) {
                    throw new Error(`CPF inválido no usuário ${registro.id}.`);
                }
                const cpfHash = await bcrypt.hash(cpf, 10);
                await client.query(
                    'UPDATE usuarios SET cpf_hash = $1 WHERE id = $2',
                    [cpfHash, registro.id]
                );
            }
            await client.query('ALTER TABLE usuarios ALTER COLUMN cpf_hash SET NOT NULL');
            await client.query('ALTER TABLE usuarios DROP COLUMN cpf');
        } else {
            const vazios = (await client.query(
                'SELECT COUNT(*) AS total FROM usuarios WHERE cpf_hash IS NULL'
            )).rows[0].total;
            if (Number(vazios) > 0) {
                throw new Error('Há usuários sem hash de CPF; não foi possível concluir a migração.');
            }
            await client.query('ALTER TABLE usuarios ALTER COLUMN cpf_hash SET NOT NULL');
        }

        await client.query('COMMIT');
        console.log('CPF de login migrado para hash; coluna em texto puro removida.');
    } catch (erro) {
        await client.query('ROLLBACK');
        throw erro;
    } finally {
        client.release();
    }
} catch (erro) {
    console.error('Erro ao migrar CPF de login:', erro);
    process.exitCode = 1;
} finally {
    await pool.end();
}
