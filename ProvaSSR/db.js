import pg from 'pg';

const { Pool } = pg;

// Configuração das credenciais de acesso ao PostgreSQL local
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'Pediatria_Infantil',
    password: 'senai',
    port: 5432,
});

export default pool;