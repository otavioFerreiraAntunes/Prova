import bcrypt from 'bcrypt';

const [cpf, senha] = process.argv.slice(2);

if (!cpf || !senha) {
    console.error('Uso: node gerar-hash.js <cpf> <senha>');
    process.exitCode = 1;
} else {
    try {
        const cpfSomenteDigitos = cpf.replace(/\D/g, '');
        const [cpfHash, senhaHash] = await Promise.all([
            bcrypt.hash(cpfSomenteDigitos, 10),
            bcrypt.hash(senha, 10)
        ]);

        console.log('Hash do CPF:', cpfHash);
        console.log('Hash da senha:', senhaHash);
    } catch (erro) {
        console.error('Erro ao gerar hashes:', erro);
        process.exitCode = 1;
    }
}