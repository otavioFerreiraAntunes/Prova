import bcrypt from 'bcrypt';

const senhaPlana = process.argv[2] || '123456';

try {
    const hash = await bcrypt.hash(senhaPlana, 10);
    console.log('Hash gerado com sucesso: ' + hash);
} catch (erro) {
    console.error('Erro ao gerar hash:', erro);
    process.exitCode = 1;
}
