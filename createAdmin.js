const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Conexão com a base de dados
mongoose.connect('mongodb://localhost:27017/cambio-app')
    .then(() => console.log('Conectado à base de dados para criar admin.'))
    .catch(err => console.error('Erro ao conectar ao MongoDB:', err));

const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isPremium: { type: Boolean, default: false },
    isAdmin: { type: Boolean, default: false }
});
const User = mongoose.model('User', UserSchema);

const createAdminUser = async () => {
    const email = 'admin@cambio.com';
    const password = 'adminpassword123';

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            console.log('Utilizador admin já existe. Atualizando para admin...');
            await User.updateOne({ email }, { isAdmin: true });
            console.log('Utilizador admin atualizado com sucesso!');
            return;
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const adminUser = new User({
            email,
            password: hashedPassword,
            isAdmin: true, // Garante que a conta admin tem a propriedade
            isPremium: true // O admin também é premium
        });
        await adminUser.save();
        console.log('Utilizador admin criado com sucesso!');
    } catch (err) {
        console.error('Erro ao criar o utilizador admin:', err);
    } finally {
        mongoose.disconnect();
    }
};

createAdminUser();
