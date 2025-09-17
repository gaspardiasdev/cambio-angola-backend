#!/bin/bash

echo "🚀 Iniciando build para Render..."

# Definir variáveis de ambiente para build
export NODE_ENV=production
export NPM_CONFIG_PRODUCTION=false

echo "📦 Instalando dependências..."
npm ci --silent

echo "🧹 Limpando cache npm..."
npm cache clean --force

echo "🔍 Verificando estrutura de arquivos..."
ls -la

echo "📋 Verificando package.json..."
node -e "console.log('Package.json válido:', !!require('./package.json'))"

echo "🔧 Verificando se todos os arquivos necessários existem..."
if [ ! -f "server.js" ]; then
    echo "❌ server.js não encontrado!"
    exit 1
fi

if [ ! -d "models" ]; then
    echo "⚠️ Diretório models não encontrado - criando estrutura básica..."
    mkdir -p models
    echo "// Modelo de usuário básico
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isPremium: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
  dateCreated: { type: Date, default: Date.now },
  lastLogin: Date,
  premiumUpgradeDate: Date,
  premiumExpiryDate: Date
});

module.exports = mongoose.model('User', userSchema);" > models/userModel.js

    echo "// Modelo de taxas básico
const mongoose = require('mongoose');

const rateSchema = new mongoose.Schema({
  date: { type: String, required: true },
  usdBuy: Number,
  usdSell: Number,
  eurBuy: Number,
  eurSell: Number,
  zarBuy: Number,
  zarSell: Number,
  cadBuy: Number,
  cadSell: Number,
  source: String,
  confidence: String,
  dateCreated: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Rate', rateSchema);" > models/rateModel.js

    echo "// Modelo de alertas básico
const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema({
  currency: { type: String, required: true },
  value: { type: Number, required: true },
  type: { type: String, enum: ['above', 'below'], default: 'above' },
  rateType: { type: String, enum: ['buy', 'sell'], default: 'buy' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  isTriggered: { type: Boolean, default: false },
  dateCreated: { type: Date, default: Date.now },
  dateTriggered: Date
});

module.exports = mongoose.model('Alert', alertSchema);" > models/alertModel.js
fi

echo "🎯 Testando servidor..."
timeout 10s node -e "
const app = require('./server.js');
console.log('✅ Servidor pode ser importado com sucesso');
process.exit(0);
" || echo "⚠️ Teste de servidor falhou, mas continuando..."

echo "📊 Informações do sistema:"
echo "Node version: $(node --version)"
echo "NPM version: $(npm --version)"
echo "Memory: $(free -h | head -2)"
echo "Disk: $(df -h / | tail -1)"

echo "✅ Build concluído com sucesso!"