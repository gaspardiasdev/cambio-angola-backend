// models/rateModel.js
const mongoose = require("mongoose");

const rateSchema = new mongoose.Schema({
  date: {
    type: Date,
    required: true,
    index: true
  },
  // Dólar Americano
  usdBuy: {
    type: Number,
    required: true,
    min: [0, "Taxa não pode ser negativa"]
  },
  usdSell: {
    type: Number,
    required: true,
    min: [0, "Taxa não pode ser negativa"]
  },
  // Euro
  eurBuy: {
    type: Number,
    required: true,
    min: [0, "Taxa não pode ser negativa"]
  },
  eurSell: {
    type: Number,
    required: true,
    min: [0, "Taxa não pode ser negativa"]
  },
  // Rand Sul-Africano
  zarBuy: {
    type: Number,
    required: true,
    min: [0, "Taxa não pode ser negativa"]
  },
  zarSell: {
    type: Number,
    required: true,
    min: [0, "Taxa não pode ser negativa"]
  },
  // Dólar Canadense
  cadBuy: {
    type: Number,
    required: true,
    min: [0, "Taxa não pode ser negativa"]
  },
  cadSell: {
    type: Number,
    required: true,
    min: [0, "Taxa não pode ser negativa"]
  },
  // Metadados
  source: {
    type: String,
    enum: ['BNA', 'Mercado', 'Admin', 'API'],
    default: 'Mercado'
  },
  confidence: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  volatility: {
    usd: Number,
    eur: Number,
    zar: Number,
    cad: Number
  },
  marketConditions: {
    type: String,
    enum: ['stable', 'volatile', 'trending_up', 'trending_down'],
    default: 'stable'
  }
}, {
  timestamps: true
});

// Index composto para consultas otimizadas
rateSchema.index({ date: -1, source: 1 });

// Método para calcular spread
rateSchema.methods.getSpread = function(currency) {
  const buy = this[`${currency}Buy`];
  const sell = this[`${currency}Sell`];
  return ((sell - buy) / buy * 100).toFixed(2);
};

// Método para calcular variação
rateSchema.statics.calculateVariation = async function(currency, days = 1) {
  const rates = await this.find()
    .sort({ date: -1 })
    .limit(days + 1);
  
  if (rates.length < 2) return null;
  
  const current = rates[0][`${currency}Buy`];
  const previous = rates[days][`${currency}Buy`];
  
  return {
    absolute: current - previous,
    percentage: ((current - previous) / previous * 100).toFixed(2)
  };
};

module.exports = mongoose.model("Rate", rateSchema);