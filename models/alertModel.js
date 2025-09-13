// models/alertModel.js
const mongoose = require("mongoose");

const alertSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true
  },
  currency: {
    type: String,
    required: [true, "Moeda é obrigatória"],
    enum: {
      values: ['usd', 'eur', 'zar', 'cad'],
      message: "Moeda deve ser usd, eur, zar ou cad"
    }
  },
  value: {
    type: Number,
    required: [true, "Valor é obrigatório"],
    min: [1, "Valor deve ser maior que 0"]
  },
  type: {
    type: String,
    enum: ['above', 'below', 'exact'],
    default: 'above'
  },
  rateType: {
    type: String,
    enum: ['buy', 'sell'],
    default: 'buy'
  },
  isTriggered: {
    type: Boolean,
    default: false,
    index: true
  },
  dateCreated: {
    type: Date,
    default: Date.now
  },
  triggeredAt: {
    type: Date
  },
  triggeredRate: {
    type: Number
  },
  // Configurações de notificação
  notifications: {
    whatsapp: {
      type: Boolean,
      default: true
    },
    email: {
      type: Boolean,
      default: false
    },
    push: {
      type: Boolean,
      default: false
    }
  },
  // Configurações avançadas
  settings: {
    repeatAlert: {
      type: Boolean,
      default: false
    },
    repeatInterval: {
      type: Number, // em minutos
      default: 60
    },
    expiresAt: {
      type: Date
    },
    description: {
      type: String,
      maxlength: [200, "Descrição não pode exceder 200 caracteres"]
    }
  },
  // Estatísticas
  stats: {
    timesTriggered: {
      type: Number,
      default: 0
    },
    lastTriggered: {
      type: Date
    },
    averageResponseTime: {
      type: Number // em segundos
    }
  }
}, {
  timestamps: true
});

// Index composto para consultas otimizadas
alertSchema.index({ userId: 1, isTriggered: 1 });
alertSchema.index({ currency: 1, isTriggered: 1, value: 1 });

// Middleware para expirar alertas automaticamente
alertSchema.pre('save', function(next) {
  // Se não tem data de expiração e não é premium, expira em 30 dias
  if (!this.settings.expiresAt && !this.isNew) {
    const expirationDate = new Date();
    expirationDate.setDate(expirationDate.getDate() + 30);
    this.settings.expiresAt = expirationDate;
  }
  next();
});

// Método para verificar se o alerta expirou
alertSchema.methods.isExpired = function() {
  return this.settings.expiresAt && new Date() > this.settings.expiresAt;
};

// Método para formatar para display
alertSchema.methods.toDisplay = function() {
  const currencyNames = {
    usd: 'Dólar Americano',
    eur: 'Euro',
    zar: 'Rand Sul-Africano',
    cad: 'Dólar Canadense'
  };

  const typeNames = {
    above: 'acima de',
    below: 'abaixo de',
    exact: 'igual a'
  };

  return {
    id: this._id,
    currency: currencyNames[this.currency],
    currencyCode: this.currency.toUpperCase(),
    condition: `${typeNames[this.type]} ${this.value.toLocaleString()} Kz`,
    isActive: !this.isTriggered && !this.isExpired(),
    createdAt: this.dateCreated,
    triggeredAt: this.triggeredAt,
    description: this.settings.description
  };
};

// Static method para limpar alertas expirados
alertSchema.statics.cleanExpired = async function() {
  const result = await this.deleteMany({
    'settings.expiresAt': { $lt: new Date() },
    isTriggered: false
  });
  return result.deletedCount;
};

// Static method para estatísticas de alertas
alertSchema.statics.getStats = async function(userId) {
  const pipeline = [
    { $match: { userId: new mongoose.Types.ObjectId(userId) } },
    {
      $group: {
        _id: null,
        total: { $sum: 1 },
        triggered: { $sum: { $cond: ['$isTriggered', 1, 0] } },
        active: { $sum: { $cond: [{ $and: ['$isTriggered', { $eq: [false] }] }, 1, 0] } },
        byType: { $push: '$type' },
        byCurrency: { $push: '$currency' }
      }
    }
  ];

  const result = await this.aggregate(pipeline);
  return result[0] || {
    total: 0,
    triggered: 0,
    active: 0,
    byType: [],
    byCurrency: []
  };
};

module.exports = mongoose.model("Alert", alertSchema);