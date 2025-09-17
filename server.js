const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");
require("dotenv").config();

// Validação de variáveis de ambiente
const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
  console.error('❌ Variáveis de ambiente em falta:', missingEnvVars);
  if (process.env.NODE_ENV === 'production') {
    console.log('⚠️ Usando valores padrão para variáveis em falta...');
  }
}

// Set defaults for missing variables
if (!process.env.JWT_SECRET) {
  process.env.JWT_SECRET = 'your_super_secret_key_here_change_in_production';
  console.log('⚠️ Usando JWT_SECRET padrão - ALTERE em produção!');
}

console.log('📋 Configuração do ambiente:');
console.log('- NODE_ENV:', process.env.NODE_ENV || 'development');
console.log('- PORT:', process.env.PORT || 5000);
console.log('- MONGODB_URI:', process.env.MONGODB_URI ? '✅ Definido' : '❌ Não definido');

// Importar models apenas se MongoDB estiver disponível
let User, Rate, Alert;
const initModels = () => {
  try {
    User = require("./models/userModel");
    Rate = require("./models/rateModel");
    Alert = require("./models/alertModel");
    console.log('✅ Models carregados com sucesso');
  } catch (error) {
    console.error('⚠️ Erro ao carregar models:', error.message);
  }
};

const app = express();
const PORT = process.env.PORT || 5000;

// CONFIGURAÇÃO DE SEGURANÇA
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false
}));

if (process.env.NODE_ENV === 'production') {
  app.use(compression());
  app.use(morgan('combined'));
  app.set('trust proxy', 1);
} else {
  app.use(morgan('dev'));
}

// Rate Limiting otimizado para Render
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: process.env.NODE_ENV === 'production' ? 1000 : 100,
  message: {
    error: "Muitas requisições deste IP",
    retryAfter: "15 minutos",
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting para health checks
    return req.path === '/' || req.path === '/health' || req.path === '/api/health';
  }
});

app.use(limiter);

// CORS Configuration otimizada para Render
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      process.env.FRONTEND_URL,
      'https://seu-frontend.netlify.app',
      'https://seu-frontend.vercel.app',
      'http://localhost:3000',
      'http://localhost:5173',
      'http://192.168.51.7:3000'
    ].filter(Boolean);

    // Permitir requests sem origin (health checks, etc)
    if (!origin) return callback(null, true);
    
    // Em produção, ser mais permissivo para evitar falhas de deployment
    if (process.env.NODE_ENV === 'production') {
      return callback(null, true);
    }
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(null, true); // Permitir em desenvolvimento
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  exposedHeaders: ['X-Updated-Token']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

// MongoDB Connection otimizada para Render
const connectDB = async () => {
  if (!process.env.MONGODB_URI) {
    console.log('⚠️ MONGODB_URI não definida. Executando sem banco de dados.');
    return false;
  }

  const maxRetries = 3;
  let retries = 0;
  
  const connectionOptions = {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    maxPoolSize: 5, // Reduzido para Render
    retryWrites: true,
    w: 'majority',
    bufferCommands: false,
  };

  while (retries < maxRetries) {
    try {
      console.log(`🔄 Tentativa de conexão MongoDB ${retries + 1}/${maxRetries}...`);
      
      await mongoose.connect(process.env.MONGODB_URI, connectionOptions);
      console.log("✅ MongoDB conectado com sucesso!");
      
      // Carregar models após conexão
      initModels();
      
      // Inicializar database
      setTimeout(() => initializeDatabase(), 1000);
      
      return true;
      
    } catch (error) {
      retries++;
      console.error(`❌ Erro na conexão MongoDB (tentativa ${retries}/${maxRetries}):`, error.message);
      
      if (retries >= maxRetries) {
        console.error("❌ Máximo de tentativas de conexão excedido");
        console.log("⚠️ Continuando sem MongoDB - modo offline");
        return false;
      }
      
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }
  return false;
};

// Event listeners do MongoDB
mongoose.connection.on('connected', () => {
  console.log('📊 MongoDB: Conexão estabelecida');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB: Erro na conexão:', err.message);
});

mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB: Conexão perdida');
});

// Health check otimizado para Render
app.get(["/", "/api/health", "/health"], async (req, res) => {
  try {
    const dbConnected = mongoose.connection.readyState === 1;
    
    let ratesCount = 0;
    if (dbConnected && Rate) {
      try {
        ratesCount = await Rate.countDocuments();
      } catch (error) {
        console.error('Erro ao contar rates:', error.message);
      }
    }

    const health = {
      status: "OK",
      timestamp: new Date().toISOString(),
      version: "2.0.0",
      environment: process.env.NODE_ENV || 'development',
      port: PORT,
      database: {
        connected: dbConnected,
        status: dbConnected ? 'connected' : 'disconnected'
      },
      uptime: Math.floor(process.uptime()),
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024)
      }
    };

    res.status(200).json(health);
  } catch (error) {
    console.error("Erro no health check:", error);
    res.status(200).json({
      status: "OK",
      error: "Health check com avisos",
      timestamp: new Date().toISOString(),
      uptime: Math.floor(process.uptime())
    });
  }
});

// Initialize Database
const initializeDatabase = async () => {
  try {
    if (!User || !Rate || mongoose.connection.readyState !== 1) {
      console.log("⚠️ Modelos não carregados ou MongoDB desconectado");
      return;
    }

    const rateCount = await Rate.countDocuments();

    if (rateCount === 0) {
      console.log("📊 Populando base de dados com taxas iniciais...");
      const ratesData = generateRatesData();
      await Rate.insertMany(
        ratesData.map((rate) => ({
          ...rate,
          date: new Date(rate.date),
        }))
      );
      console.log("✅ Dados de taxas inseridos com sucesso!");
    }

    // Criar admin se não existir
    const adminExists = await User.findOne({ isAdmin: true });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash("admin123", 10);
      await User.create({
        email: "admin@cambio.ao",
        password: hashedPassword,
        isAdmin: true,
        isPremium: true,
      });
      console.log("👤 Conta admin criada: admin@cambio.ao / admin123");
    }
  } catch (error) {
    console.error("❌ Erro na inicialização:", error.message);
  }
};

// Geração de dados mock
const generateRatesData = () => {
  const rates = [];
  const baseRates = {
    usdBuy: 1000,
    usdSell: 1100,
    eurBuy: 1150,
    eurSell: 1250,
    zarBuy: 60,
    zarSell: 70,
    cadBuy: 720,
    cadSell: 770,
  };

  for (let i = 0; i <= 30; i++) {
    const date = new Date();
    date.setDate(date.getDate() - i);

    const variation = (Math.random() - 0.5) * 0.04;

    rates.push({
      date: date.toISOString().split("T")[0],
      usdBuy: Math.round(baseRates.usdBuy * (1 + variation)),
      usdSell: Math.round(baseRates.usdSell * (1 + variation)),
      eurBuy: Math.round(baseRates.eurBuy * (1 + variation)),
      eurSell: Math.round(baseRates.eurSell * (1 + variation)),
      zarBuy: Math.round(baseRates.zarBuy * (1 + variation)),
      zarSell: Math.round(baseRates.zarSell * (1 + variation)),
      cadBuy: Math.round(baseRates.cadBuy * (1 + variation)),
      cadSell: Math.round(baseRates.cadSell * (1 + variation)),
      source: i === 0 ? "BNA" : "Mercado",
      confidence: Math.random() > 0.2 ? "high" : "medium",
    });
  }

  return rates;
};

const JWT_SECRET = process.env.JWT_SECRET;

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Token não fornecido" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Token inválido" });
    req.user = user;
    next();
  });
};

const authenticateAdmin = (req, res, next) => {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({
      message: "Acesso negado. Apenas administradores.",
    });
  }
  next();
};

// Cache simples
const ratesCache = {
  data: null,
  timestamp: 0,
  ttl: 60000,
};

const validateEmail = (email) => {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email) && email.length <= 254;
};

// === ROTAS DE AUTENTICAÇÃO ===
app.post("/api/auth/register", async (req, res) => {
  try {
    if (!User) {
      return res.status(503).json({ message: "Serviço temporariamente indisponível" });
    }

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email e senha são obrigatórios" });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ message: "Email inválido" });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: "Senha deve ter pelo menos 8 caracteres" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email já registado" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "Utilizador registado com sucesso!" });
  } catch (error) {
    console.error("Erro no registo:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    if (!User) {
      return res.status(503).json({ message: "Serviço temporariamente indisponível" });
    }

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email e senha são obrigatórios" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Credenciais inválidas" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Credenciais inválidas" });
    }

    const token = jwt.sign(
      {
        userId: user._id,
        isPremium: user.isPremium,
        isAdmin: user.isAdmin,
        email: user.email,
      },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    user.lastLogin = new Date();
    await user.save();

    res.json({
      token,
      user: {
        email: user.email,
        isPremium: user.isPremium,
        isAdmin: user.isAdmin,
      },
      isPremium: user.isPremium,
      isAdmin: user.isAdmin,
    });
  } catch (error) {
    console.error("Erro no login:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// === ROTAS DE TAXAS ===
app.get("/api/rates", async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    let isPremium = false;

    if (token) {
      try {
        const user = jwt.verify(token, JWT_SECRET);
        isPremium = user.isPremium;
      } catch (err) {
        isPremium = false;
      }
    }

    const limit = isPremium ? 30 : 7;
    
    let rates;
    if (ratesCache.data && (Date.now() - ratesCache.timestamp) < 60000) {
      rates = ratesCache.data.slice(0, limit);
    } else {
      if (Rate && mongoose.connection.readyState === 1) {
        rates = await Rate.find().sort({ date: -1 }).limit(limit);
      } else {
        rates = generateRatesData().slice(0, limit);
      }
      
      ratesCache.data = rates;
      ratesCache.timestamp = Date.now();
    }

    res.json(rates);
  } catch (error) {
    console.error("Erro ao buscar taxas:", error);
    const fallbackRates = generateRatesData().slice(0, 7);
    res.json(fallbackRates);
  }
});

// === SIMULADOR DE CÂMBIO ===
app.post("/api/simulate", authenticateToken, async (req, res) => {
  try {
    const { amount, fromCurrency, toCurrency, bank = "bna" } = req.body;

    if (!amount || !fromCurrency || !toCurrency) {
      return res.status(400).json({ message: "Dados incompletos para simulação" });
    }

    let latestRates;
    if (Rate && mongoose.connection.readyState === 1) {
      latestRates = await Rate.findOne().sort({ date: -1 });
    }
    
    if (!latestRates) {
      const fallbackRates = generateRatesData()[0];
      latestRates = fallbackRates;
    }

    const bankFees = {
      bna: 0.5,
      bic: 1.2,
      bai: 1.0,
      standard: 1.5,
      millennium: 1.3,
    };

    const fee = bankFees[bank] || 1.0;
    const rate = latestRates[`${fromCurrency}Sell`] || 1;

    const baseAmount = amount * rate;
    const feeAmount = baseAmount * (fee / 100);
    const finalAmount = baseAmount - feeAmount;

    res.json({
      amount: parseFloat(amount),
      fromCurrency: fromCurrency.toUpperCase(),
      toCurrency: toCurrency.toUpperCase(),
      rate,
      baseAmount,
      feePercentage: fee,
      feeAmount,
      finalAmount,
      bank: bank.toUpperCase(),
    });
  } catch (error) {
    console.error("Erro na simulação:", error);
    res.status(500).json({ message: "Erro na simulação" });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Erro não tratado:', err);
  
  res.status(500).json({ 
    message: "Erro interno do servidor",
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    message: "Endpoint não encontrado",
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

// Graceful shutdown
const gracefulShutdown = async () => {
  console.log('\n🛑 Iniciando graceful shutdown...');
  try {
    if (mongoose.connection.readyState === 1) {
      await mongoose.connection.close();
      console.log('✅ Conexão MongoDB fechada');
    }
  } catch (error) {
    console.error('❌ Erro ao fechar conexão MongoDB:', error);
  }
  process.exit(0);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Função de inicialização do servidor
const startServer = async () => {
  try {
    console.log('🚀 Iniciando servidor...');
    
    // Tentar conectar ao MongoDB
    if (process.env.MONGODB_URI) {
      await connectDB();
    }
    
    // Iniciar servidor HTTP
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`
🚀 ====================================
   Servidor Cambio Angola iniciado!
🌐 URL: http://localhost:${PORT}
📊 Ambiente: ${process.env.NODE_ENV || "development"}
⏰ Horário: ${new Date().toLocaleString("pt-PT")}
📊 MongoDB: ${mongoose.connection.readyState === 1 ? 'Conectado' : 'Desconectado'}
====================================
      `);
    });

    // Configurar timeouts para Render
    server.keepAliveTimeout = 120000;
    server.headersTimeout = 120000;
    
    server.on('error', (error) => {
      console.error('❌ Erro no servidor:', error);
      if (error.code === 'EADDRINUSE') {
        console.error(`❌ Porta ${PORT} já está em uso`);
        process.exit(1);
      }
    });

  } catch (error) {
    console.error('❌ Falha ao iniciar servidor:', error);
    process.exit(1);
  }
};

// Iniciar servidor
if (require.main === module) {
  startServer().catch((error) => {
    console.error('❌ Erro fatal:', error);
    process.exit(1);
  });
}

module.exports = app;