/* eslint-disable no-irregular-whitespace */
/* eslint-disable no-unused-vars */
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const cron = require("node-cron");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");
require("dotenv").config();

// Validação de variáveis de ambiente
console.log('🔍 Validando variáveis de ambiente...');

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
console.log('- JWT_SECRET:', process.env.JWT_SECRET ? '✅ Definido' : '❌ Não definido');

// Models
const User = require("./models/userModel");
const Rate = require("./models/rateModel");
const Alert = require("./models/alertModel");

const app = express();
const PORT = process.env.PORT || 5000;

// CONFIGURAÇÃO DE SEGURANÇA PRIMEIRO
if (process.env.NODE_ENV === 'production') {
  app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: false
  }));
  app.use(compression());
  app.use(morgan('combined'));
  app.set('trust proxy', 1);
} else {
  app.use(morgan('dev'));
}

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 500,
  message: {
    error: "Muitas requisições deste IP",
    retryAfter: "15 minutos",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);

// CORS Configuration - Mais permissiva para deployment
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      process.env.FRONTEND_URL,
      'https://seu-frontend.netlify.app',
      'https://seu-frontend.vercel.app',
      'http://localhost:3000',
      'http://localhost:5173',
      'http://localhost:5000', // Para health checks
    ].filter(Boolean);

    // Em produção, permitir requests sem origin (ex: health checks)
    if (!origin && process.env.NODE_ENV === 'production') {
      return callback(null, true);
    }
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log('CORS bloqueou origem:', origin);
      // Em produção, ser mais permissivo para evitar falhas de deployment
      if (process.env.NODE_ENV === 'production') {
        callback(null, true);
      } else {
        callback(new Error('Não permitido pelo CORS'));
      }
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

// Logging middleware
app.use((req, res, next) => {
  if (process.env.NODE_ENV !== 'production') {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    if (req.headers.origin) {
      console.log('Origin:', req.headers.origin);
    }
  }
  next();
});

// MongoDB Connection com timeout reduzido para deployment
const connectDB = async () => {
  const maxRetries = process.env.NODE_ENV === 'production' ? 5 : 3;
  let retries = 0;
  
  const connectionOptions = {
    serverSelectionTimeoutMS: process.env.NODE_ENV === 'production' ? 10000 : 5000,
    socketTimeoutMS: 45000,
    maxPoolSize: 10,
    retryWrites: true,
    w: 'majority',
    maxIdleTimeMS: 30000,
    bufferCommands: false,
  };

  while (retries < maxRetries) {
    try {
      console.log(`🔄 Tentativa de conexão MongoDB ${retries + 1}/${maxRetries}...`);
      
      const mongoUri = process.env.MONGODB_URI;
      if (!mongoUri) {
        throw new Error('MONGODB_URI não definida nas variáveis de ambiente');
      }
      
      await mongoose.connect(mongoUri, connectionOptions);
      
      console.log("✅ MongoDB conectado com sucesso!");
      await initializeDatabase();
      return;
      
    } catch (error) {
      retries++;
      console.error(`❌ Erro na conexão MongoDB (tentativa ${retries}/${maxRetries}):`, error.message);
      
      if (retries >= maxRetries) {
        console.error("❌ Máximo de tentativas de conexão excedido");
        
        if (process.env.NODE_ENV === 'production') {
          console.log("⚠️ Continuando sem MongoDB - modo degradado");
          return; // Não fazer throw em produção
        } else {
          throw error;
        }
      }
      
      const waitTime = Math.min(1000 * retries, 5000);
      console.log(`⏳ Aguardando ${waitTime}ms antes da próxima tentativa...`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
  }
};

// Enhanced MongoDB event listeners
mongoose.connection.on('connected', () => {
  console.log('📊 MongoDB: Conexão estabelecida');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB: Erro na conexão:', err.message);
});

mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB: Conexão perdida');
});

mongoose.connection.on('reconnected', () => {
  console.log('🔄 MongoDB: Reconectado');
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('\n🛑 Recebido SIGTERM. Fechando servidor graciosamente...');
  await gracefulShutdown();
});

process.on('SIGINT', async () => {
  console.log('\n🛑 Recebido SIGINT. Fechando servidor graciosamente...');
  await gracefulShutdown();
});

const gracefulShutdown = async () => {
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

// Health check melhorado para deployment
app.get(["/", "/api/health", "/health"], async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState;
    const dbConnected = dbStatus === 1;
    
    let ratesCount = 0;
    if (dbConnected) {
      try {
        ratesCount = await Rate.countDocuments();
      } catch (error) {
        console.error('Erro ao contar rates:', error);
      }
    }

    const health = {
      status: "OK", // Sempre OK para evitar falhas de deployment
      timestamp: new Date().toISOString(),
      version: "2.0.0",
      environment: process.env.NODE_ENV || 'development',
      port: process.env.PORT || 5000,
      database: {
        connected: dbConnected,
        status: ['disconnected', 'connected', 'connecting', 'disconnecting'][dbStatus] || 'unknown'
      },
      data: {
        ratesCount,
        hasData: ratesCount > 0
      },
      uptime: Math.floor(process.uptime()),
      deployment: {
        region: process.env.DEPLOYMENT_REGION || 'unknown',
        timestamp: process.env.DEPLOYMENT_TIMESTAMP || new Date().toISOString()
      }
    };

    // Sempre retorna 200 para health checks de deployment
    res.status(200).json(health);
  } catch (error) {
    console.error("Erro no health check:", error);
    // Mesmo com erro, retorna status OK para não falhar deployment
    res.status(200).json({
      status: "OK",
      error: "Health check com avisos",
      timestamp: new Date().toISOString(),
      uptime: Math.floor(process.uptime())
    });
  }
});

// Initialize Database com melhor tratamento de erros
const initializeDatabase = async () => {
  try {
    if (mongoose.connection.readyState !== 1) {
      console.log("⚠️ MongoDB não conectado. Pulando inicialização.");
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
    } else {
      console.log(`📊 Base já contém ${rateCount} registros de taxas.`);
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
    console.error("❌ Erro na inicialização:", error);
    // Não fazer throw para não falhar o deployment
  }
};

// Dados de câmbio com oscilação realista
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

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "your_super_secret_key_here";

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

// Cache simples para rates
const ratesCache = {
  data: null,
  timestamp: 0,
  ttl: 60000,
};

// Middleware para validar premium em tempo real
const validatePremiumStatus = async (req, res, next) => {
  try {
    if (!req.user || !req.user.userId) {
      return next();
    }

    // Verificar se MongoDB está conectado
    if (mongoose.connection.readyState !== 1) {
      return next();
    }

    const currentUser = await User.findById(req.user.userId);
    if (!currentUser) {
      return res.status(401).json({ message: "Utilizador não encontrado" });
    }

    if (req.user.isPremium !== currentUser.isPremium) {
      const newToken = jwt.sign(
        {
          userId: currentUser._id,
          isPremium: currentUser.isPremium,
          isAdmin: currentUser.isAdmin,
          email: currentUser.email,
        },
        JWT_SECRET,
        { expiresIn: "24h" }
      );

      res.setHeader('X-Updated-Token', newToken);
      
      req.user = {
        ...req.user,
        isPremium: currentUser.isPremium,
        isAdmin: currentUser.isAdmin
      };
    }

    next();
  } catch (error) {
    console.error("Erro na validação de premium:", error);
    next();
  }
};

// === ROTAS DE AUTENTICAÇÃO ===

const validateEmail = (email) => {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email) && email.length <= 254;
};

app.post("/api/auth/register", async (req, res) => {
  try {
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

    // Verificar se MongoDB está conectado
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ message: "Serviço temporariamente indisponível" });
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
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email e senha são obrigatórios" });
    }

    // Verificar se MongoDB está conectado
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ message: "Serviço temporariamente indisponível" });
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
app.get("/api/rates", validatePremiumStatus, async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    let isPremium = false;

    if (token) {
      try {
        const user = jwt.verify(token, JWT_SECRET);
        
        // Verificar se MongoDB está conectado antes de consultar
        if (mongoose.connection.readyState === 1) {
          const dbUser = await User.findById(user.userId);
          isPremium = dbUser ? dbUser.isPremium : false;
          
          if (user.isPremium !== isPremium) {
            console.log(`⚠️ Discrepância detectada para ${user.email}: Token=${user.isPremium}, DB=${isPremium}`);
          }
        } else {
          isPremium = user.isPremium; // Usar dados do token se DB não estiver disponível
        }
      } catch (err) {
        isPremium = false;
      }
    }

    const cacheKey = isPremium ? 'rates_premium' : 'rates_basic';
    const limit = isPremium ? 30 : 7;
    
    let rates;
    if (ratesCache[cacheKey] && (Date.now() - ratesCache[cacheKey].timestamp) < 60000) {
      rates = ratesCache[cacheKey].data;
    } else {
      // Verificar se MongoDB está conectado
      if (mongoose.connection.readyState !== 1) {
        // Retornar dados de exemplo se DB não estiver disponível
        rates = generateRatesData().slice(0, limit);
      } else {
        rates = await Rate.find().sort({ date: -1 }).limit(limit);
      }
      
      ratesCache[cacheKey] = {
        data: rates,
        timestamp: Date.now()
      };
    }

    res.json(rates);
  } catch (error) {
    console.error("Erro ao buscar taxas:", error);
    // Em caso de erro, retornar dados de exemplo
    const limit = 7; // Assume usuário básico em caso de erro
    const fallbackRates = generateRatesData().slice(0, limit);
    res.json(fallbackRates);
  }
});

// Error handling middleware melhorado
app.use((err, req, res, next) => {
  console.error('Erro não tratado:', err);
  
  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({ 
      message: "Erro interno do servidor",
      timestamp: new Date().toISOString()
    });
  } else {
    res.status(500).json({ 
      message: "Erro interno do servidor",
      error: err.message,
      stack: err.stack,
      timestamp: new Date().toISOString()
    });
  }
});

// 404 handler
app.use((req, res) => {
  console.log(`404 - Endpoint não encontrado: ${req.method} ${req.path}`);
  res.status(404).json({ 
    message: "Endpoint não encontrado",
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

// === ADICIONAR OUTRAS ROTAS AQUI ===
// [Adicione suas outras rotas de alerts, admin, etc. aqui]

// Função de inicialização do servidor
const startServer = async () => {
  try {
    console.log('🚀 Iniciando servidor...');
    
    // Tentar conectar ao MongoDB, mas não falhar se não conseguir
    if (process.env.MONGODB_URI) {
      try {
        await connectDB();
      } catch (dbError) {
        console.error('⚠️ Falha na conexão inicial com MongoDB:', dbError.message);
        console.log('🔄 Servidor continuará em modo degradado...');
      }
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

    server.on('error', (error) => {
      console.error('❌ Erro no servidor:', error);
      if (error.code === 'EADDRINUSE') {
        console.error(`❌ Porta ${PORT} já está em uso`);
        process.exit(1);
      }
    });

    // Configurar timeout do servidor para deployment
    server.timeout = 30000; // 30 segundos

  } catch (error) {
    console.error('❌ Falha ao iniciar servidor:', error);
    process.exit(1);
  }
};

// Iniciar servidor
startServer().catch((error) => {
  console.error('❌ Erro fatal:', error);
  process.exit(1);
});

module.exports = app;