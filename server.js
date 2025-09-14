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
require("dotenv").config();

// Models
const User = require("./models/userModel");
const Rate = require("./models/rateModel");
const Alert = require("./models/alertModel");

const app = express();
const PORT = process.env.PORT || 5000;

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 500, // Aumentar para 500 requests por IP
  message: {
    error: "Muitas requisições deste IP",
    retryAfter: "15 minutos",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Middleware
app.use(limiter);
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      process.env.FRONTEND_URL,
      'https://seu-frontend.netlify.app',
      'https://seu-frontend.vercel.app',
      'http://localhost:3000',
      'http://localhost:5173',
    ].filter(Boolean);

    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log('CORS bloqueou origem:', origin);
      callback(new Error('Não permitido pelo CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  exposedHeaders: ['X-Updated-Token']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());

app.use((req, res, next) => {
  if (process.env.NODE_ENV !== 'production') {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    if (req.headers.origin) {
      console.log('Origin:', req.headers.origin);
    }
  }
  next();
});

const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");

// ===== 1. CONFIGURAÇÃO DE SEGURANÇA =====
if (process.env.NODE_ENV === 'production') {
  app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: false // Desabilitar temporariamente para APIs
  }));
  app.use(compression());
  app.use(morgan('combined'));
  app.set('trust proxy', 1);
} else {
  app.use(morgan('dev'));
}



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

  // Começar de 0 (hoje) até 30 dias atrás
  for (let i = 0; i <= 30; i++) {
    const date = new Date();
    date.setDate(date.getDate() - i);

    const variation = (Math.random() - 0.5) * 0.04; // Oscilação de -2% a +2%

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

// MongoDB Connection
// MongoDB Connection with better error handling and retry logic
const connectDB = async () => {
  const maxRetries = 5;
  let retries = 0;
  
  const connectionOptions = {
    serverSelectionTimeoutMS: 10000, // 10 seconds timeout
    socketTimeoutMS: 45000,
    maxPoolSize: 10,
    retryWrites: true,
    w: 'majority'
  };

  while (retries < maxRetries) {
    try {
      console.log(`🔄 Tentativa de conexão MongoDB ${retries + 1}/${maxRetries}...`);
      
      await mongoose.connect(
        process.env.MONGODB_URI || "mongodb://localhost:27017/cambio-app",
        connectionOptions
      );
      
      console.log("✅ MongoDB conectado com sucesso!");
      await initializeDatabase();
      return;
      
    } catch (error) {
      retries++;
      console.error(`❌ Erro na conexão MongoDB (tentativa ${retries}/${maxRetries}):`, error.message);
      
      if (retries >= maxRetries) {
        console.error("❌ Máximo de tentativas de conexão excedido");
        
        // Em produção, você pode querer continuar sem MongoDB ou usar fallback
        if (process.env.NODE_ENV === 'production') {
          console.log("⚠️ Servidor iniciará sem conexão MongoDB - funcionalidade limitada");
          return;
        } else {
          process.exit(1);
        }
      }
      
      // Wait before retry (exponential backoff)
      const waitTime = Math.min(1000 * Math.pow(2, retries - 1), 10000);
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
process.on('SIGINT', async () => {
  console.log('\n🛑 Recebido sinal de interrupção. Fechando servidor...');
  
  try {
    await mongoose.connection.close();
    console.log('✅ Conexão MongoDB fechada');
  } catch (error) {
    console.error('❌ Erro ao fechar conexão MongoDB:', error);
  }
  
  process.exit(0);
});

// Enhanced cron job with better error handling
cron.schedule("* * * * *", async () => {
  try {
    // Check if MongoDB is connected before proceeding
    if (mongoose.connection.readyState !== 1) {
      console.log("⚠️ MongoDB desconectado. Pulando verificação de alertas.");
      return;
    }

    const latestRates = await Rate.findOne().sort({ date: -1 });
    if (!latestRates) return;

    const pendingAlerts = await Alert.find({ isTriggered: false }).populate("userId");
    let alertsTriggered = 0;

    for (const alert of pendingAlerts) {
      if (!alert.userId) continue;

      const rateKey = `${alert.currency}${
        alert.rateType === "buy" ? "Buy" : "Sell"
      }`;
      const currentRate = latestRates[rateKey];

      if (!currentRate) continue;

      let shouldTrigger = false;
      if (alert.type === "above" && currentRate >= alert.value) {
        shouldTrigger = true;
      } else if (alert.type === "below" && currentRate <= alert.value) {
        shouldTrigger = true;
      }

      if (shouldTrigger) {
        try {
          await sendEmailNotification(alert, currentRate, alert.userId);
          alert.isTriggered = true;
          alert.triggeredAt = new Date();
          alert.triggeredRate = currentRate;
          await alert.save();
          alertsTriggered++;
        } catch (emailError) {
          console.error(`❌ Erro ao enviar alerta para ${alert.userId.email}:`, emailError.message);
        }
      }
    }

    if (alertsTriggered > 0) {
      console.log(`✅ Alertas disparados: ${alertsTriggered}`);
    }
  } catch (error) {
    console.error("❌ Erro na verificação de alertas:", error.message);
    // Don't exit the process, just log the error
  }
});

// Enhanced health check with MongoDB status
app.get(["/", "/api/health", "/health"], async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState;
    const dbConnected = dbStatus === 1;
    
    const health = {
      status: dbConnected ? "OK" : "DEGRADED",
      timestamp: new Date().toISOString(),
      version: "2.0.0",
      environment: process.env.NODE_ENV || 'development',
      url: `https://cambio-angola-backend.onrender.com`,
      database: {
        connected: dbConnected,
        status: ['disconnected', 'connected', 'connecting', 'disconnecting'][dbStatus]
      }
    };

    res.status(dbConnected ? 200 : 503).json(health);
  } catch (error) {
    res.status(503).json({
      status: "ERROR",
      error: "Health check failed",
      timestamp: new Date().toISOString()
    });
  }
});

// Initialize Database
const initializeDatabase = async () => {
  try {
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
      console.log(
        `📊 Base já contém ${rateCount} registros de taxas. Nenhuma reinserção feita.`
      );
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
  }
};

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

// === ROTAS DE AUTENTICAÇÃO ===

// Função de validação melhorada
const validateEmail = (email) => {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email) && email.length <= 254;
};

// Rota de registo:
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email e senha são obrigatórios" });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ message: "Email inválido" });
    }

    if (password.length < 8) {
      // Aumentar para 8 caracteres
      return res
        .status(400)
        .json({ message: "Senha deve ter pelo menos 8 caracteres" });
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
      return res
        .status(400)
        .json({ message: "Email e senha são obrigatórios" });
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

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // CORREÇÃO: Retornar os dados no formato esperado pelo frontend
    res.json({
      token,
      user: {
        email: user.email,
        isPremium: user.isPremium,
        isAdmin: user.isAdmin,
      },
      isPremium: user.isPremium, // Mantendo para compatibilidade
      isAdmin: user.isAdmin, // Mantendo para compatibilidade
    });
  } catch (error) {
    console.error("Erro no login:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// === ROTAS DE TAXAS ===
// No server.js, adicionar cache simples:
const ratesCache = {
  data: null,
  timestamp: 0,
  ttl: 60000, // 1 minuto
};

// server.js - Middleware para validar premium em tempo real
const validatePremiumStatus = async (req, res, next) => {
  try {
    if (!req.user || !req.user.userId) {
      return next();
    }

    // Buscar estado atual do utilizador na base de dados
    const currentUser = await User.findById(req.user.userId);
    if (!currentUser) {
      return res.status(401).json({ message: "Utilizador não encontrado" });
    }

    // Verificar se o estado premium mudou
    if (req.user.isPremium !== currentUser.isPremium) {
      // Gerar novo token com estado atualizado
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

      // Enviar novo token no header da resposta
      res.setHeader('X-Updated-Token', newToken);
      
      // Atualizar req.user para a requisição atual
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

// server.js - Endpoint de taxas com validação rigorosa
app.get("/api/rates", validatePremiumStatus, async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    let isPremium = false;

    if (token) {
      try {
        const user = jwt.verify(token, JWT_SECRET);
        
        // VALIDAÇÃO DUPLA: Verificar na base de dados também
        const dbUser = await User.findById(user.userId);
        isPremium = dbUser ? dbUser.isPremium : false;
        
        // Se houver discrepância, usar dados da base
        if (user.isPremium !== isPremium) {
          console.log(`⚠️ Discrepância detectada para ${user.email}: Token=${user.isPremium}, DB=${isPremium}`);
        }
      } catch (err) {
        isPremium = false;
      }
    }

    // Cache com chave diferente para premium/básico
    const cacheKey = isPremium ? 'rates_premium' : 'rates_basic';
    const limit = isPremium ? 30 : 7;
    
    let rates;
    if (ratesCache[cacheKey] && (Date.now() - ratesCache[cacheKey].timestamp) < 60000) {
      rates = ratesCache[cacheKey].data;
    } else {
      rates = await Rate.find().sort({ date: -1 }).limit(limit);
      ratesCache[cacheKey] = {
        data: rates,
        timestamp: Date.now()
      };
    }

    res.json(rates);
  } catch (error) {
    console.error("Erro ao buscar taxas:", error);
    res.status(500).json({ message: "Erro ao carregar taxas" });
  }
});

// Nova rota para estatísticas
app.get("/api/rates/stats", authenticateToken, async (req, res) => {
  try {
    const rates = await Rate.find().sort({ date: -1 }).limit(30);

    if (rates.length < 2) {
      return res.json({ message: "Dados insuficientes para estatísticas" });
    }

    const latest = rates[0];
    const previous = rates[1];

    const currencies = ["usd", "eur", "zar", "cad"];
    const stats = {};

    currencies.forEach((currency) => {
      const buyField = `${currency}Buy`;
      const sellField = `${currency}Sell`;

      const buyChange =
        ((latest[buyField] - previous[buyField]) / previous[buyField]) * 100;
      const sellChange =
        ((latest[sellField] - previous[sellField]) / previous[sellField]) * 100;

      stats[currency] = {
        buyChange: buyChange.toFixed(2),
        sellChange: sellChange.toFixed(2),
        trend: buyChange > 0 ? "up" : buyChange < 0 ? "down" : "stable",
      };
    });

    res.json(stats);
  } catch (error) {
    console.error("Erro ao calcular estatísticas:", error);
    res.status(500).json({ message: "Erro ao calcular estatísticas" });
  }
});

// Adicione este endpoint temporário para criar/verificar admin
app.post("/api/admin/create", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: "Email e senha obrigatórios" });
    }

    // Verifica se já existe
    const existingAdmin = await User.findOne({ email });
    if (existingAdmin) {
      return res.json({ 
        message: "Admin já existe", 
        email: existingAdmin.email,
        isPremium: existingAdmin.isPremium,
        isAdmin: existingAdmin.isAdmin
      });
    }

    // Cria novo admin
    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new User({
      email,
      password: hashedPassword,
      isAdmin: true,
      isPremium: true,
      dateCreated: new Date()
    });

    await newAdmin.save();
    
    console.log("✅ Novo admin criado:", email);
    
    res.status(201).json({
      message: "Admin criado com sucesso",
      email: newAdmin.email,
      isAdmin: newAdmin.isAdmin,
      isPremium: newAdmin.isPremium
    });

  } catch (error) {
    console.error("Erro ao criar admin:", error);
    res.status(500).json({ message: "Erro interno" });
  }
});

// Endpoint para listar todos os utilizadores (debug)
app.get("/api/debug/users", async (req, res) => {
  try {
    const users = await User.find().select("-password");
    res.json({
      total: users.length,
      users: users.map(u => ({
        email: u.email,
        isAdmin: u.isAdmin,
        isPremium: u.isPremium,
        dateCreated: u.dateCreated
      }))
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// === ROTAS DO UTILIZADOR ===
app.post("/api/user/phone", authenticateToken, async (req, res) => {
  try {
    const { phoneNumber } = req.body;

    if (!phoneNumber) {
      return res
        .status(400)
        .json({ message: "Número de telefone é obrigatório" });
    } // Busca o utilizador pelo ID do token JWT

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: "Utilizador não encontrado" });
    } // Atualiza o campo phoneNumber

    user.phoneNumber = phoneNumber;
    await user.save();

    res.json({ message: "Número de telefone atualizado com sucesso!" });
  } catch (error) {
    console.error("Erro ao atualizar o número de telefone:", error);
    res.status(500).json({ message: "Erro ao atualizar o número de telefone" });
  }
});

// === ROTAS DE ALERTAS ===
app.post("/api/alerts", authenticateToken, async (req, res) => {
  try {
    // Adicione 'rateType' à desestruturação para capturá-lo do corpo da requisição
    const { currency, value, type = "above", rateType = "buy" } = req.body;

    if (!currency || !value) {
      return res
        .status(400)
        .json({ message: "Moeda e valor são obrigatórios" });
    }

    if (!req.user.isPremium) {
      const alertCount = await Alert.countDocuments({
        userId: req.user.userId,
        isTriggered: false,
      });

      if (alertCount >= 1) {
        return res.status(403).json({
          message:
            "Utilizadores básicos podem ter apenas 1 alerta ativo. Upgrade para Premium para alertas ilimitados.",
        });
      }
    }

    const newAlert = new Alert({
      currency,
      value: parseFloat(value),
      type,
      rateType, // Adicione o rateType ao objeto do novo alerta
      userId: req.user.userId,
    });

    await newAlert.save();
    res.status(201).json({
      message: "Alerta criado com sucesso!",
      alert: newAlert,
    });
  } catch (error) {
    console.error("Erro ao criar alerta:", error);
    res.status(500).json({ message: "Erro ao criar alerta" });
  }
});

app.get("/api/alerts", authenticateToken, async (req, res) => {
  try {
    const alerts = await Alert.find({ userId: req.user.userId }).sort({
      dateCreated: -1,
    });
    res.json(alerts);
  } catch (error) {
    console.error("Erro ao buscar alertas:", error);
    res.status(500).json({ message: "Erro ao buscar alertas" });
  }
});

app.delete("/api/alerts/:id", authenticateToken, async (req, res) => {
  try {
    const alert = await Alert.findOne({
      _id: req.params.id,
      userId: req.user.userId,
    });

    if (!alert) {
      return res.status(404).json({ message: "Alerta não encontrado" });
    }

    await Alert.deleteOne({ _id: req.params.id });
    res.json({ message: "Alerta removido com sucesso" });
  } catch (error) {
    console.error("Erro ao remover alerta:", error);
    res.status(500).json({ message: "Erro ao remover alerta" });
  }
});

// === SIMULADOR DE CÂMBIO ===
app.post("/api/simulate", authenticateToken, async (req, res) => {
  try {
    const { amount, fromCurrency, toCurrency, bank = "bna" } = req.body;

    if (!amount || !fromCurrency || !toCurrency) {
      return res
        .status(400)
        .json({ message: "Dados incompletos para simulação" });
    }

    const latestRates = await Rate.findOne().sort({ date: -1 });
    if (!latestRates) {
      return res.status(500).json({ message: "Taxas não disponíveis" });
    } // Comissões por banco (%)

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

// === ROTA DE EXPORTAÇÃO DE DADOS ===
const ExcelJS = require("exceljs");

app.post("/api/export-rates", authenticateToken, async (req, res) => {
  try {
    // Apenas usuários premium e admins podem exportar todos os dados
    if (!req.user.isPremium && !req.user.isAdmin) {
      return res
        .status(403)
        .json({ message: "Funcionalidade exclusiva para usuários Premium." });
    }

    const rates = await Rate.find().sort({ date: 1 });
    if (!rates || rates.length === 0) {
      return res
        .status(404)
        .json({ message: "Nenhum dado de taxas para exportar." });
    }

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet("Taxas de Câmbio"); // Headers

    worksheet.columns = [
      { header: "Data", key: "date", width: 15 },
      { header: "USD Compra", key: "usdBuy", width: 15 },
      { header: "USD Venda", key: "usdSell", width: 15 },
      { header: "EUR Compra", key: "eurBuy", width: 15 },
      { header: "EUR Venda", key: "eurSell", width: 15 },
      { header: "ZAR Compra", key: "zarBuy", width: 15 },
      { header: "ZAR Venda", key: "zarSell", width: 15 },
      { header: "CAD Compra", key: "cadBuy", width: 15 },
      { header: "CAD Venda", key: "cadSell", width: 15 },
    ]; // Rows

    rates.forEach((rate) => {
      worksheet.addRow({
        date: rate.date.toLocaleDateString("pt-AO"),
        usdBuy: rate.usdBuy,
        usdSell: rate.usdSell,
        eurBuy: rate.eurBuy,
        eurSell: rate.eurSell,
        zarBuy: rate.zarBuy,
        zarSell: rate.zarSell,
        cadBuy: rate.cadBuy,
        cadSell: rate.cadSell,
      });
    });

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=" + "taxas_de_cambio.xlsx"
    );

    await workbook.xlsx.write(res);
    res.end();

    console.log("✅ Exportação de dados concluída com sucesso.");
  } catch (error) {
    console.error("❌ Erro na exportação de dados:", error);
    res.status(500).json({ message: "Erro ao exportar dados." });
  }
});

// server.js - Novo endpoint para forçar validação
app.post("/api/auth/validate", authenticateToken, async (req, res) => {
  try {
    const currentUser = await User.findById(req.user.userId);
    if (!currentUser) {
      return res.status(404).json({ message: "Utilizador não encontrado" });
    }

    // Sempre gerar token atualizado
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

    res.json({
      token: newToken,
      user: {
        id: currentUser._id,
        email: currentUser.email,
        isPremium: currentUser.isPremium,
        isAdmin: currentUser.isAdmin,
      },
      message: "Sessão validada com sucesso"
    });
  } catch (error) {
    console.error("Erro na validação:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// === ROTAS ADMIN ===
app.get(
  "/api/admin/dashboard",
  authenticateToken,
  authenticateAdmin,
  async (req, res) => {
    try {
      const totalUsers = await User.countDocuments();
      const premiumUsers = await User.countDocuments({ isPremium: true });
      const totalAlerts = await Alert.countDocuments();
      const activeAlerts = await Alert.countDocuments({ isTriggered: false }); // Usuários registados nos últimos 30 dias

      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      const recentUsers = await User.countDocuments({
        dateCreated: { $gte: thirtyDaysAgo },
      });

      res.json({
        totalUsers,
        premiumUsers,
        totalAlerts,
        activeAlerts,
        recentUsers,
        conversionRate:
          totalUsers > 0 ? ((premiumUsers / totalUsers) * 100).toFixed(2) : 0,
      });
    } catch (error) {
      console.error("Erro no dashboard admin:", error);
      res.status(500).json({ message: "Erro ao carregar dashboard" });
    }
  }
);

app.get(
  "/api/admin/users",
  authenticateToken,
  authenticateAdmin,
  async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 10;
      const skip = (page - 1) * limit;

      const users = await User.find()
        .select("-password")
        .sort({ dateCreated: -1 })
        .skip(skip)
        .limit(limit);

      const total = await User.countDocuments();

      res.json({
        users,
        pagination: {
          current: page,
          total: Math.ceil(total / limit),
          hasNext: skip + limit < total,
          hasPrev: page > 1,
        },
      });
    } catch (error) {
      console.error("Erro ao listar utilizadores:", error);
      res.status(500).json({ message: "Erro ao listar utilizadores" });
    }
  }
);

// Na rota /api/admin/upgrade-to-premium, após user.save():
app.post(
  "/api/admin/upgrade-to-premium",
  authenticateToken,
  authenticateAdmin,
  async (req, res) => {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ message: "Email é obrigatório" });
      }

      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: "Utilizador não encontrado" });
      }

      if (user.isPremium) {
        return res.status(400).json({ message: "Utilizador já é Premium" });
      }

      // Atualiza para Premium
      user.isPremium = true;
      user.premiumUpgradeDate = new Date();
      user.premiumExpiryDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      await user.save();

      // CORREÇÃO: Gera token atualizado
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

      res.json({
        message: `Utilizador ${email} foi promovido a Premium com sucesso`,
        token, // Token atualizado
        user: {
          email: user.email,
          isPremium: user.isPremium,
          isAdmin: user.isAdmin,
        },
      });
    } catch (error) {
      console.error("Erro ao promover utilizador:", error);
      res.status(500).json({ message: "Erro ao promover utilizador" });
    }
  }
);

app.post(
  "/api/admin/update-rates",
  authenticateToken,
  authenticateAdmin,
  async (req, res) => {
    try {
      const {
        usdBuy,
        usdSell,
        eurBuy,
        eurSell,
        zarBuy,
        zarSell,
        cadBuy,
        cadSell,
      } = req.body; // Validação

      const requiredFields = {
        usdBuy,
        usdSell,
        eurBuy,
        eurSell,
        zarBuy,
        zarSell,
        cadBuy,
        cadSell,
      };
      for (const [field, value] of Object.entries(requiredFields)) {
        if (!value || isNaN(value)) {
          return res.status(400).json({
            message: `Campo ${field} é obrigatório e deve ser numérico`,
          });
        }
      }

      const newRate = new Rate({
        date: new Date(),
        usdBuy: parseFloat(usdBuy),
        usdSell: parseFloat(usdSell),
        eurBuy: parseFloat(eurBuy),
        eurSell: parseFloat(eurSell),
        zarBuy: parseFloat(zarBuy),
        zarSell: parseFloat(zarSell),
        cadBuy: parseFloat(cadBuy),
        cadSell: parseFloat(cadSell),
        source: "Admin",
        confidence: "high",
      });

      await newRate.save();
      console.log("📈 Taxas atualizadas pelo admin:", req.user.email);

      res.status(201).json({ message: "Taxas atualizadas com sucesso!" });
    } catch (error) {
      console.error("Erro ao atualizar taxas:", error);
      res.status(500).json({ message: "Erro ao atualizar taxas" });
    }
  }
);

// === SISTEMA DE ALERTAS AUTOMATIZADO ===
const sendEmailNotification = async (alert, currentRate, user) => {
  if (!user.email) {
    console.log(`⚠️ Alerta para utilizador sem email não enviado: ${user._id}`);
    return;
  }

  const currencyNames = {
    usd: "Dólar Americano",
    eur: "Euro",
    zar: "Rand Sul-Africano",
    cad: "Dólar Canadense",
  }; // Configurar o 'transporter' para o envio do email // Por segurança, use variáveis de ambiente para o seu email e senha

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER, // Exemplo: seu-email@gmail.com
      pass: process.env.GMAIL_PASS, // Senha de aplicação gerada pelo Google
    },
  });

  const mailOptions = {
    from: process.env.GMAIL_USER,
    to: user.email,
    subject: `🔔 Alerta de Preço - ${alert.currency.toUpperCase()}`,
    html: `
<h3>Olá, ${user.email}!</h3>
<p>A taxa de câmbio para <strong>${
      currencyNames[alert.currency]
    }</strong> atingiu o teu valor-alvo!</p>
<p><strong>Valor-Alvo:</strong> ${alert.value.toLocaleString()} Kz</p>
<p><strong>Taxa Atual:</strong> ${currentRate.toLocaleString()} Kz</p>
<br/>
<p>Não percas esta oportunidade! Acessa o nosso site para mais detalhes.</p>
<br/>
<small>Esta é uma notificação automática do Cambio Angola.</small>
`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`✅ Alerta de email enviado com sucesso para ${user.email}`);
  } catch (error) {
    console.error(`❌ Falha ao enviar email para ${user.email}:`, error);
  }
};

const sendEmailNotificationPremiumExpired = async (user) => {
  if (!user.email) return;

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.GMAIL_USER,
    to: user.email,
    subject: "⚠️ Plano Premium expirado",
    html: `
      <h3>Olá, ${user.email}!</h3>
      <p>O teu plano Premium expirou e a tua conta voltou para o estado básico.</p>
      <p>Renova o teu plano para continuares a usufruir de todos os benefícios.</p>
      <br/>
      <small>Esta é uma notificação automática do Cambio Angola.</small>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`✅ Email de expiração enviado para ${user.email}`);
  } catch (error) {
    console.error(
      `❌ Falha ao enviar email de expiração para ${user.email}:`,
      error
    );
  }
};

const removeExpiredPremiums = async () => {
  try {
    const now = new Date();
    // Busca todos os usuários premium cujo premiumExpiryDate já passou
    const expiredUsers = await User.find({
      isPremium: true,
      premiumExpiryDate: { $lte: now },
    });

    if (expiredUsers.length === 0) {
      console.log("✅ Nenhum usuário Premium expirado encontrado hoje.");
      return;
    }

    for (const user of expiredUsers) {
      user.isPremium = false;
      user.premiumUpgradeDate = null;
      user.premiumExpiryDate = null;
      await user.save();

      console.log(`⚠️ Usuário ${user.email} rebaixado de Premium.`);

      // Envia notificação por email
      await sendEmailNotificationPremiumExpired(user);
    }
  } catch (error) {
    console.error("❌ Erro ao remover usuários Premium expirados:", error);
  }
};

// Rebaixar usuário de Premium manualmente
app.post(
  "/api/admin/remove-premium",
  authenticateToken,
  authenticateAdmin,
  async (req, res) => {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ message: "Email é obrigatório" });
      }

      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: "Utilizador não encontrado" });
      }

      if (!user.isPremium) {
        return res.status(400).json({ message: "Utilizador já não é Premium" });
      }

      user.isPremium = false;
      user.premiumUpgradeDate = null;
      user.premiumExpiryDate = null;
      await user.save();

      // Envia email de notificação
      await sendEmailNotificationPremiumExpired(user);

      res.json({
        message: `Utilizador ${email} foi rebaixado de Premium com sucesso`,
        user: {
          email: user.email,
          isPremium: user.isPremium,
          isAdmin: user.isAdmin,
        },
      });
    } catch (error) {
      console.error("Erro ao rebaixar usuário de Premium:", error);
      res.status(500).json({ message: "Erro ao rebaixar usuário de Premium" });
    }
  }
);

// No server.js, adicionar middleware de validação:
const validateRequestBody = (schema) => {
  return (req, res, next) => {
    const errors = [];

    for (const [field, rules] of Object.entries(schema)) {
      const value = req.body[field];

      if (rules.required && (!value || value.toString().trim() === "")) {
        errors.push(`${field} é obrigatório`);
        continue;
      }

      if (value && rules.type === "number") {
        const num = parseFloat(value);
        if (
          isNaN(num) ||
          (rules.min && num < rules.min) ||
          (rules.max && num > rules.max)
        ) {
          errors.push(`${field} deve ser um número válido`);
        }
      }

      if (
        value &&
        rules.type === "string" &&
        rules.maxLength &&
        value.length > rules.maxLength
      ) {
        errors.push(`${field} excede o limite de caracteres`);
      }
    }

    if (errors.length > 0) {
      return res.status(400).json({ message: errors[0], errors });
    }

    next();
  };
};

// Usar nas rotas:
app.post(
  "/api/alerts",
  authenticateToken,
  validateRequestBody({
    currency: { required: true, type: "string" },
    value: { required: true, type: "number", min: 0 },
    rateType: { required: true, type: "string" },
  }),
  async (req, res) => {
    // ... resto do código
  }
);

// Executa todos os dias às 00:00
cron.schedule("0 0 * * *", async () => {
  console.log("⏰ Verificando usuários com Premium expirado...");
  await removeExpiredPremiums();
});

// Substitui o cron job de alertas por uma versão mais limpa:
cron.schedule("* * * * *", async () => {
  try {
    const latestRates = await Rate.findOne().sort({ date: -1 });
    if (!latestRates) return;

    const pendingAlerts = await Alert.find({ isTriggered: false }).populate(
      "userId"
    );
    let alertsTriggered = 0;

    for (const alert of pendingAlerts) {
      if (!alert.userId) continue;

      const rateKey = `${alert.currency}${
        alert.rateType === "buy" ? "Buy" : "Sell"
      }`;
      const currentRate = latestRates[rateKey];

      if (!currentRate) continue;

      let shouldTrigger = false;
      if (alert.type === "above" && currentRate >= alert.value) {
        shouldTrigger = true;
      } else if (alert.type === "below" && currentRate <= alert.value) {
        shouldTrigger = true;
      }

      if (shouldTrigger) {
        await sendEmailNotification(alert, currentRate, alert.userId);
        alert.isTriggered = true;
        alert.triggeredAt = new Date();
        alert.triggeredRate = currentRate;
        await alert.save();
        alertsTriggered++;
      }
    }

    // Só faz log se houver alertas disparados
    if (alertsTriggered > 0) {
      console.log(`Alertas disparados: ${alertsTriggered}`);
    }
  } catch (error) {
    console.error("Erro na verificação de alertas:", error);
  }
});

// Cron job para gerar novas taxas todos os dias às 9h da manhã
cron.schedule("0 9 * * *", async () => {
  try {
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

    const variation = (Math.random() - 0.5) * 0.04; // -2% a +2%

    const newRate = new Rate({
      date: new Date(),
      usdBuy: Math.round(baseRates.usdBuy * (1 + variation)),
      usdSell: Math.round(baseRates.usdSell * (1 + variation)),
      eurBuy: Math.round(baseRates.eurBuy * (1 + variation)),
      eurSell: Math.round(baseRates.eurSell * (1 + variation)),
      zarBuy: Math.round(baseRates.zarBuy * (1 + variation)),
      zarSell: Math.round(baseRates.zarSell * (1 + variation)),
      cadBuy: Math.round(baseRates.cadBuy * (1 + variation)),
      cadSell: Math.round(baseRates.cadSell * (1 + variation)),
      source: "CronJob",
      confidence: "high",
    });

    await newRate.save();
    console.log("📈 Nova taxa diária inserida:", newRate.date);
  } catch (error) {
    console.error("❌ Erro ao inserir nova taxa diária:", error);
  }
});

// Health check
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
      status: dbConnected ? "OK" : "ERROR", 
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
      uptime: Math.floor(process.uptime())
    };

    const statusCode = health.status === "OK" ? 200 : 503;
    res.status(statusCode).json(health);
  } catch (error) {
    console.error("Erro no health check:", error);
    res.status(503).json({
      status: "ERROR",
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Erro não tratado:', err);
  
  // Não expor detalhes do erro em produção
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

// 404 handler melhorado
app.use((req, res) => {
  console.log(`404 - Endpoint não encontrado: ${req.method} ${req.path}`);
  res.status(404).json({ 
    message: "Endpoint não encontrado",
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

// Rate limiting específico por utilizador autenticado:
const createUserRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  max: 30, // 30 requests por minuto por utilizador
  keyGenerator: (req) => req.user?.userId || req.ip,
  message: { error: "Muitas requisições. Tente novamente em 1 minuto." },
});

// Aplicar em rotas específicas:
app.use("/api/alerts", createUserRateLimit);
app.use("/api/simulate", createUserRateLimit);




// Aplicar middleware nas rotas que precisam de validação premium
app.use("/api/rates", validatePremiumStatus);
app.use("/api/alerts", validatePremiumStatus);
app.use("/api/export-rates", validatePremiumStatus);

// Iniciar servidor
const startServer = async () => {
  await connectDB();

  app.listen(PORT, () => {
    console.log(`
🚀 ====================================
   Servidor Cambio Angola iniciado!
🌐 URL: http://localhost:${PORT}
📊 Ambiente: ${process.env.NODE_ENV || "development"}
⏰ Horário: ${new Date().toLocaleString("pt-PT")}
====================================
    `);
  });
};

startServer().catch(console.error);
