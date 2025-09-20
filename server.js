const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");
const cron = require("node-cron");
const nodemailer = require("nodemailer");
const ExcelJS = require("exceljs");
const { OAuth2Client } = require("google-auth-library");
require("dotenv").config();

// Após as importações, adicione:
const logger = {
  info: (message, meta) => console.log(`ℹ️  ${message}`, meta?.details || ''),
  error: (message, meta) => console.error(`❌ ${message}`, meta?.details || ''),
  warn: (message, meta) => console.warn(`⚠️  ${message}`, meta?.details || ''),
  debug: (message, meta) => console.log(`🔍 ${message}`, meta?.details || '')
};

// Validação de variáveis de ambiente
const requiredEnvVars = ["MONGODB_URI", "JWT_SECRET"];
const missingEnvVars = requiredEnvVars.filter(
  (varName) => !process.env[varName]
);

if (missingEnvVars.length > 0) {
  console.error("❌ Variáveis de ambiente em falta:", missingEnvVars);
  if (process.env.NODE_ENV === "production") {
    console.log("⚠️ Usando valores padrão para variáveis em falta...");
  }
}

// Set defaults for missing variables
if (!process.env.JWT_SECRET) {
  process.env.JWT_SECRET = "your_super_secret_key_here_change_in_production";
  console.log("⚠️ Usando JWT_SECRET padrão - ALTERE em produção!");
}

console.log("📋 Configuração do ambiente:");
console.log("- NODE_ENV:", process.env.NODE_ENV || "development");
console.log("- PORT:", process.env.PORT || 5000);
console.log(
  "- MONGODB_URI:",
  process.env.MONGODB_URI ? "✅ Definido" : "❌ Não definido"
);

// Importar models apenas se MongoDB estiver disponível
let User, Rate, Alert;
const initModels = () => {
  try {
    User = require("./models/userModel");
    Rate = require("./models/rateModel");
    Alert = require("./models/alertModel");
    console.log("✅ Models carregados com sucesso");
  } catch (error) {
    console.error("⚠️ Erro ao carregar models:", error.message);
  }
};

const app = express();
const PORT = process.env.PORT || 5000;

// CONFIGURAÇÃO DE SEGURANÇA
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: false,
  })
);

if (process.env.NODE_ENV === "production") {
  app.use(compression());
  app.use(morgan("combined"));
  app.set("trust proxy", 1);
} else {
  app.use(morgan("dev"));
}

// Rate Limiting otimizado
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: process.env.NODE_ENV === "production" ? 1000 : 100,
  message: {
    error: "Muitas requisições deste IP",
    retryAfter: "15 minutos",
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting para health checks
    return (
      req.path === "/" || req.path === "/health" || req.path === "/api/health"
    );
  },
});

app.use(limiter);

// Rate limiting específico por utilizador autenticado
const createUserRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  max: 30, // 30 requests por minuto por utilizador
  keyGenerator: (req) => req.user?.userId || req.ip,
  message: { error: "Muitas requisições. Tente novamente em 1 minuto." },
});

// CORS Configuration otimizada
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      process.env.FRONTEND_URL,
      "https://seu-frontend.netlify.app",
      "https://seu-frontend.vercel.app",
      "http://localhost:3000",
      "http://localhost:5173",
      "http://192.168.51.7:3000",
    ].filter(Boolean);

    // Permitir requests sem origin (health checks, etc)
    if (!origin) return callback(null, true);

    // Em produção, ser mais permissivo para evitar falhas de deployment
    if (process.env.NODE_ENV === "production") {
      return callback(null, true);
    }

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(null, true); // Permitir em desenvolvimento
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "Accept",
    "Origin",
  ],
  exposedHeaders: ["X-Updated-Token"],
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));
app.use(express.json({ limit: "10mb" }));

// Initialize Google OAuth client
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Verify Google token function
const verifyGoogleToken = async (token) => {
  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    return ticket.getPayload();
  } catch (error) {
    console.error("Error verifying Google token:", error);
    throw new Error("Token do Google inválido");
  }
};

// === GOOGLE OAUTH ROUTE ===
// Add this route to your existing routes section
app.post("/api/auth/google", async (req, res) => {
  try {
    if (!User) {
      return res
        .status(503)
        .json({ message: "Serviço temporariamente indisponível" });
    }

    const { credential, userInfo } = req.body;

    if (!credential) {
      return res.status(400).json({ message: "Token do Google é obrigatório" });
    }

    // Verify the Google token
    let googlePayload;
    try {
      googlePayload = await verifyGoogleToken(credential);
    } catch (error) {
      return res.status(400).json({ message: "Token do Google inválido" });
    }

    const { email, name, picture, sub: googleId } = googlePayload;

    if (!email) {
      return res
        .status(400)
        .json({ message: "Email não fornecido pelo Google" });
    }

    // Check if user already exists
    let user = await User.findOne({
      $or: [{ email: email }, { googleId: googleId }],
    });

    if (user) {
      // User exists, update Google info if not set
      if (!user.googleId) {
        user.googleId = googleId;
        user.name = user.name || name;
        user.picture = picture;
        await user.save();
      }

      // Update last login
      user.lastLogin = new Date();
      await user.save();

      logger.info("Login Google realizado", {
        details: { email: user.email, method: "google" },
      });
    } else {
      // Create new user with Google info
      user = new User({
        email: email,
        googleId: googleId,
        name: name,
        picture: picture,
        password: null, // No password for Google users
        isEmailVerified: true, // Google emails are verified
        authProvider: "google",
      });

      await user.save();

      logger.info("Registo Google realizado", {
        details: { email: user.email, method: "google" },
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        userId: user._id,
        isPremium: user.isPremium,
        isAdmin: user.isAdmin,
        email: user.email,
        authProvider: user.authProvider || "google",
      },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        isPremium: user.isPremium,
        isAdmin: user.isAdmin,
        authProvider: user.authProvider || "google",
      },
      message: "Autenticação Google bem-sucedida",
    });
  } catch (error) {
    console.error("Erro na autenticação Google:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Add this middleware to handle users without passwords
const authenticateGoogleUser = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Token não fornecido" });

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) return res.status(403).json({ message: "Token inválido" });

    // For Google users, we might need additional validation
    if (decoded.authProvider === "google") {
      // Additional Google-specific validation can be added here
    }

    req.user = decoded;
    next();
  });
};

// Middleware de logging para desenvolvimento
app.use((req, res, next) => {
  if (process.env.NODE_ENV !== "production") {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    if (req.headers.origin) {
      console.log("Origin:", req.headers.origin);
    }
  }
  next();
});

// MongoDB Connection otimizada
const connectDB = async () => {
  if (!process.env.MONGODB_URI) {
    console.log("⚠️ MONGODB_URI não definida. Executando sem banco de dados.");
    return false;
  }

  const maxRetries = 3;
  let retries = 0;

  const connectionOptions = {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    maxPoolSize: 5, // Reduzido para Render
    retryWrites: true,
    w: "majority",
    maxIdleTimeMS: 30000,
    bufferCommands: false,
  };

  while (retries < maxRetries) {
    try {
      console.log(
        `🔄 Tentativa de conexão MongoDB ${retries + 1}/${maxRetries}...`
      );

      await mongoose.connect(process.env.MONGODB_URI, connectionOptions);
      console.log("✅ MongoDB conectado com sucesso!");

      // Carregar models após conexão
      initModels();

      // Inicializar database
      setTimeout(() => initializeDatabase(), 1000);

      return true;
    } catch (error) {
      retries++;
      console.error(
        `❌ Erro na conexão MongoDB (tentativa ${retries}/${maxRetries}):`,
        error.message
      );

      if (retries >= maxRetries) {
        console.error("❌ Máximo de tentativas de conexão excedido");
        console.log("⚠️ Continuando sem MongoDB - modo offline");
        return false;
      }

      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }
  return false;
};

// Event listeners do MongoDB
mongoose.connection.on("connected", () => {
  console.log("📊 MongoDB: Conexão estabelecida");
});

mongoose.connection.on("error", (err) => {
  console.error("❌ MongoDB: Erro na conexão:", err.message);
});

mongoose.connection.on("disconnected", () => {
  console.log("⚠️ MongoDB: Conexão perdida");
});

mongoose.connection.on("reconnected", () => {
  console.log("🔄 MongoDB: Reconectado");
});

// Health check otimizado
app.get(["/", "/api/health", "/health"], async (req, res) => {
  try {
    const dbConnected = mongoose.connection.readyState === 1;

    let ratesCount = 0;
    if (dbConnected && Rate) {
      try {
        ratesCount = await Rate.countDocuments();
      } catch (error) {
        console.error("Erro ao contar rates:", error.message);
      }
    }

    const health = {
      status: "OK",
      timestamp: new Date().toISOString(),
      version: "2.0.0",
      environment: process.env.NODE_ENV || "development",
      port: PORT,
      database: {
        connected: dbConnected,
        status: dbConnected ? "connected" : "disconnected",
      },
      uptime: Math.floor(process.uptime()),
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
      },
      data: {
        ratesCount,
        hasData: ratesCount > 0,
      },
    };

    res.status(200).json(health);
  } catch (error) {
    console.error("Erro no health check:", error);
    res.status(200).json({
      status: "OK",
      error: "Health check com avisos",
      timestamp: new Date().toISOString(),
      uptime: Math.floor(process.uptime()),
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

// Middleware para validar premium em tempo real
const validatePremiumStatus = async (req, res, next) => {
  try {
    if (!req.user || !req.user.userId) {
      return next();
    }

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
      res.setHeader("X-Updated-Token", newToken);

      // Atualizar req.user para a requisição atual
      req.user = {
        ...req.user,
        isPremium: currentUser.isPremium,
        isAdmin: currentUser.isAdmin,
      };
    }

    next();
  } catch (error) {
    console.error("Erro na validação de premium:", error);
    next();
  }
};

// Middleware de validação de request body
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
      return res
        .status(503)
        .json({ message: "Serviço temporariamente indisponível" });
    }

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
    if (!User) {
      return res
        .status(503)
        .json({ message: "Serviço temporariamente indisponível" });
    }

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

// Endpoint para forçar validação
app.post("/api/auth/validate", authenticateToken, async (req, res) => {
  try {
    const currentUser = await User.findById(req.user.userId);
    if (!currentUser) {
      return res.status(404).json({ message: "Utilizador não encontrado" });
    }

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
      message: "Sessão validada com sucesso",
    });
  } catch (error) {
    console.error("Erro na validação:", error);
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

        // VALIDAÇÃO DUPLA: Verificar na base de dados também
        if (User && mongoose.connection.readyState === 1) {
          const dbUser = await User.findById(user.userId);
          isPremium = dbUser ? dbUser.isPremium : false;
        } else {
          isPremium = user.isPremium || false;
        }
      } catch (err) {
        isPremium = false;
      }
    }

    const limit = isPremium ? 30 : 7;

    let rates;
    if (ratesCache.data && Date.now() - ratesCache.timestamp < 60000) {
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

// Estatísticas das taxas
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

// === ROTAS DO UTILIZADOR ===
app.post("/api/user/phone", authenticateToken, async (req, res) => {
  try {
    const { phoneNumber } = req.body;

    if (!phoneNumber) {
      return res
        .status(400)
        .json({ message: "Número de telefone é obrigatório" });
    }

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: "Utilizador não encontrado" });
    }

    user.phoneNumber = phoneNumber;
    await user.save();

    res.json({ message: "Número de telefone atualizado com sucesso!" });
  } catch (error) {
    console.error("Erro ao atualizar o número de telefone:", error);
    res.status(500).json({ message: "Erro ao atualizar o número de telefone" });
  }
});

// === ROTAS DE ALERTAS ===
app.post(
  "/api/alerts",
  authenticateToken,
  createUserRateLimit,
  validateRequestBody({
    currency: { required: true, type: "string" },
    value: { required: true, type: "number", min: 0 },
    rateType: { required: true, type: "string" },
  }),
  async (req, res) => {
    try {
      const { currency, value, type = "above", rateType = "buy" } = req.body;

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
        rateType,
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
  }
);

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
app.post(
  "/api/simulate",
  authenticateToken,
  createUserRateLimit,
  async (req, res) => {
    try {
      const { amount, fromCurrency, toCurrency, bank = "bna" } = req.body;

      if (!amount || !fromCurrency || !toCurrency) {
        return res
          .status(400)
          .json({ message: "Dados incompletos para simulação" });
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
  }
);

// === ROTA DE EXPORTAÇÃO DE DADOS ===
app.post(
  "/api/export-rates",
  authenticateToken,
  validatePremiumStatus,
  async (req, res) => {
    try {
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
      const worksheet = workbook.addWorksheet("Taxas de Câmbio");

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
      ];

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

      // Estilizar o cabeçalho
      worksheet.getRow(1).eachCell((cell) => {
        cell.font = { bold: true };
        cell.fill = {
          type: "pattern",
          pattern: "solid",
          fgColor: { argb: "FFE6E6FA" },
        };
      });

      res.setHeader(
        "Content-Type",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
      );
      res.setHeader(
        "Content-Disposition",
        `attachment; filename=taxas-cambio-${
          new Date().toISOString().split("T")[0]
        }.xlsx`
      );

      await workbook.xlsx.write(res);
      res.end();
    } catch (error) {
      console.error("Erro na exportação:", error);
      res.status(500).json({ message: "Erro ao exportar dados" });
    }
  }
);

// === ROTAS ADMINISTRATIVAS ===
app.post(
  "/api/admin/rates",
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
      } = req.body;

      if (
        !usdBuy ||
        !usdSell ||
        !eurBuy ||
        !eurSell ||
        !zarBuy ||
        !zarSell ||
        !cadBuy ||
        !cadSell
      ) {
        return res
          .status(400)
          .json({ message: "Todos os campos de taxas são obrigatórios" });
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

      // Limpar cache
      ratesCache.data = null;
      ratesCache.timestamp = 0;

      res.status(201).json({
        message: "Taxa adicionada com sucesso!",
        rate: newRate,
      });
    } catch (error) {
      console.error("Erro ao adicionar taxa:", error);
      res.status(500).json({ message: "Erro ao adicionar taxa" });
    }
  }
);

app.get(
  "/api/admin/users",
  authenticateToken,
  authenticateAdmin,
  async (req, res) => {
    try {
      const users = await User.find({}, "-password").sort({ createdAt: -1 });

      const userStats = await User.aggregate([
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            premium: { $sum: { $cond: ["$isPremium", 1, 0] } },
            basic: { $sum: { $cond: ["$isPremium", 0, 1] } },
            admins: { $sum: { $cond: ["$isAdmin", 1, 0] } },
          },
        },
      ]);

      res.json({
        users,
        stats: userStats[0] || { total: 0, premium: 0, basic: 0, admins: 0 },
      });
    } catch (error) {
      console.error("Erro ao buscar usuários:", error);
      res.status(500).json({ message: "Erro ao buscar usuários" });
    }
  }
);

app.patch(
  "/api/admin/users/:id/premium",
  authenticateToken,
  authenticateAdmin,
  async (req, res) => {
    try {
      const { isPremium } = req.body;

      const user = await User.findByIdAndUpdate(
        req.params.id,
        { isPremium: Boolean(isPremium) },
        { new: true }
      );

      if (!user) {
        return res.status(404).json({ message: "Utilizador não encontrado" });
      }

      res.json({
        message: `Status Premium ${
          isPremium ? "ativado" : "desativado"
        } com sucesso!`,
        user: {
          id: user._id,
          email: user.email,
          isPremium: user.isPremium,
          isAdmin: user.isAdmin,
        },
      });
    } catch (error) {
      console.error("Erro ao atualizar status premium:", error);
      res.status(500).json({ message: "Erro ao atualizar status premium" });
    }
  }
);

app.get(
  "/api/admin/alerts",
  authenticateToken,
  authenticateAdmin,
  async (req, res) => {
    try {
      const alerts = await Alert.find({})
        .populate("userId", "email")
        .sort({ dateCreated: -1 });

      res.json(alerts);
    } catch (error) {
      console.error("Erro ao buscar alertas:", error);
      res.status(500).json({ message: "Erro ao buscar alertas" });
    }
  }
);

// Add this route in server.js after the existing admin routes:
app.patch(
  "/api/admin/users/email/:email/premium",
  authenticateToken,
  authenticateAdmin,
  async (req, res) => {
    try {
      const { isPremium } = req.body;
      const email = decodeURIComponent(req.params.email);

      const user = await User.findOneAndUpdate(
        { email: email },
        { isPremium: Boolean(isPremium) },
        { new: true }
      );

      if (!user) {
        return res.status(404).json({ message: "Utilizador não encontrado" });
      }

      res.json({
        message: `Status Premium ${
          isPremium ? "ativado" : "desativado"
        } com sucesso!`,
        user: {
          id: user._id,
          email: user.email,
          isPremium: user.isPremium,
          isAdmin: user.isAdmin,
        },
      });
    } catch (error) {
      console.error("Erro ao atualizar status premium:", error);
      res.status(500).json({ message: "Erro ao atualizar status premium" });
    }
  }
);

// === SISTEMA DE NOTIFICAÇÕES ===
const checkAlerts = async () => {
  try {
    if (!Alert || !Rate || mongoose.connection.readyState !== 1) {
      return;
    }

    const activeAlerts = await Alert.find({ isTriggered: false });
    const latestRate = await Rate.findOne().sort({ date: -1 });

    if (!latestRate || activeAlerts.length === 0) {
      return;
    }

    for (const alert of activeAlerts) {
      const rateField = `${alert.currency}${
        alert.rateType === "buy" ? "Buy" : "Sell"
      }`;
      const currentRate = latestRate[rateField];

      let shouldTrigger = false;

      if (alert.type === "above" && currentRate >= alert.value) {
        shouldTrigger = true;
      } else if (alert.type === "below" && currentRate <= alert.value) {
        shouldTrigger = true;
      }

      if (shouldTrigger) {
        alert.isTriggered = true;
        alert.triggeredAt = new Date();
        alert.triggeredValue = currentRate;
        await alert.save();

        // Aqui você pode implementar envio de email/SMS
        console.log(
          `🔔 Alerta disparado para ${alert.currency.toUpperCase()}: ${currentRate} (${
            alert.type
          } ${alert.value})`
        );
      }
    }
  } catch (error) {
    console.error("Erro ao verificar alertas:", error);
  }
};

// Executar verificação de alertas a cada 5 minutos
cron.schedule("*/5 * * * *", checkAlerts);

// === MIDDLEWARE DE TRATAMENTO DE ERROS ===
app.use((err, req, res, next) => {
  console.error("Erro não tratado:", err);
  res.status(500).json({
    message: "Erro interno do servidor",
    error: process.env.NODE_ENV === "production" ? {} : err,
    timestamp: new Date().toISOString(),
  });
});

// === TRATAMENTO DE ROTAS NÃO ENCONTRADAS ===
app.use("*", (req, res) => {
  res.status(404).json({
    message: "Rota não encontrada",
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString(),
    availableEndpoints: [
      "GET /",
      "GET /api/health",
      "POST /api/auth/register",
      "POST /api/auth/login",
      "POST /api/auth/validate",
      "GET /api/rates",
      "GET /api/rates/stats",
      "POST /api/user/phone",
      "POST /api/alerts",
      "GET /api/alerts",
      "DELETE /api/alerts/:id",
      "POST /api/simulate",
      "POST /api/export-rates",
      "POST /api/admin/rates",
      "GET /api/admin/users",
      "PATCH /api/admin/users/:id/premium",
      "GET /api/admin/alerts",
    ],
  });
});

// Graceful shutdown
const gracefulShutdown = async (signal) => {
  console.log(`\n🛑 Recebido sinal ${signal}. Encerrando servidor...`);

  try {
    if (mongoose.connection.readyState === 1) {
      await mongoose.connection.close();
      console.log("📴 Conexão MongoDB encerrada");
    }
  } catch (error) {
    console.error("❌ Erro ao fechar conexão MongoDB:", error);
  }

  console.log("✅ Encerramento concluído");
  process.exit(0);
};

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Função de inicialização do servidor
const startServer = async () => {
  try {
    console.log("🚀 Iniciando servidor...");

    // Tentar conectar ao MongoDB
    const dbConnected = await connectDB();

    if (!dbConnected) {
      console.log("⚠️ Servidor iniciará sem base de dados (modo offline)");
    }

    // Iniciar servidor HTTP
    const server = app.listen(PORT, "0.0.0.0", () => {
      console.log(`
🚀 ====================================
   Servidor Cambio Angola iniciado!
🌐 URL: http://localhost:${PORT}
📊 Ambiente: ${process.env.NODE_ENV || "development"}
⏰ Horário: ${new Date().toLocaleString("pt-PT")}
📊 MongoDB: ${
        mongoose.connection.readyState === 1 ? "Conectado" : "Desconectado"
      }
📋 Funcionalidades ativas:
   - Autenticação JWT
   - Sistema de Alertas
   - Simulador de Câmbio
   - Exportação Excel (Premium)
   - Painel Administrativo
   - Cache Inteligente
   - Rate Limiting
====================================
      `);
    });

    // Configurar timeouts para Render
    server.keepAliveTimeout = 120000;
    server.headersTimeout = 120000;

    server.on("error", (error) => {
      console.error("❌ Erro no servidor:", error);
      if (error.code === "EADDRINUSE") {
        console.error(`❌ Porta ${PORT} já está em uso`);
        process.exit(1);
      }
    });

    // Iniciar verificação de alertas se estiver conectado
    if (dbConnected) {
      console.log(
        "🔔 Sistema de alertas ativado - verificações a cada 5 minutos"
      );
    }
  } catch (error) {
    console.error("❌ Falha ao iniciar servidor:", error);
    process.exit(1);
  }
};

// Iniciar servidor
if (require.main === module) {
  startServer().catch((error) => {
    console.error("❌ Erro fatal:", error);
    process.exit(1);
  });
}

module.exports = app;
