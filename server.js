require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// ======== CONFIGURAÇÃO DO SUPABASE ========
// ==========================================
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const allowedIP = process.env.ALLOWED_IP || '191.248.35.46';
const supabase = createClient(supabaseUrl, supabaseKey);

// ==========================================
// ======== MIDDLEWARES =====================
// ==========================================
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// ======== FILTRO DE IP ====================
// ==========================================
app.use((req, res, next) => {
  // Permitir health check sem filtro de IP
  if (req.path === '/health') return next();

  const xForwardedFor = req.headers['x-forwarded-for'];
  const clientIP = xForwardedFor
    ? xForwardedFor.split(',')[0].trim()
    : req.socket.remoteAddress;

  const cleanIP = clientIP.replace('::ffff:', '');

  if (cleanIP !== allowedIP) {
    console.log('❌ IP bloqueado:', cleanIP);
    return res.status(403).json({
      error: 'Acesso negado',
      message: `Seu IP (${cleanIP}) não tem permissão para acessar este sistema`
    });
  }

  next();
});

// ==========================================
// ======== ROTA PRINCIPAL ==================
// ==========================================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==========================================
// ======== API - OBTER IP PÚBLICO ==========
// ==========================================
app.get('/api/ip', (req, res) => {
  const xForwardedFor = req.headers['x-forwarded-for'];
  const clientIP = xForwardedFor
    ? xForwardedFor.split(',')[0].trim()
    : req.socket.remoteAddress;

  const cleanIP = clientIP.replace('::ffff:', '');
  res.json({ ip: cleanIP });
});

// ==========================================
// ======== API - VERIFICAR HORÁRIO =========
// ==========================================
app.get('/api/business-hours', (req, res) => {
  const now = new Date();
  const brasiliaTime = new Date(now.toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
  const dayOfWeek = brasiliaTime.getDay();
  const hour = brasiliaTime.getHours();
  
  const isBusinessHours = dayOfWeek >= 1 && dayOfWeek <= 5 && hour >= 8 && hour < 18;
  
  res.json({
    isBusinessHours,
    currentTime: brasiliaTime.toLocaleString('pt-BR'),
    day: dayOfWeek,
    hour: hour
  });
});

// ==========================================
// ======== API - LOGIN =====================
// ==========================================
app.post('/api/login', async (req, res) => {
  try {
    const { username, password, deviceToken } = req.body;

    // 1. Validar campos
    if (!username || !password || !deviceToken) {
      return res.status(400).json({ 
        error: 'Campos obrigatórios ausentes' 
      });
    }

    // 2. Verificar IP
    const xForwardedFor = req.headers['x-forwarded-for'];
    const clientIP = xForwardedFor
      ? xForwardedFor.split(',')[0].trim()
      : req.socket.remoteAddress;
    const cleanIP = clientIP.replace('::ffff:', '');

    if (cleanIP !== allowedIP) {
      await logLoginAttempt(username, false, 'IP não autorizado', deviceToken, cleanIP);
      return res.status(403).json({ 
        error: 'IP não autorizado' 
      });
    }

    // 3. Verificar horário comercial
    const now = new Date();
    const brasiliaTime = new Date(now.toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
    const dayOfWeek = brasiliaTime.getDay();
    const hour = brasiliaTime.getHours();
    const isBusinessHours = dayOfWeek >= 1 && dayOfWeek <= 5 && hour >= 8 && hour < 18;

    if (!isBusinessHours) {
      return res.status(403).json({ 
        error: 'Fora do horário comercial',
        message: 'Acesso permitido apenas de segunda a sexta, das 8h às 18h' 
      });
    }

    // 4. Verificar credenciais
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('username', username.toLowerCase().trim())
      .eq('password', password)
      .eq('is_active', true)
      .single();

    if (userError || !userData) {
      await logLoginAttempt(username, false, 'Credenciais inválidas', deviceToken, cleanIP);
      return res.status(401).json({ 
        error: 'Usuário ou senha incorretos' 
      });
    }

    // 5. Verificar dispositivo autorizado
    const { data: deviceData } = await supabase
      .from('authorized_devices')
      .select('*')
      .eq('user_id', userData.id)
      .eq('is_active', true)
      .single();

    if (deviceData) {
      // Dispositivo já existe - verificar se é o mesmo
      if (deviceData.device_token !== deviceToken) {
        await logLoginAttempt(username, false, 'Dispositivo não autorizado', deviceToken, cleanIP);
        return res.status(403).json({ 
          error: 'Este usuário já está vinculado a outro dispositivo' 
        });
      }
    } else {
      // Primeiro login - autorizar dispositivo
      const { error: deviceError } = await supabase
        .from('authorized_devices')
        .insert({
          user_id: userData.id,
          device_token: deviceToken,
          device_name: req.headers['user-agent'] || 'Unknown',
          ip_address: cleanIP,
          user_agent: req.headers['user-agent'] || 'Unknown'
        });

      if (deviceError) {
        console.error('Erro ao autorizar dispositivo:', deviceError);
        return res.status(500).json({ error: 'Erro ao autorizar dispositivo' });
      }
    }

    // 6. Criar sessão
    const sessionToken = 'sess_' + Date.now() + '_' + Math.random().toString(36).substr(2, 16);
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 8);

    const { error: sessionError } = await supabase
      .from('active_sessions')
      .insert({
        user_id: userData.id,
        device_token: deviceToken,
        ip_address: cleanIP,
        session_token: sessionToken,
        expires_at: expiresAt.toISOString()
      });

    if (sessionError) {
      console.error('Erro ao criar sessão:', sessionError);
      return res.status(500).json({ error: 'Erro ao criar sessão' });
    }

    // 7. Log de sucesso
    await logLoginAttempt(username, true, null, deviceToken, cleanIP);

    // 8. Retornar dados da sessão
    res.json({
      success: true,
      session: {
        userId: userData.id,
        username: userData.username,
        name: userData.name,
        isAdmin: userData.is_admin,
        sessionToken: sessionToken,
        deviceToken: deviceToken,
        ip: cleanIP,
        expiresAt: expiresAt.toISOString()
      }
    });

  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// ==========================================
// ======== API - LOGOUT ====================
// ==========================================
app.post('/api/logout', async (req, res) => {
  try {
    const { sessionToken } = req.body;

    if (!sessionToken) {
      return res.status(400).json({ error: 'Session token ausente' });
    }

    await supabase
      .from('active_sessions')
      .update({ is_active: false })
      .eq('session_token', sessionToken);

    res.json({ success: true });
  } catch (error) {
    console.error('Erro no logout:', error);
    res.status(500).json({ error: 'Erro ao fazer logout' });
  }
});

// ==========================================
// ======== API - VERIFICAR SESSÃO ==========
// ==========================================
app.post('/api/verify-session', async (req, res) => {
  try {
    const { sessionToken } = req.body;

    if (!sessionToken) {
      return res.status(400).json({ error: 'Session token ausente' });
    }

    const { data: session, error } = await supabase
      .from('active_sessions')
      .select('*')
      .eq('session_token', sessionToken)
      .eq('is_active', true)
      .single();

    if (error || !session) {
      return res.status(401).json({ valid: false });
    }

    if (new Date(session.expires_at) < new Date()) {
      return res.status(401).json({ valid: false, reason: 'expired' });
    }

    res.json({ valid: true });
  } catch (error) {
    console.error('Erro ao verificar sessão:', error);
    res.status(500).json({ error: 'Erro ao verificar sessão' });
  }
});

// ==========================================
// ======== FUNÇÃO AUXILIAR - LOG ===========
// ==========================================
async function logLoginAttempt(username, success, reason, deviceToken, ip) {
  try {
    await supabase.from('login_attempts').insert({
      username: username,
      ip_address: ip,
      device_token: deviceToken,
      success: success,
      failure_reason: reason
    });
  } catch (error) {
    console.error('Erro ao registrar log:', error);
  }
}

// ==========================================
// ======== HEALTH CHECK ====================
// ==========================================
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    supabase: supabaseUrl ? 'configured' : 'not configured'
  });
});

// ==========================================
// ======== INICIAR SERVIDOR ================
// ==========================================
app.listen(PORT, () => {
  console.log(`==> Portal Central rodando na porta ${PORT}`);
  console.log(`==> IP autorizado: ${allowedIP}`);
  console.log(`==> Supabase configurado: ${supabaseUrl ? 'Sim' : 'Não'}`);
});
