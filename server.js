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
const allowedIP = process.env.ALLOWED_IP || '187.36.172.217';
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
  if (req.path === '/health' || req.path.startsWith('/api/')) {
    return next();
  }

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
      console.log('❌ Tentativa de login com IP não autorizado:', cleanIP, '| Usuário:', username);
      await logLoginAttempt(username, false, 'IP não autorizado', deviceToken, cleanIP);
      return res.status(403).json({ 
        error: 'IP não autorizado',
        message: `Seu IP (${cleanIP}) não tem permissão para acessar este sistema`
      });
    }

    // 3. Verificar horário comercial
    const now = new Date();
    const brasiliaTime = new Date(now.toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
    const dayOfWeek = brasiliaTime.getDay();
    const hour = brasiliaTime.getHours();
    const isBusinessHours = dayOfWeek >= 1 && dayOfWeek <= 5 && hour >= 8 && hour < 18;

    if (!isBusinessHours) {
      console.log('❌ Tentativa de login fora do horário comercial:', username);
      await logLoginAttempt(username, false, 'Fora do horário comercial', deviceToken, cleanIP);
      return res.status(403).json({ 
        error: 'Fora do horário comercial',
        message: 'Acesso permitido apenas de segunda a sexta, das 8h às 18h' 
      });
    }

    // 4. Buscar usuário (CORRIGIDO - busca case-insensitive)
    const usernameSearch = username.toLowerCase().trim();
    console.log('🔍 Buscando usuário:', usernameSearch);
    
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('*')
      .ilike('username', usernameSearch) // 🔧 MUDANÇA: ilike ao invés de eq
      .single();

    if (userError || !userData) {
      console.log('❌ Usuário não encontrado:', usernameSearch);
      console.log('   Erro Supabase:', userError);
      
      await logLoginAttempt(username, false, 'Usuário não encontrado', deviceToken, cleanIP);
      return res.status(401).json({ 
        error: 'Usuário ou senha incorretos' 
      });
    }

    console.log('✅ Usuário encontrado:', userData.username);

    // 5. Verificar se usuário está ativo
    if (userData.is_active === false) {
      console.log('❌ Usuário inativo:', username);
      await logLoginAttempt(username, false, 'Usuário inativo', deviceToken, cleanIP);
      return res.status(401).json({ 
        error: 'Usuário inativo' 
      });
    }

    // 6. Verificar senha (texto simples)
    if (password !== userData.password) {
      console.log('❌ Senha incorreta para usuário:', username);
      await logLoginAttempt(username, false, 'Senha incorreta', deviceToken, cleanIP);
      return res.status(401).json({ 
        error: 'Usuário ou senha incorretos' 
      });
    }

    console.log('✅ Senha correta');

    // 7. Gerar device_fingerprint único
    const deviceFingerprint = deviceToken + '_' + Date.now();
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const truncatedUserAgent = userAgent.substring(0, 95);
    const truncatedDeviceName = userAgent.substring(0, 95);

    // 8. Verificar/Criar dispositivo autorizado (CORRIGIDO)
    const { data: existingDevice } = await supabase
      .from('authorized_devices')
      .select('*')
      .eq('user_id', userData.id)
      .eq('is_active', true)
      .maybeSingle(); // 🔧 MUDANÇA: maybeSingle ao invés de single

    if (existingDevice) {
      console.log('ℹ️ Dispositivo já existe para usuário:', username);
      
      // Atualizar informações do dispositivo
      await supabase
        .from('authorized_devices')
        .update({
          device_token: deviceToken,
          device_fingerprint: deviceFingerprint,
          ip_address: cleanIP,
          user_agent: truncatedUserAgent,
          last_login: new Date().toISOString()
        })
        .eq('id', existingDevice.id);
        
      console.log('✅ Dispositivo atualizado');
    } else {
      // Primeiro login - criar novo dispositivo
      const { error: deviceError } = await supabase
        .from('authorized_devices')
        .insert({
          user_id: userData.id,
          device_token: deviceToken,
          device_fingerprint: deviceFingerprint, // 🔧 CAMPO OBRIGATÓRIO
          device_name: truncatedDeviceName,
          ip_address: cleanIP,
          user_agent: truncatedUserAgent
        });

      if (deviceError) {
        console.error('❌ Erro ao autorizar dispositivo:', deviceError);
        return res.status(500).json({ 
          error: 'Erro ao autorizar dispositivo',
          details: deviceError.message 
        });
      }
      console.log('✅ Novo dispositivo autorizado para usuário:', username);
    }

    // 9. Criar sessão
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
      console.error('❌ Erro ao criar sessão:', sessionError);
      return res.status(500).json({ error: 'Erro ao criar sessão' });
    }

    // 10. Log de sucesso
    await logLoginAttempt(username, true, null, deviceToken, cleanIP);
    console.log('✅ Login realizado com sucesso:', username, '| IP:', cleanIP);

    // 11. Retornar dados da sessão
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
    console.error('❌ Erro no login:', error);
    res.status(500).json({ 
      error: 'Erro interno no servidor',
      details: error.message 
    });
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

    console.log('✅ Logout realizado:', sessionToken.substr(0, 20) + '...');
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Erro no logout:', error);
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
    console.error('❌ Erro ao verificar sessão:', error);
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
    console.error('❌ Erro ao registrar log:', error);
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
  console.log('='.repeat(50));
  console.log(`🚀 Portal Central rodando na porta ${PORT}`);
  console.log(`🔒 IP autorizado: ${allowedIP}`);
  console.log(`💾 Supabase configurado: ${supabaseUrl ? 'Sim ✅' : 'Não ❌'}`);
  console.log('⚠️  Senhas em texto simples - use bcrypt em produção!');
  console.log('='.repeat(50));
});
