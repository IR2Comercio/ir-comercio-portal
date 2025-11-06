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
const supabase = createClient(supabaseUrl, supabaseKey);

// ==========================================
// ======== MIDDLEWARES =====================
// ==========================================
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Responder a requisições OPTIONS (preflight)
app.options('*', cors());

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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

    // 2. Obter IP do cliente
    const xForwardedFor = req.headers['x-forwarded-for'];
    const clientIP = xForwardedFor
      ? xForwardedFor.split(',')[0].trim()
      : req.socket.remoteAddress;
    const cleanIP = clientIP.replace('::ffff:', '');

    // 3. Buscar usuário (case-insensitive)
    const usernameSearch = username.toLowerCase().trim();
    console.log('🔍 Buscando usuário:', usernameSearch);
    
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('*')
      .ilike('username', usernameSearch)
      .single();

    if (userError || !userData) {
      console.log('❌ Usuário não encontrado:', usernameSearch);
      await logLoginAttempt(username, false, 'Usuário não encontrado', deviceToken, cleanIP);
      return res.status(401).json({ 
        error: 'Usuário ou senha incorretos' 
      });
    }

    console.log('✅ Usuário encontrado:', userData.username);

    // 4. Verificar se usuário está ativo
    if (userData.is_active === false) {
      console.log('❌ Usuário inativo:', username);
      await logLoginAttempt(username, false, 'Usuário inativo', deviceToken, cleanIP);
      return res.status(401).json({ 
        error: 'Usuário inativo' 
      });
    }

    // 5. Verificar horário comercial (apenas para não-admin)
    if (!userData.is_admin) {
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
          message: 'Acesso de usuários permitido apenas de segunda a sexta, das 8h às 18h (horário de Brasília)' 
        });
      }
    }

    // 6. Verificar senha
    if (password !== userData.password) {
      console.log('❌ Senha incorreta para usuário:', username);
      await logLoginAttempt(username, false, 'Senha incorreta', deviceToken, cleanIP);
      return res.status(401).json({ 
        error: 'Usuário ou senha incorretos' 
      });
    }

    console.log('✅ Senha correta');

    // 7. Registrar/Atualizar dispositivo usando UPSERT
    const deviceFingerprint = deviceToken + '_' + Date.now();
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const truncatedUserAgent = userAgent.substring(0, 95);
    const truncatedDeviceName = userAgent.substring(0, 95);

    console.log('ℹ️ Registrando/atualizando dispositivo');
    
    const { error: deviceError } = await supabase
      .from('authorized_devices')
      .upsert({
        user_id: userData.id,
        device_token: deviceToken,
        device_fingerprint: deviceFingerprint,
        device_name: truncatedDeviceName,
        ip_address: cleanIP,
        user_agent: truncatedUserAgent,
        is_active: true,
        last_access: new Date().toISOString()
      }, {
        onConflict: 'device_token',
        ignoreDuplicates: false
      });

    if (deviceError) {
      console.error('❌ Erro ao registrar dispositivo:', deviceError);
      return res.status(500).json({ 
        error: 'Erro ao registrar dispositivo',
        details: deviceError.message 
      });
    }
    console.log('✅ Dispositivo registrado/atualizado');

    // 8. Criar ou atualizar sessão
    const sessionToken = 'sess_' + Date.now() + '_' + Math.random().toString(36).substr(2, 16);
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 8);

    // Verificar se já existe uma sessão ativa para este usuário + dispositivo
    const { data: existingSession } = await supabase
      .from('active_sessions')
      .select('*')
      .eq('user_id', userData.id)
      .eq('device_token', deviceToken)
      .eq('is_active', true)
      .maybeSingle();

    if (existingSession) {
      console.log('ℹ️ Sessão ativa encontrada - atualizando');
      
      // Atualizar sessão existente
      const { error: sessionError } = await supabase
        .from('active_sessions')
        .update({
          ip_address: cleanIP,
          session_token: sessionToken,
          expires_at: expiresAt.toISOString(),
          last_activity: new Date().toISOString()
        })
        .eq('id', existingSession.id);

      if (sessionError) {
        console.error('❌ Erro ao atualizar sessão:', sessionError);
        return res.status(500).json({ 
          error: 'Erro ao atualizar sessão',
          details: sessionError.message 
        });
      }
      
      console.log('✅ Sessão atualizada com sucesso');
    } else {
      console.log('ℹ️ Criando nova sessão');
      
      // Desativar sessões antigas deste usuário + dispositivo
      await supabase
        .from('active_sessions')
        .update({ is_active: false })
        .eq('user_id', userData.id)
        .eq('device_token', deviceToken);
      
      // Criar nova sessão
      const { error: sessionError } = await supabase
        .from('active_sessions')
        .insert({
          user_id: userData.id,
          device_token: deviceToken,
          ip_address: cleanIP,
          session_token: sessionToken,
          expires_at: expiresAt.toISOString(),
          is_active: true,
          last_activity: new Date().toISOString()
        });

      if (sessionError) {
        console.error('❌ Erro ao criar sessão:', sessionError);
        return res.status(500).json({ 
          error: 'Erro ao criar sessão',
          details: sessionError.message 
        });
      }
      
      console.log('✅ Nova sessão criada com sucesso');
    }

    // 9. Log de sucesso
    await logLoginAttempt(username, true, null, deviceToken, cleanIP);
    console.log('✅ Login realizado com sucesso:', username, '| IP:', cleanIP);

    // 10. Retornar dados da sessão
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
    const { sessionToken, deviceToken } = req.body;

    if (!sessionToken) {
      return res.status(400).json({ error: 'Session token ausente' });
    }

    // Desativar a sessão
    const { error } = await supabase
      .from('active_sessions')
      .update({ 
        is_active: false,
        logout_at: new Date().toISOString()
      })
      .eq('session_token', sessionToken);

    if (error) {
      console.error('❌ Erro ao fazer logout:', error);
      return res.status(500).json({ error: 'Erro ao fazer logout' });
    }

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
      return res.status(400).json({ 
        valid: false, 
        reason: 'token_missing' 
      });
    }

    // Buscar sessão
    const { data: session, error } = await supabase
      .from('active_sessions')
      .select(`
        *,
        users:user_id (
          id,
          username,
          name,
          is_admin,
          is_active
        )
      `)
      .eq('session_token', sessionToken)
      .eq('is_active', true)
      .single();

    if (error || !session) {
      return res.status(401).json({ 
        valid: false, 
        reason: 'session_not_found' 
      });
    }

    // Verificar se o usuário ainda está ativo
    if (!session.users.is_active) {
      await supabase
        .from('active_sessions')
        .update({ is_active: false })
        .eq('session_token', sessionToken);
      
      return res.status(401).json({ 
        valid: false, 
        reason: 'user_inactive' 
      });
    }

    // Verificar expiração
    if (new Date(session.expires_at) < new Date()) {
      await supabase
        .from('active_sessions')
        .update({ is_active: false })
        .eq('session_token', sessionToken);
      
      return res.status(401).json({ 
        valid: false, 
        reason: 'session_expired' 
      });
    }

    // Verificar horário comercial para não-admin
    if (!session.users.is_admin) {
      const now = new Date();
      const brasiliaTime = new Date(now.toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
      const dayOfWeek = brasiliaTime.getDay();
      const hour = brasiliaTime.getHours();
      const isBusinessHours = dayOfWeek >= 1 && dayOfWeek <= 5 && hour >= 8 && hour < 18;

      if (!isBusinessHours) {
        return res.status(403).json({ 
          valid: false, 
          reason: 'outside_business_hours',
          message: 'Acesso permitido apenas de segunda a sexta, das 8h às 18h (horário de Brasília)'
        });
      }
    }

    // Atualizar última atividade
    await supabase
      .from('active_sessions')
      .update({ last_activity: new Date().toISOString() })
      .eq('session_token', sessionToken);

    res.json({ 
      valid: true,
      session: {
        userId: session.users.id,
        username: session.users.username,
        name: session.users.name,
        isAdmin: session.users.is_admin
      }
    });
  } catch (error) {
    console.error('❌ Erro ao verificar sessão:', error);
    res.status(500).json({ 
      valid: false,
      reason: 'server_error',
      error: 'Erro ao verificar sessão' 
    });
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
      failure_reason: reason,
      timestamp: new Date().toISOString()
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
// ======== ROTA 404 ========================
// ==========================================
app.use((req, res) => {
  res.status(404).json({ error: 'Rota não encontrada' });
});

// ==========================================
// ======== INICIAR SERVIDOR ================
// ==========================================
app.listen(PORT, () => {
  console.log('='.repeat(50));
  console.log(`🚀 Portal Central rodando na porta ${PORT}`);
  console.log(`💾 Supabase configurado: ${supabaseUrl ? 'Sim ✅' : 'Não ❌'}`);
  console.log('⏰ Horário comercial: Seg-Sex, 8h-18h (apenas não-admin)');
  console.log('='.repeat(50));
});
