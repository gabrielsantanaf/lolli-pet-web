/**
 * API Service - Centraliza todas as chamadas HTTP para o backend
 *
 * Este arquivo gerencia:
 * - Configuração da URL base da API
 * - Autenticação com tokens JWT
 * - Headers padrão para todas as requisições
 * - Tratamento de erros centralizado
 */

// Obtém a URL base da API a partir das variáveis de ambiente
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001';

/**
 * Interface para respostas de erro da API
 */
export interface ApiError {
  message: string;
  status: number;
  details?: unknown;
}

/**
 * Interface para dados de login
 */
export interface LoginData {
  email: string;
  password: string;
}

/**
 * Interface para dados de cadastro/signup
 */
export interface SignupData {
  nome: string;
  email: string;
  password: string;
}

/**
 * Interface para resposta do endpoint /token (retorna apenas o token)
 */
interface TokenResponse {
  token: string;
}

/**
 * Interface para dados do usuário retornados pelo /veterinarios/me
 */
interface UserData {
  id: number;
  nome: string;
  email: string;
  crmv?: string;
  especialidade?: string;
}

/**
 * Interface para resposta completa de autenticação
 * (combina token + dados do usuário)
 */
export interface AuthResponse {
  token: string;
  user: UserData;
}

/**
 * Obtém o token JWT do localStorage
 */
export const getToken = (): string | null => {
  return localStorage.getItem('authToken');
};

/**
 * Salva o token JWT no localStorage
 *
 * @param token - Token JWT recebido do backend
 */
export const setToken = (token: string): void => {
  localStorage.setItem('authToken', token);
};

/**
 * Remove o token JWT do localStorage
 */
export const removeToken = (): void => {
  localStorage.removeItem('authToken');
};

/**
 * Salva os dados do usuário no localStorage
 *
 * @param user - Dados do usuário
 */
export const setUser = (user: UserData): void => {
  localStorage.setItem('user', JSON.stringify(user));
};

/**
 * Obtém os dados do usuário do localStorage
 */
export const getUser = (): UserData | null => {
  const userStr = localStorage.getItem('user');
  if (!userStr) return null;

  try {
    return JSON.parse(userStr);
  } catch {
    return null;
  }
};

/**
 * Remove os dados do usuário do localStorage
 */
export const removeUser = (): void => {
  localStorage.removeItem('user');
};

/**
 * Cria headers padrão para requisições HTTP
 * Inclui o token de autenticação se disponível
 *
 * @param includeAuth - Se true, inclui o token de autenticação no header
 */
const getHeaders = (includeAuth = false): HeadersInit => {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };

  if (includeAuth) {
    const token = getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
  }

  return headers;
};

/**
 * Função genérica para fazer requisições HTTP
 *
 * @param endpoint - Endpoint da API (ex: '/token')
 * @param options - Opções do fetch
 * @param includeAuth - Se true, inclui o token de autenticação
 * @returns Promise com os dados da resposta
 */
const apiRequest = async <T>(
  endpoint: string,
  options: RequestInit = {},
  includeAuth = false
): Promise<T> => {
  const url = `${API_BASE_URL}${endpoint}`;

  console.log(`[API] ${options.method || 'GET'} ${url}`, {
    headers: getHeaders(includeAuth),
    body: options.body ? JSON.parse(options.body as string) : undefined,
  });

  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        ...getHeaders(includeAuth),
        ...options.headers,
      },
    });

    // Tenta fazer parse do JSON da resposta
    let data;
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      data = await response.json();
    } else {
      data = await response.text();
    }

    console.log(`[API] Response ${response.status}:`, data);

    // Se a resposta não for OK (status 200-299), lança um erro
    if (!response.ok) {
      const error: ApiError = {
        message: data?.message || data || 'Erro ao comunicar com o servidor',
        status: response.status,
        details: data,
      };
      throw error;
    }

    return data as T;
  } catch (error) {
    // Se for um erro da API (já tratado acima), repassa
    if ((error as ApiError).status) {
      throw error;
    }

    // Caso contrário, é um erro de rede ou parsing
    console.error('[API] Erro na requisição:', error);
    throw {
      message: 'Erro ao conectar com o servidor. Verifique sua conexão.',
      status: 0,
      details: error,
    } as ApiError;
  }
};

// ============================================================
// ENDPOINTS DE AUTENTICAÇÃO
// ============================================================

/**
 * Busca os dados do veterinário logado no servidor
 *
 * Envia para: GET /veterinarios/me
 * Headers: Authorization: Bearer {token}
 * Retorna: { id, nome, email, crmv, especialidade }
 *
 * Esta função é chamada após o login para obter os dados completos do usuário
 */
export const getMe = async (): Promise<UserData> => {
  console.log('[AUTH] Buscando dados do usuário logado');

  const userData = await apiRequest<UserData>(
    '/veterinarios/me',
    {
      method: 'GET',
    },
    true // Inclui token de autenticação
  );

  // Atualiza o localStorage com os dados frescos do servidor
  setUser(userData);

  return userData;
};

/**
 * Faz login do usuário
 *
 * Fluxo:
 * 1. POST /token → recebe apenas o token JWT
 * 2. GET /veterinarios/me → busca dados completos do usuário
 * 3. Salva token e dados no localStorage
 * 4. Retorna { token, user }
 *
 * @param data - Dados de login (email e senha)
 */
export const login = async (data: LoginData): Promise<AuthResponse> => {
  console.log('[AUTH] Fazendo login com email:', data.email);

  try {
    // PASSO 1: Faz login e recebe apenas o token
    const tokenResponse = await apiRequest<TokenResponse>(
      '/token',
      {
        method: 'POST',
        body: JSON.stringify(data),
      }
    );

    console.log('[AUTH] ✅ Token recebido');

    // PASSO 2: Salva o token no localStorage
    setToken(tokenResponse.token);

    // PASSO 3: Busca dados completos do usuário usando o token
    console.log('[AUTH] Buscando dados do usuário...');
    const userData = await getMe();

    console.log('[AUTH] ✅ Login bem-sucedido! Dados do usuário:', userData);

    // PASSO 4: Retorna token + dados do usuário
    return {
      token: tokenResponse.token,
      user: userData
    };
  } catch (error) {
    // Se der erro em qualquer etapa, remove o token e repassa o erro
    console.error('[AUTH] ❌ Erro no login:', error);
    removeToken();
    throw error;
  }
};

/**
 * Registra um novo usuário (veterinário)
 *
 * Envia para: POST /veterinarios
 * Body: { nome, email, password, crmv, especialidade }
 * Retorna: { id, nome, email }
 *
 * Após criar o veterinário, você ainda precisa fazer login
 * para obter o token de autenticação
 *
 * @param data - Dados de cadastro
 */
export const signup = async (data: SignupData): Promise<AuthResponse> => {
  console.log('[AUTH] Registrando novo usuário:', data.email);

  // Cria o veterinário
  await apiRequest<UserData>(
    '/veterinarios',
    {
      method: 'POST',
      body: JSON.stringify(data),
    }
  );

  console.log('[AUTH] Veterinário criado! Fazendo login...');

  // Após criar, faz login automaticamente
  const loginResponse = await login({
    email: data.email,
    password: data.password
  });

  console.log('[AUTH] Cadastro bem-sucedido! Token salvo.');
  return loginResponse;
};

/**
 * Faz logout do usuário
 * Remove token e dados do localStorage
 */
export const logout = (): void => {
  console.log('[AUTH] Fazendo logout...');
  removeToken();
  removeUser();
  console.log('[AUTH] Logout completo. Tokens removidos.');
};

/**
 * Verifica se o usuário está autenticado
 * (verifica apenas se existe token no localStorage)
 */
export const isAuthenticated = (): boolean => {
  return !!getToken();
};

/**
 * Revalida a autenticação buscando dados do servidor
 * Útil para verificar se o token ainda é válido
 *
 * @returns true se o token é válido, false caso contrário
 */
export const revalidateAuth = async (): Promise<boolean> => {
  const token = getToken();

  if (!token) {
    return false;
  }

  try {
    await getMe(); // Se conseguir buscar, token é válido
    return true;
  } catch (error) {
    // Token inválido ou expirado
    console.error('[AUTH] Token inválido:', error);
    removeToken();
    removeUser();
    return false;
  }
};

// ============================================================
// ENDPOINTS DE CLIENTES
// ============================================================

/**
 * Cadastra um novo cliente com seus pets
 *
 * Envia para: POST /clientes
 * Headers: Authorization: Bearer {token}
 * Body: { nome, email, telefone, pets: [...] }
 *
 * @param data - Dados do cliente e pets
 */
export const cadastrarCliente = async (data: unknown): Promise<unknown> => {
  console.log('[CLIENTES] Cadastrando novo cliente');

  return apiRequest(
    '/clientes',
    {
      method: 'POST',
      body: JSON.stringify(data),
    },
    true // Inclui token de autenticação
  );
};

/**
 * Lista todos os clientes
 *
 * Envia para: GET /clientes
 * Headers: Authorization: Bearer {token}
 * Retorna: Array de clientes
 */
export const listarClientes = async (): Promise<unknown[]> => {
  console.log('[CLIENTES] Listando clientes');

  return apiRequest(
    '/clientes',
    {
      method: 'GET',
    },
    true // Inclui token de autenticação
  );
};

// ============================================================
// ENDPOINTS DE PETS
// ============================================================

/**
 * Lista todos os pets
 *
 * Envia para: GET /pets
 * Headers: Authorization: Bearer {token}
 * Retorna: Array de pets
 */
export const listarPets = async (): Promise<unknown[]> => {
  console.log('[PETS] Listando pets');

  return apiRequest(
    '/pets',
    {
      method: 'GET',
    },
    true // Inclui token de autenticação
  );
};

// ============================================================
// ENDPOINTS DE AGENDAMENTOS
// ============================================================

/**
 * Cria um agendamento clínico
 *
 * Envia para: POST /agendamentos
 * Headers: Authorization: Bearer {token}
 * Body: { servico: 'clinico', pet_id, data_hora, observacoes }
 *
 * @param data - Dados do agendamento clínico
 */
export const agendarClinico = async (data: unknown): Promise<unknown> => {
  console.log('[AGENDAMENTO] Criando agendamento clínico');

  return apiRequest(
    '/agendamentos',
    {
      method: 'POST',
      body: JSON.stringify({ ...(data as Record<string, unknown>), servico: 'clinico' }),
    },
    true // Inclui token de autenticação
  );
};

/**
 * Cria um agendamento de petshop
 *
 * Envia para: POST /agendamentos
 * Headers: Authorization: Bearer {token}
 * Body: { servico: 'petshop', pet_id, data_hora, observacoes }
 *
 * @param data - Dados do agendamento petshop
 */
export const agendarPetshop = async (data: unknown): Promise<unknown> => {
  console.log('[AGENDAMENTO] Criando agendamento petshop');

  return apiRequest(
    '/agendamentos',
    {
      method: 'POST',
      body: JSON.stringify({ ...(data as Record<string, unknown>), servico: 'petshop' }),
    },
    true // Inclui token de autenticação
  );
};

/**
 * Lista todos os agendamentos
 *
 * Envia para: GET /agendamentos
 * Headers: Authorization: Bearer {token}
 * Retorna: Array de agendamentos
 */
export const listarAgendamentos = async (): Promise<unknown[]> => {
  console.log('[AGENDAMENTO] Listando agendamentos');

  return apiRequest(
    '/agendamentos',
    {
      method: 'GET',
    },
    true // Inclui token de autenticação
  );
};

/**
 * Busca um agendamento específico por ID
 *
 * Envia para: GET /agendamentos/:id
 * Headers: Authorization: Bearer {token}
 * Retorna: Dados do agendamento
 *
 * @param id - ID do agendamento
 */
export const buscarAgendamento = async (id: number): Promise<unknown> => {
  console.log('[AGENDAMENTO] Buscando agendamento:', id);

  return apiRequest(
    `/agendamentos/${id}`,
    {
      method: 'GET',
    },
    true // Inclui token de autenticação
  );
};

/**
 * Atualiza um agendamento
 *
 * Envia para: PUT /agendamentos/:id
 * Headers: Authorization: Bearer {token}
 * Body: { status, observacoes, ... }
 *
 * @param id - ID do agendamento
 * @param data - Dados para atualizar
 */
export const atualizarAgendamento = async (id: number, data: unknown): Promise<unknown> => {
  console.log('[AGENDAMENTO] Atualizando agendamento:', id);

  return apiRequest(
    `/agendamentos/${id}`,
    {
      method: 'PUT',
      body: JSON.stringify(data),
    },
    true // Inclui token de autenticação
  );
};

/**
 * Deleta um agendamento
 *
 * Envia para: DELETE /agendamentos/:id
 * Headers: Authorization: Bearer {token}
 *
 * @param id - ID do agendamento
 */
export const deletarAgendamento = async (id: number): Promise<unknown> => {
  console.log('[AGENDAMENTO] Deletando agendamento:', id);

  return apiRequest(
    `/agendamentos/${id}`,
    {
      method: 'DELETE',
    },
    true // Inclui token de autenticação
  );
};

// ============================================================
// ENDPOINTS DE PRONTUÁRIO
// ============================================================

/**
 * Busca prontuários (pode filtrar por cliente ou pet)
 *
 * Envia para: GET /prontuarios?clienteId=xxx&petId=xxx
 * Headers: Authorization: Bearer {token}
 *
 * @param params - Parâmetros de filtro (opcional)
 */
export const buscarProntuarios = async (params?: Record<string, string>): Promise<unknown[]> => {
  console.log('[PRONTUARIO] Buscando prontuários');

  const queryString = params
    ? '?' + new URLSearchParams(params).toString()
    : '';

  return apiRequest(
    `/prontuarios${queryString}`,
    {
      method: 'GET',
    },
    true // Inclui token de autenticação
  );
};

// ============================================================
// EXPORT DEFAULT
// ============================================================

export default {
  // Auth
  login,
  signup,
  logout,
  isAuthenticated,
  revalidateAuth,
  getMe,
  getToken,
  setToken,
  removeToken,
  getUser,
  setUser,
  removeUser,

  // Clientes
  cadastrarCliente,
  listarClientes,

  // Pets
  listarPets,

  // Agendamentos
  agendarClinico,
  agendarPetshop,
  listarAgendamentos,
  buscarAgendamento,
  atualizarAgendamento,
  deletarAgendamento,

  // Prontuários
  buscarProntuarios,
};