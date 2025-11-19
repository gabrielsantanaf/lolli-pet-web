/**
 * Página de Cadastro/Signup
 *
 * Funcionalidades:
 * - Formulário de cadastro com validação
 * - Integração com backend via API service
 * - Confirmação de senha
 * - Redirecionamento após cadastro bem-sucedido
 * - Tratamento de erros
 * - Link para página de login
 */

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useNavigate, Link } from 'react-router-dom';
import { User, Mail, Lock, UserPlus, AlertCircle } from 'lucide-react';
import { signupSchema, type SignupFormData } from '../schemas/AuthSchemas';
import { useAuth } from '../context/useAuth';
import type { ApiError } from '../../services/api';

export default function Signup() {
  const navigate = useNavigate();
  const { signup } = useAuth();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<SignupFormData>({
    resolver: zodResolver(signupSchema),
  });

  /**
   * Handler para submissão do formulário
   *
   * Envia para: POST /api/auth/signup
   * Body: { nome: string, email: string, password: string}
   * Resposta esperada: { token: string, user: {...} }
   */
  const onSubmit = async (data: SignupFormData) => {
    setIsSubmitting(true);
    setErrorMessage(null);

    console.log('[Signup] Tentando cadastrar usuário:', { email: data.email, nome: data.nome });

    try {
      // Chama a função de signup do AuthContext
      // Isso internamente chama: POST /api/auth/signup
      await signup(data.nome, data.email, data.password);

      console.log('[Signup] Cadastro bem-sucedido! Redirecionando...');

      // Redireciona para a página inicial após cadastro
      navigate('/');
    } catch (error) {
      console.error('[Signup] Erro ao fazer cadastro:', error);

      // Trata erros da API
      const apiError = error as ApiError;
      if (apiError.message) {
        setErrorMessage(apiError.message);
      } else {
        setErrorMessage('Erro ao fazer cadastro. Tente novamente.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-pink-50 to-cyan-50 dark:from-gray-900 dark:to-gray-800 flex items-center justify-center p-4">
      <div className="max-w-md w-full">
        {/* Card de Cadastro */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl p-8">
          {/* Cabeçalho */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-pink-500 to-cyan-500 rounded-full mb-4">
              <UserPlus className="w-8 h-8 text-white" />
            </div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
              Criar Conta
            </h1>
            <p className="text-gray-600 dark:text-gray-400">
              Preencha os dados para se cadastrar
            </p>
          </div>

          {/* Mensagem de Erro */}
          {errorMessage && (
            <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-red-600 dark:text-red-400">
                {errorMessage}
              </p>
            </div>
          )}

          {/* Formulário */}
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
            {/* Campo de Nome */}
            <div>
              <label
                htmlFor="nome"
                className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2"
              >
                Nome Completo
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <User className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  {...register('nome')}
                  id="nome"
                  type="text"
                  autoComplete="name"
                  placeholder="Seu nome completo"
                  className={`
                    block w-full pl-10 pr-3 py-3 border rounded-lg
                    bg-white dark:bg-gray-700
                    text-gray-900 dark:text-white
                    placeholder-gray-400 dark:placeholder-gray-500
                    focus:outline-none focus:ring-2 focus:ring-pink-500 focus:border-transparent
                    ${
                      errors.nome
                        ? 'border-red-300 dark:border-red-600'
                        : 'border-gray-300 dark:border-gray-600'
                    }
                  `}
                />
              </div>
              {errors.nome && (
                <p className="mt-1 text-sm text-red-600 dark:text-red-400">
                  {errors.nome.message}
                </p>
              )}
            </div>

            {/* Campo de Email */}
            <div>
              <label
                htmlFor="email"
                className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2"
              >
                E-mail
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  {...register('email')}
                  id="email"
                  type="email"
                  autoComplete="email"
                  placeholder="seu@email.com"
                  className={`
                    block w-full pl-10 pr-3 py-3 border rounded-lg
                    bg-white dark:bg-gray-700
                    text-gray-900 dark:text-white
                    placeholder-gray-400 dark:placeholder-gray-500
                    focus:outline-none focus:ring-2 focus:ring-pink-500 focus:border-transparent
                    ${
                      errors.email
                        ? 'border-red-300 dark:border-red-600'
                        : 'border-gray-300 dark:border-gray-600'
                    }
                  `}
                />
              </div>
              {errors.email && (
                <p className="mt-1 text-sm text-red-600 dark:text-red-400">
                  {errors.email.message}
                </p>
              )}
            </div>

            {/* Campo de Senha */}
            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2"
              >
                Senha
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  {...register('password')}
                  id="password"
                  type="password"
                  autoComplete="new-password"
                  placeholder="••••••••"
                  className={`
                    block w-full pl-10 pr-3 py-3 border rounded-lg
                    bg-white dark:bg-gray-700
                    text-gray-900 dark:text-white
                    placeholder-gray-400 dark:placeholder-gray-500
                    focus:outline-none focus:ring-2 focus:ring-pink-500 focus:border-transparent
                    ${
                      errors.password
                        ? 'border-red-300 dark:border-red-600'
                        : 'border-gray-300 dark:border-gray-600'
                    }
                  `}
                />
              </div>
              {errors.password && (
                <p className="mt-1 text-sm text-red-600 dark:text-red-400">
                  {errors.password.message}
                </p>
              )}
            </div>

            {/* Campo de Confirmação de Senha */}
            <div>
              <label
                htmlFor="confirmPassword"
                className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2"
              >
                Confirmar Senha
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  {...register('confirmPassword')}
                  id="confirmPassword"
                  type="password"
                  autoComplete="new-password"
                  placeholder="••••••••"
                  className={`
                    block w-full pl-10 pr-3 py-3 border rounded-lg
                    bg-white dark:bg-gray-700
                    text-gray-900 dark:text-white
                    placeholder-gray-400 dark:placeholder-gray-500
                    focus:outline-none focus:ring-2 focus:ring-pink-500 focus:border-transparent
                    ${
                      errors.confirmPassword
                        ? 'border-red-300 dark:border-red-600'
                        : 'border-gray-300 dark:border-gray-600'
                    }
                  `}
                />
              </div>
              {errors.confirmPassword && (
                <p className="mt-1 text-sm text-red-600 dark:text-red-400">
                  {errors.confirmPassword.message}
                </p>
              )}
            </div>

            {/* Botão de Submit */}
            <button
              type="submit"
              disabled={isSubmitting}
              className={`
                w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg
                font-semibold text-white
                transition-all duration-200
                ${
                  isSubmitting
                    ? 'bg-gray-400 cursor-not-allowed'
                    : 'bg-gradient-to-r from-pink-500 to-cyan-500 hover:from-pink-600 hover:to-cyan-600 shadow-lg hover:shadow-xl'
                }
              `}
            >
              {isSubmitting ? (
                <>
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Cadastrando...
                </>
              ) : (
                <>
                  <UserPlus className="w-5 h-5" />
                  Criar Conta
                </>
              )}
            </button>
          </form>

          {/* Link para Login */}
          <div className="mt-6 text-center">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Já tem uma conta?{' '}
              <Link
                to="/login"
                className="font-semibold text-pink-600 dark:text-pink-400 hover:text-pink-700 dark:hover:text-pink-300 transition-colors"
              >
                Faça login aqui
              </Link>
            </p>
          </div>
        </div>

        {/* Informações de Debug (remover em produção) */}
        <div className="mt-4 p-4 bg-gray-100 dark:bg-gray-700 rounded-lg text-xs text-gray-600 dark:text-gray-400">
          <p className="font-semibold mb-1">🔧 Informações de Debug:</p>
          <p>
            • Endpoint: <code className="bg-white dark:bg-gray-800 px-1 py-0.5 rounded">POST /api/auth/signup</code>
          </p>
          <p>
            • Body:{' '}
            <code className="bg-white dark:bg-gray-800 px-1 py-0.5 rounded">
              {'{ nome, email, password}'}
            </code>
          </p>
          <p>
            • Token salvo em: <code className="bg-white dark:bg-gray-800 px-1 py-0.5 rounded">localStorage.authToken</code>
          </p>
        </div>
      </div>
    </div>
  );
}
