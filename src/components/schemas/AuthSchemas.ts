/**
 * Schemas de validação para autenticação (Login e Signup)
 * Usando Zod para validação type-safe
 */

import { z } from 'zod';

/**
 * Schema de validação para Login
 *
 * Valida:
 * - Email: deve ser válido
 * - Password: mínimo 6 caracteres
 */
export const loginSchema = z.object({
  email: z
    .string()
    .min(1, 'O e-mail é obrigatório')
    .email('E-mail inválido'),
  password: z
    .string()
    .min(6, 'A senha deve ter no mínimo 6 caracteres'),
});

/**
 * Type inference do schema de login
 */
export type LoginFormData = z.infer<typeof loginSchema>;

/**
 * Schema de validação para Signup/Cadastro
 *
 * Valida:
 * - Nome: mínimo 3 caracteres
 * - Email: deve ser válido
 * - Password: mínimo 6 caracteres
 * - ConfirmPassword: deve ser igual à senha
 * - Telefone: opcional, mas se fornecido deve ter 10-11 dígitos
 */
export const signupSchema = z
  .object({
    nome: z
      .string()
      .min(3, 'O nome completo é obrigatório (mínimo 3 caracteres)'),
    email: z
      .string()
      .min(1, 'O e-mail é obrigatório')
      .email('E-mail inválido'),
    password: z
      .string()
      .min(6, 'A senha deve ter no mínimo 6 caracteres'),
    confirmPassword: z
      .string()
      .min(6, 'A confirmação de senha deve ter no mínimo 6 caracteres'),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'As senhas não coincidem',
    path: ['confirmPassword'],
  });

/**
 * Type inference do schema de signup
 */
export type SignupFormData = z.infer<typeof signupSchema>;
