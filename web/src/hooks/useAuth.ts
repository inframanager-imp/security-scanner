import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { useAuthStore } from '../store/authStore';
import { authApi } from '../api/auth';

export function useAuth() {
  const { user, accessToken, refreshToken, isAuthenticated, login, logout, setTokens } =
    useAuthStore();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const handleLogin = useCallback(
    async (email: string, password: string) => {
      const data = await authApi.login(email, password);
      login(data);
      navigate('/dashboard');
    },
    [login, navigate],
  );

  const handleLogout = useCallback(async () => {
    const token = refreshToken;
    logout();
    if (token) {
      try {
        await authApi.logout(token);
      } catch {
        // Ignore errors during logout
      }
    }
    navigate('/login');
  }, [logout, refreshToken, navigate]);

  const switchTenant = useCallback(
    async (tenantId: string) => {
      if (!refreshToken) return;
      const data = await authApi.switchTenant(tenantId, refreshToken);
      setTokens(data);
      // Every cached query belongs to the previous organization.
      queryClient.clear();
      navigate('/dashboard');
    },
    [refreshToken, setTokens, queryClient, navigate],
  );

  return {
    user,
    accessToken,
    isAuthenticated,
    login: handleLogin,
    logout: handleLogout,
    switchTenant,
  };
}
