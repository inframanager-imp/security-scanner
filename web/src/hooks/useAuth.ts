import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';
import { authApi } from '../api/auth';

export function useAuth() {
  const { user, accessToken, refreshToken, isAuthenticated, login, logout } =
    useAuthStore();
  const navigate = useNavigate();

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

  return {
    user,
    accessToken,
    isAuthenticated,
    login: handleLogin,
    logout: handleLogout,
  };
}
