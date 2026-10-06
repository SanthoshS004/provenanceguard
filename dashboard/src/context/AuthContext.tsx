import React, { createContext, useContext, useState, useEffect } from 'react';
import { UserSession } from '../types';
import { issueDevToken, setApiInterceptors } from '../services/api';

interface AuthContextType {
  session: UserSession | null;
  isAuthenticated: boolean;
  loginWithDevToken: (orgId: string, role: string, projectId?: string) => Promise<string>;
  logout: () => void;
  toastMessage: string | null;
  clearToast: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // In-memory token storage only - No localStorage/sessionStorage long-lived API key storage
  const [session, setSession] = useState<UserSession | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const logout = () => {
    setSession(null);
  };

  const clearToast = () => {
    setToastMessage(null);
  };

  useEffect(() => {
    setApiInterceptors(
      () => {
        // Automatic session expiry redirect
        setSession(null);
        setToastMessage('Session expired or unauthorized. Please re-authenticate.');
      },
      (forbiddenMessage: string) => {
        // Non-disruptive 403 Forbidden notification toast
        setToastMessage(`Forbidden: ${forbiddenMessage}`);
      }
    );
  }, []);

  const loginWithDevToken = async (orgId: string, role: string, projectId?: string): Promise<string> => {
    try {
      const res = await issueDevToken({
        organization_id: orgId,
        role: role,
        project_id: projectId,
      });

      setSession({
        token: res.access_token,
        user_id: 'dev-user-01',
        organization_id: orgId,
        project_id: projectId,
        role: role,
        scopes: ['*'],
      });
      setToastMessage(null);
      return res.access_token;
    } catch (err: any) {
      setToastMessage(`Login Failed: ${err.message}`);
      throw err;
    }
  };

  return (
    <AuthContext.Provider
      value={{
        session,
        isAuthenticated: !!session,
        loginWithDevToken,
        logout,
        toastMessage,
        clearToast,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
