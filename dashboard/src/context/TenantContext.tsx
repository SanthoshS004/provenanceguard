import React, { createContext, useContext, useState, useEffect } from 'react';
import { Project } from '../types';
import { getProjects } from '../services/api';
import { useAuth } from './AuthContext';

interface TenantContextType {
  selectedOrgId: string;
  selectedProjectId: string;
  projects: Project[];
  setSelectedOrgId: (id: string) => void;
  setSelectedProjectId: (id: string) => void;
  refreshProjects: () => Promise<void>;
}

const TenantContext = createContext<TenantContextType | undefined>(undefined);

export const TenantProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { session } = useAuth();
  const [selectedOrgId, setSelectedOrgId] = useState<string>('00000000-0000-0000-0000-000000000001');
  const [selectedProjectId, setSelectedProjectId] = useState<string>('');
  const [projects, setProjects] = useState<Project[]>([]);

  useEffect(() => {
    if (session?.organization_id) {
      setSelectedOrgId(session.organization_id);
    }
  }, [session]);

  const refreshProjects = async () => {
    if (!session?.token) return;
    try {
      const projs = await getProjects(session.token, selectedOrgId);
      setProjects(projs);
      if (projs.length > 0 && !selectedProjectId) {
        setSelectedProjectId(projs[0].id);
      }
    } catch {
      setProjects([]);
    }
  };

  useEffect(() => {
    refreshProjects();
  }, [session, selectedOrgId]);

  return (
    <TenantContext.Provider
      value={{
        selectedOrgId,
        selectedProjectId,
        projects,
        setSelectedOrgId,
        setSelectedProjectId,
        refreshProjects,
      }}
    >
      {children}
    </TenantContext.Provider>
  );
};

export const useTenant = () => {
  const context = useContext(TenantContext);
  if (!context) {
    throw new Error('useTenant must be used within a TenantProvider');
  }
  return context;
};
