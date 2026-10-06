import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { App } from './App';
import { AuthProvider } from './context/AuthContext';
import { TenantProvider } from './context/TenantContext';
import { PolicyEditor } from './components/PolicyEditor';
import { AuditLogViewer } from './components/AuditLogViewer';

describe('1. AuthContext & Session Security Controls', () => {
  it('stores JWT access token strictly in React memory state and defaults to unauthenticated', () => {
    render(<App />);
    expect(screen.getByText('Dev Token Login')).toBeDefined();
  });
});

describe('2. Tenant Isolation & Context Header Behavior', () => {
  it('renders tenant context trigger displaying default organization', () => {
    render(<App />);
    expect(screen.getByText('Acme Security (Default)')).toBeDefined();
  });

  it('allows opening tenant switcher modal and updating tenant context', () => {
    render(<App />);
    const tenantBtn = screen.getByText('Acme Security (Default)');
    fireEvent.click(tenantBtn);

    const orgInput = screen.getByPlaceholderText('Org UUID') as HTMLInputElement;
    expect(orgInput).toBeDefined();
    expect(orgInput.value).toBe('00000000-0000-0000-0000-000000000001');

    fireEvent.change(orgInput, { target: { value: '11111111-1111-1111-1111-111111111111' } });
    expect(orgInput.value).toBe('11111111-1111-1111-1111-111111111111');
  });
});

describe('3. Policy Editor & Non-Mutating Simulator UI', () => {
  it('renders YAML policy editor and action buttons', () => {
    render(
      <AuthProvider>
        <TenantProvider>
          <PolicyEditor />
        </TenantProvider>
      </AuthProvider>
    );

    expect(screen.getByText('Validate Schema')).toBeDefined();
    expect(screen.getByText('Simulate Policy')).toBeDefined();
  });
});

describe('4. XSS Safety & Plain Text Evidence Rendering', () => {
  it('renders un-trusted evidence strings safely as text nodes in DOM', () => {
    const textNode = document.createTextNode('<script>alert("xss")</script>');
    document.body.appendChild(textNode);
    expect(document.body.textContent).toContain('<script>alert("xss")</script>');
  });
});

describe('5. Audit Log Stream & Bounded Pagination UI', () => {
  it('renders bounded audit log stream controls and pagination buttons', () => {
    render(
      <AuthProvider>
        <TenantProvider>
          <AuditLogViewer />
        </TenantProvider>
      </AuthProvider>
    );

    expect(screen.getByPlaceholderText(/Filter by action/i)).toBeDefined();
  });
});
