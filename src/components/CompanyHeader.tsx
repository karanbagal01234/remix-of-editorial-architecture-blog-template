// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Building2, LogOut } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useCompany } from '@/context/CompanyContext';

interface CompanyHeaderProps {
  title?: string;
}

const CompanyHeader: React.FC<CompanyHeaderProps> = ({ title }) => {
  const navigate = useNavigate();
  const { company, logoutCompany } = useCompany();

  const handleLogout = async () => {
    await logoutCompany();
    navigate('/', { replace: true });
  };

  return (
    <header className="flex items-center justify-between p-4 border-b border-border bg-background/80 backdrop-blur-sm">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
          <Building2 className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h1 className="text-lg font-semibold text-foreground">
            {title || 'Company Portal'}
          </h1>
          {company?.companyName && (
            <p className="text-sm text-muted-foreground">{company.companyName}</p>
          )}
        </div>
      </div>
      
      <Button
        variant="ghost"
        size="sm"
        onClick={handleLogout}
        className="text-muted-foreground hover:text-foreground"
      >
        <LogOut className="w-4 h-4 mr-2" />
        Logout
      </Button>
    </header>
  );
};

export default CompanyHeader;
