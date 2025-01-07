import { ReactNode, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

interface EEGuardProps {
  redirect?: string
  children: ReactNode
}

const EEGuard = ({ redirect, children }: EEGuardProps) => {
  const navigate = useNavigate();
  const isEnterpriseEdition = useEnterpriseEdition();

  useEffect(() => {
    if (!isEnterpriseEdition) navigate(redirect ?? '/dashboard');
  }, [isEnterpriseEdition, redirect]);

  return isEnterpriseEdition ? children : null;
};

export default EEGuard;
