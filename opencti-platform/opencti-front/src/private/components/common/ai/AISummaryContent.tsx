import React, { ReactNode } from 'react';
import { useFormatter } from '../../../../components/i18n';

interface AISummaryContentProps {
  loading: boolean;
  children?: ReactNode;
}

const AISummaryContent = ({ loading, children }: AISummaryContentProps) => {
  const { t_i18n } = useFormatter();
  return (
    <div aria-live="polite" role="status">
      {loading
        ? <span className="sr-only">{t_i18n('Loading AI summary...')}</span>
        : children
      }
    </div>
  );
};

export default AISummaryContent;
