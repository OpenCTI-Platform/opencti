import React, { ReactNode } from 'react';
import { useFormatter } from '../../../components/i18n';

/** The "Learn more" link of a hunting field or surface, opening its section of the documentation. */
export const HuntLearnMore = ({ href, testId }: { href: string; testId?: string }) => {
  const { t_i18n } = useFormatter();
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" data-testid={testId} style={{ whiteSpace: 'nowrap' }}>
      {t_i18n('Learn more')}
    </a>
  );
};

/** A help text followed by its "Learn more" link, for the helper text of a field. */
export const HuntHelp = ({ text, href }: { text: ReactNode; href: string }) => (
  <>
    {text}
    {' '}
    <HuntLearnMore href={href} />
  </>
);
