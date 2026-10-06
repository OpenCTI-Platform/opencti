import React, { type ReactNode } from 'react';
import { Button, Hero, HeroBody, HeroHeader, Text, Thumbnail } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { useHubEntry } from './HubEntryContext';

interface HubFirstUseProps {
  /** The one primary action that fills the entry. */
  action?: ReactNode;
  /** The page of the entry on https://docs.opencti.io. */
  documentationUrl?: string;
  /** What the entry needs before it shows anything (the integrations to set up, their permissions). */
  children?: ReactNode;
}

/**
 * The first-use state of a Defense area or a Curation tab: its name and the question it answers, both
 * from its registry entry, with its primary action and its documentation. Every entry explains itself
 * the same way; the entry decides when it has nothing to show yet.
 */
const HubFirstUse = ({ action, documentationUrl, children }: HubFirstUseProps) => {
  const { t_i18n } = useFormatter();
  const entry = useHubEntry();
  if (!entry) {
    return null;
  }
  return (
    <Hero data-testid="hub-first-use">
      <HeroHeader icon={entry.icon ? <Thumbnail>{entry.icon}</Thumbnail> : undefined} action={action}>
        <Text variant="title-md">{t_i18n(entry.label)}</Text>
      </HeroHeader>
      {(entry.description || documentationUrl || children) && (
        <HeroBody>
          {entry.description && <Text variant="content-base">{t_i18n(entry.description)}</Text>}
          {children}
          {documentationUrl && (
            <Button priority="tertiary" size="sm" asChild>
              <a href={documentationUrl} target="_blank" rel="noreferrer">{t_i18n('Read the documentation')}</a>
            </Button>
          )}
        </HeroBody>
      )}
    </Hero>
  );
};

export default HubFirstUse;
