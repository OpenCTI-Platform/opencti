import React, { type ReactNode } from 'react';
import { Button, Card, CardContent, CardFooter, CardHeader, CardTitle, Text, Thumbnail } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { useHubEntry } from './HubEntryContext';

interface HubFirstUseProps {
  /** The one primary action that fills the entry ("Plan a hunt"). */
  action?: ReactNode;
  /** The page of the entry on https://docs.opencti.io. */
  documentationUrl?: string;
}

/**
 * The first-use state of a Defense area or a Curation tab: its name and the question it answers, both
 * from its registry entry, with its primary action and its documentation. Every entry explains itself
 * the same way; the entry decides when it has nothing to show yet.
 */
const HubFirstUse = ({ action, documentationUrl }: HubFirstUseProps) => {
  const { t_i18n } = useFormatter();
  const entry = useHubEntry();
  if (!entry) {
    return null;
  }
  return (
    <Card data-testid="hub-first-use">
      <CardHeader icon={entry.icon ? <Thumbnail>{entry.icon}</Thumbnail> : undefined} action={action}>
        <CardTitle>{t_i18n(entry.label)}</CardTitle>
      </CardHeader>
      {entry.description && (
        <CardContent clamp={0}>
          <Text variant="content-base">{t_i18n(entry.description)}</Text>
        </CardContent>
      )}
      {documentationUrl && (
        <CardFooter>
          <Button priority="tertiary" size="sm" asChild>
            <a href={documentationUrl} target="_blank" rel="noreferrer">{t_i18n('Read the documentation')}</a>
          </Button>
        </CardFooter>
      )}
    </Card>
  );
};

export default HubFirstUse;
