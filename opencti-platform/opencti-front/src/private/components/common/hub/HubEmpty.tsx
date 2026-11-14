import React from 'react';
import { Text } from '@filigran/design-system';
import PageContainer from '../../../../components/PageContainer';
import { useFormatter } from '../../../../components/i18n';
import HubBreadcrumbs from './HubBreadcrumbs';
import { type HubEntry, HubEntryContext } from './HubEntryContext';
import HubFirstUse from './HubFirstUse';

interface HubEmptyProps {
  /** The hub itself: its name, what it is for and its icon, as English source strings. */
  hub: HubEntry;
  /** The English source labels of the breadcrumb entries above the hub, if any. */
  parents?: string[];
  /** English source string: that the hub has no page yet and where its pages will appear. */
  message: string;
  /** The page of the hub on https://docs.opencti.io. */
  documentationUrl: string;
}

/**
 * The landing page of a hub while no entry is registered on the platform: the first-use state of the
 * hub as a whole, which names it, says what it is for and that its pages are not available yet.
 */
const HubEmpty = ({ hub, parents = [], message, documentationUrl }: HubEmptyProps) => {
  const { t_i18n } = useFormatter();
  return (
    <PageContainer withRightMenu={false}>
      <HubBreadcrumbs hub={hub.label} parents={parents} />
      <HubEntryContext.Provider value={hub}>
        <HubFirstUse documentationUrl={documentationUrl}>
          <Text variant="content-base" data-testid="hub-empty">{t_i18n(message)}</Text>
        </HubFirstUse>
      </HubEntryContext.Provider>
    </PageContainer>
  );
};

export default HubEmpty;
