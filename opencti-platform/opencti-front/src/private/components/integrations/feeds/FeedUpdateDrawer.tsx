import React, { Suspense, useEffect } from 'react';
import { graphql, usePreloadedQuery, useQueryLoader } from 'react-relay';
import type { PreloadedQuery } from 'react-relay';
import SyncEdition from '@components/data/sync/SyncEdition';
import IngestionRssEdition from '@components/data/ingestionRss/IngestionRssEdition';
import IngestionTaxiiEditionContainer, { ingestionTaxiiEditionContainerQuery } from '@components/data/ingestionTaxii/IngestionTaxiiEditionContainer';
import IngestionTaxiiCollectionEdition from '@components/data/ingestionTaxiiCollection/IngestionTaxiiCollectionEdition';
import IngestionCsvEditionContainer, { ingestionCsvEditionContainerQuery } from '@components/data/ingestionCsv/IngestionCsvEditionContainer';
import IngestionJsonEditionContainer, { ingestionJsonEditionContainerQuery } from '@components/data/ingestionJson/IngestionJsonEditionContainer';
import FormEditionContainer, { formEditionContainerQuery } from '@components/data/forms/FormEditionContainer';
import { IngestionTaxiiEditionContainerQuery } from '@components/data/ingestionTaxii/__generated__/IngestionTaxiiEditionContainerQuery.graphql';
import { IngestionCsvEditionContainerQuery } from '@components/data/ingestionCsv/__generated__/IngestionCsvEditionContainerQuery.graphql';
import { IngestionJsonEditionContainerQuery } from '@components/data/ingestionJson/__generated__/IngestionJsonEditionContainerQuery.graphql';
import { FormEditionContainerQuery } from '@components/data/forms/__generated__/FormEditionContainerQuery.graphql';
import { FeedUpdateDrawerSyncQuery } from '@components/integrations/feeds/__generated__/FeedUpdateDrawerSyncQuery.graphql';
import { FeedUpdateDrawerRssQuery } from '@components/integrations/feeds/__generated__/FeedUpdateDrawerRssQuery.graphql';
import { FeedUpdateDrawerTaxiiPushQuery } from '@components/integrations/feeds/__generated__/FeedUpdateDrawerTaxiiPushQuery.graphql';
import { BuiltInIntegrationKind } from '@components/integrations/available/builtInIntegrations';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';

const feedUpdateDrawerSyncQuery = graphql`
  query FeedUpdateDrawerSyncQuery($id: String!) {
    synchronizer(id: $id) {
      id
      name
      uri
      stream_id
      listen_deletion
      no_dependencies
      ssl_verify
      synchronized
      current_state_date
      user {
        id
        name
      }
    }
  }
`;

const feedUpdateDrawerRssQuery = graphql`
  query FeedUpdateDrawerRssQuery($id: String!) {
    ingestionRss(id: $id) {
      id
      name
      uri
      ingestion_running
      current_state_date
      ...IngestionRssEdition_ingestionRss
    }
  }
`;

const feedUpdateDrawerTaxiiPushQuery = graphql`
  query FeedUpdateDrawerTaxiiPushQuery($id: String!) {
    ingestionTaxiiCollection(id: $id) {
      id
      name
      description
      ingestion_running
      ...IngestionTaxiiCollectionEdition_ingestionTaxii
    }
  }
`;

interface FeedUpdateDrawerProps {
  kind: BuiltInIntegrationKind;
  feedId: string;
  onClose: () => void;
}

interface KindUpdateProps {
  feedId: string;
  onClose: () => void;
}

const SyncUpdateContent = ({ queryRef, onClose }: { queryRef: PreloadedQuery<FeedUpdateDrawerSyncQuery>; onClose: () => void }) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(feedUpdateDrawerSyncQuery, queryRef);
  if (!data.synchronizer) return null;
  return (
    <Drawer
      title={t_i18n('Update an OpenCTI stream')}
      open={true}
      onClose={onClose}
    >
      <SyncEdition synchronizer={data.synchronizer} />
    </Drawer>
  );
};

const SyncUpdate = ({ feedId, onClose }: KindUpdateProps) => {
  const [queryRef, loadQuery] = useQueryLoader<FeedUpdateDrawerSyncQuery>(feedUpdateDrawerSyncQuery);
  useEffect(() => {
    loadQuery({ id: feedId }, { fetchPolicy: 'store-and-network' });
  }, [feedId]);
  if (!queryRef) return null;
  return (
    <Suspense fallback={null}>
      <SyncUpdateContent queryRef={queryRef} onClose={onClose} />
    </Suspense>
  );
};

const RssUpdateContent = ({ queryRef, onClose }: { queryRef: PreloadedQuery<FeedUpdateDrawerRssQuery>; onClose: () => void }) => {
  const data = usePreloadedQuery(feedUpdateDrawerRssQuery, queryRef);
  if (!data.ingestionRss) return null;
  return (
    <IngestionRssEdition
      ingestionRss={data.ingestionRss}
      handleClose={onClose}
      open={true}
    />
  );
};

const RssUpdate = ({ feedId, onClose }: KindUpdateProps) => {
  const [queryRef, loadQuery] = useQueryLoader<FeedUpdateDrawerRssQuery>(feedUpdateDrawerRssQuery);
  useEffect(() => {
    loadQuery({ id: feedId }, { fetchPolicy: 'store-and-network' });
  }, [feedId]);
  if (!queryRef) return null;
  return (
    <Suspense fallback={null}>
      <RssUpdateContent queryRef={queryRef} onClose={onClose} />
    </Suspense>
  );
};

const TaxiiPushUpdateContent = ({ queryRef, onClose }: { queryRef: PreloadedQuery<FeedUpdateDrawerTaxiiPushQuery>; onClose: () => void }) => {
  const data = usePreloadedQuery(feedUpdateDrawerTaxiiPushQuery, queryRef);
  if (!data.ingestionTaxiiCollection) return null;
  return (
    <IngestionTaxiiCollectionEdition
      ingestionTaxiiCollection={data.ingestionTaxiiCollection}
      handleClose={onClose}
      open={true}
    />
  );
};

const TaxiiPushUpdate = ({ feedId, onClose }: KindUpdateProps) => {
  const [queryRef, loadQuery] = useQueryLoader<FeedUpdateDrawerTaxiiPushQuery>(feedUpdateDrawerTaxiiPushQuery);
  useEffect(() => {
    loadQuery({ id: feedId }, { fetchPolicy: 'store-and-network' });
  }, [feedId]);
  if (!queryRef) return null;
  return (
    <Suspense fallback={null}>
      <TaxiiPushUpdateContent queryRef={queryRef} onClose={onClose} />
    </Suspense>
  );
};

const TaxiiUpdate = ({ feedId, onClose }: KindUpdateProps) => {
  const [queryRef, loadQuery] = useQueryLoader<IngestionTaxiiEditionContainerQuery>(ingestionTaxiiEditionContainerQuery);
  useEffect(() => {
    loadQuery({ id: feedId }, { fetchPolicy: 'store-and-network' });
  }, [feedId]);
  if (!queryRef) return null;
  return (
    <Suspense fallback={null}>
      <IngestionTaxiiEditionContainer
        queryRef={queryRef}
        open={true}
        handleClose={onClose}
      />
    </Suspense>
  );
};

const CsvUpdate = ({ feedId, onClose }: KindUpdateProps) => {
  const [queryRef, loadQuery] = useQueryLoader<IngestionCsvEditionContainerQuery>(ingestionCsvEditionContainerQuery);
  useEffect(() => {
    loadQuery({ id: feedId }, { fetchPolicy: 'store-and-network' });
  }, [feedId]);
  if (!queryRef) return null;
  return (
    <Suspense fallback={null}>
      <IngestionCsvEditionContainer
        queryRef={queryRef}
        open={true}
        handleClose={onClose}
      />
    </Suspense>
  );
};

const JsonUpdate = ({ feedId, onClose }: KindUpdateProps) => {
  const [queryRef, loadQuery] = useQueryLoader<IngestionJsonEditionContainerQuery>(ingestionJsonEditionContainerQuery);
  useEffect(() => {
    loadQuery({ id: feedId }, { fetchPolicy: 'store-and-network' });
  }, [feedId]);
  if (!queryRef) return null;
  return (
    <Suspense fallback={null}>
      <IngestionJsonEditionContainer
        queryRef={queryRef}
        open={true}
        handleClose={onClose}
      />
    </Suspense>
  );
};

const FormUpdate = ({ feedId, onClose }: KindUpdateProps) => {
  const [queryRef, loadQuery] = useQueryLoader<FormEditionContainerQuery>(formEditionContainerQuery);
  useEffect(() => {
    loadQuery({ id: feedId }, { fetchPolicy: 'store-and-network' });
  }, [feedId]);
  if (!queryRef) return null;
  return (
    <Suspense fallback={null}>
      <FormEditionContainer
        queryRef={queryRef}
        open={true}
        handleClose={onClose}
      />
    </Suspense>
  );
};

// Update drawer for a built-in feed instance, reusing each kind's existing
// edition components (same wiring as the legacy list popovers).
const FeedUpdateDrawer = ({ kind, feedId, onClose }: FeedUpdateDrawerProps) => {
  switch (kind) {
    case 'sync':
      return <SyncUpdate feedId={feedId} onClose={onClose} />;
    case 'rss':
      return <RssUpdate feedId={feedId} onClose={onClose} />;
    case 'taxii':
      return <TaxiiUpdate feedId={feedId} onClose={onClose} />;
    case 'taxii-push':
      return <TaxiiPushUpdate feedId={feedId} onClose={onClose} />;
    case 'csv':
      return <CsvUpdate feedId={feedId} onClose={onClose} />;
    case 'json':
      return <JsonUpdate feedId={feedId} onClose={onClose} />;
    case 'form':
    default:
      return <FormUpdate feedId={feedId} onClose={onClose} />;
  }
};

export default FeedUpdateDrawer;
