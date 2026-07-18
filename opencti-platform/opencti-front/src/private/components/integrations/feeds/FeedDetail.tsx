import React, { Suspense, useEffect } from 'react';
import { Navigate, useParams } from 'react-router-dom';
import { graphql, useQueryLoader, usePreloadedQuery } from 'react-relay';
import type { GraphQLTaggedNode, PreloadedQuery } from 'react-relay';
import type { OperationType } from 'relay-runtime';
import { Box, Grid2 as Grid, Stack, Tooltip, Typography } from '@mui/material';
import { alpha, useTheme } from '@mui/material/styles';
import SyncPopover from '@components/data/sync/SyncPopover';
import IngestionRssPopover from '@components/data/ingestionRss/IngestionRssPopover';
import IngestionTaxiiPopover from '@components/data/ingestionTaxii/IngestionTaxiiPopover';
import IngestionTaxiiCollectionPopover from '@components/data/ingestionTaxiiCollection/IngestionTaxiiCollectionPopover';
import IngestionCsvPopover from '@components/data/ingestionCsv/IngestionCsvPopover';
import IngestionJsonPopover from '@components/data/ingestionJson/IngestionJsonPopover';
import FormView from '@components/data/forms/view/FormView';
import { BuiltInIntegrationKind, getBuiltInIntegration, isBuiltInIntegrationKind } from '@components/integrations/available/builtInIntegrations';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ItemBoolean from '../../../../components/ItemBoolean';
import ItemCopy from '../../../../components/ItemCopy';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import PageContainer from '../../../../components/PageContainer';
import Card from '../../../../components/common/card/Card';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';

const feedDetailSyncQuery = graphql`
  query FeedDetailSyncQuery($id: String!) {
    synchronizer(id: $id) {
      id
      name
      uri
      stream_id
      running
      current_state_date
      listen_deletion
      no_dependencies
      ssl_verify
      synchronized
      queue_messages
      user {
        id
        name
      }
    }
  }
`;

const feedDetailRssQuery = graphql`
  query FeedDetailRssQuery($id: String!) {
    ingestionRss(id: $id) {
      id
      name
      description
      uri
      scheduling_period
      report_types
      ingestion_running
      current_state_date
      last_execution_date
      ssl_verify
      created_at
      updated_at
      user {
        id
        name
      }
    }
  }
`;

const feedDetailTaxiiQuery = graphql`
  query FeedDetailTaxiiQuery($id: String!) {
    ingestionTaxii(id: $id) {
      id
      name
      description
      uri
      collection
      version
      authentication_type
      scheduling_period
      added_after_start
      current_state_cursor
      ingestion_running
      last_execution_date
      confidence_to_score
      ssl_verify
      created_at
      updated_at
      user {
        id
        name
      }
    }
  }
`;

const feedDetailTaxiiPushQuery = graphql`
  query FeedDetailTaxiiPushQuery($id: String!) {
    ingestionTaxiiCollection(id: $id) {
      id
      name
      description
      ingestion_running
      confidence_to_score
      created_at
      updated_at
      user {
        id
        name
      }
    }
  }
`;

const feedDetailCsvQuery = graphql`
  query FeedDetailCsvQuery($id: String!) {
    ingestionCsv(id: $id) {
      id
      name
      description
      uri
      csv_mapper_type
      authentication_type
      scheduling_period
      ingestion_running
      current_state_hash
      current_state_date
      last_execution_date
      ssl_verify
      created_at
      updated_at
      user {
        id
        name
      }
    }
  }
`;

const feedDetailJsonQuery = graphql`
  query FeedDetailJsonQuery($id: String!) {
    ingestionJson(id: $id) {
      id
      name
      description
      uri
      verb
      scheduling_period
      ingestion_running
      last_execution_date
      ssl_verify
      created_at
      updated_at
      user {
        id
        name
      }
    }
  }
`;

// Broad node shape covering every feed kind; each query only fills the fields
// relevant to its kind.
export interface FeedDetailNode {
  id: string;
  name: string;
  description?: string | null;
  uri?: string | null;
  stream_id?: string | null;
  collection?: string | null;
  version?: string | null;
  verb?: string | null;
  csv_mapper_type?: string | null;
  authentication_type?: string | null;
  scheduling_period?: string | null;
  report_types?: readonly string[] | null;
  running?: boolean | null;
  ingestion_running?: boolean | null;
  listen_deletion?: boolean | null;
  no_dependencies?: boolean | null;
  synchronized?: boolean | null;
  confidence_to_score?: boolean | null;
  ssl_verify?: boolean | null;
  queue_messages?: number | null;
  added_after_start?: string | null;
  current_state_date?: string | null;
  current_state_cursor?: string | null;
  current_state_hash?: string | null;
  last_execution_date?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  user?: { readonly id: string; readonly name: string } | null;
}

type FeedKind = Exclude<BuiltInIntegrationKind, 'form'>;

const FEED_QUERIES: Record<FeedKind, { query: GraphQLTaggedNode; rootField: string }> = {
  sync: { query: feedDetailSyncQuery, rootField: 'synchronizer' },
  rss: { query: feedDetailRssQuery, rootField: 'ingestionRss' },
  taxii: { query: feedDetailTaxiiQuery, rootField: 'ingestionTaxii' },
  'taxii-push': { query: feedDetailTaxiiPushQuery, rootField: 'ingestionTaxiiCollection' },
  csv: { query: feedDetailCsvQuery, rootField: 'ingestionCsv' },
  json: { query: feedDetailJsonQuery, rootField: 'ingestionJson' },
};

const noop = () => {};

interface FeedActionsPopoverProps {
  kind: FeedKind;
  node: FeedDetailNode;
}

// Reuses the existing per-kind popovers: update drawer, start/stop, export
// and delete, with all their store wiring.
const FeedActionsPopover = ({ kind, node }: FeedActionsPopoverProps) => {
  const running = kind === 'sync' ? !!node.running : !!node.ingestion_running;
  switch (kind) {
    case 'sync':
      return <SyncPopover syncId={node.id} running={running} paginationOptions={{}} />;
    case 'rss':
      return <IngestionRssPopover ingestionRssId={node.id} running={running} paginationOptions={{}} />;
    case 'taxii':
      return <IngestionTaxiiPopover ingestionTaxiiId={node.id} running={running} setStateValue={noop} />;
    case 'taxii-push':
      return <IngestionTaxiiCollectionPopover ingestionTaxiiId={node.id} running={running} />;
    case 'csv':
      return <IngestionCsvPopover ingestionCsvId={node.id} running={running} setStateHash={noop} />;
    case 'json':
    default:
      return <IngestionJsonPopover ingestionJsonId={node.id} running={running} />;
  }
};

interface DetailFieldProps {
  label: string;
  children: React.ReactNode;
}

const DetailField = ({ label, children }: DetailFieldProps) => {
  const theme = useTheme();
  return (
    <Grid size={{ xs: 6, md: 4 }}>
      <Typography
        sx={{
          fontFamily: theme.typography.h1.fontFamily,
          fontSize: 11,
          fontWeight: 600,
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
          color: theme.palette.text.secondary,
          marginBottom: 0.5,
        }}
      >
        {label}
      </Typography>
      <Typography component="div" variant="body2" sx={{ wordBreak: 'break-all' }}>
        {children}
      </Typography>
    </Grid>
  );
};

interface FeedDetailContentProps {
  kind: FeedKind;
  queryRef: PreloadedQuery<OperationType>;
}

const FeedDetailContent = ({ kind, queryRef }: FeedDetailContentProps) => {
  const { t_i18n, nsdt, n } = useFormatter();
  const theme = useTheme();
  const { setTitle } = useConnectedDocumentModifier();
  const definition = getBuiltInIntegration(kind);

  const data = usePreloadedQuery(FEED_QUERIES[kind].query, queryRef) as Record<string, FeedDetailNode | null>;
  const node = data[FEED_QUERIES[kind].rootField];

  if (!node || !definition) return <ErrorNotFound />;

  setTitle(`${node.name} | ${t_i18n('Integrations')}`);

  const running = kind === 'sync' ? !!node.running : !!node.ingestion_running;
  const Icon = definition.icon;

  return (
    <PageContainer withGap>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Integrations') },
          { label: t_i18n('Deployed'), link: '/dashboard/integrations/deployed' },
          { label: node.name, current: true },
        ]}
        noMargin
      />

      <Box
        sx={{
          position: 'relative',
          overflow: 'hidden',
          borderRadius: 1,
          border: `1px solid ${alpha(theme.palette.text.primary, 0.08)}`,
          backgroundColor: theme.palette.background.paper,
          padding: 3,
        }}
      >
        <Stack direction="row" gap={2} alignItems="flex-start">
          <Box
            sx={{
              height: 64,
              width: 64,
              flexShrink: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: 1,
              border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
              backgroundColor: alpha(theme.palette.primary.main, 0.08),
            }}
          >
            <Icon sx={{ fontSize: 32, color: theme.palette.primary.main }} />
          </Box>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography
              variant="body2"
              sx={{
                color: theme.palette.primary.main,
                fontSize: 12,
                fontWeight: 500,
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
              }}
            >
              {`${t_i18n('Built-in')} - ${t_i18n(definition.label)}`}
            </Typography>
            <Stack direction="row" alignItems="center" gap={1.5}>
              <Typography variant="h1" sx={{ fontSize: 22, fontWeight: 700 }}>
                {node.name}
              </Typography>
              <ItemBoolean
                status={running}
                label={running ? t_i18n('Active') : t_i18n('Inactive')}
              />
            </Stack>
            {node.description && (
              <Typography variant="body2" sx={{ color: theme.palette.text.secondary, marginTop: 0.5, maxWidth: 720 }}>
                {node.description}
              </Typography>
            )}
          </Box>
          <FeedActionsPopover kind={kind} node={node} />
        </Stack>
      </Box>

      <Grid container spacing={3}>
        <Grid size={{ xs: 12, md: 7 }}>
          <Card title={t_i18n('Configuration')}>
            <Grid container spacing={3}>
              {node.uri && (
                <DetailField label={t_i18n('URL')}>
                  <Tooltip title={node.uri}>
                    <span><ItemCopy content={node.uri} /></span>
                  </Tooltip>
                </DetailField>
              )}
              {node.stream_id && (
                <DetailField label={t_i18n('Stream ID')}>
                  <ItemCopy content={node.stream_id} />
                </DetailField>
              )}
              {node.collection && (
                <DetailField label={t_i18n('Collection')}>
                  {node.collection}
                </DetailField>
              )}
              {node.version && (
                <DetailField label={t_i18n('TAXII version')}>
                  {node.version}
                </DetailField>
              )}
              {node.verb && (
                <DetailField label={t_i18n('HTTP verb')}>
                  {node.verb.toUpperCase()}
                </DetailField>
              )}
              {node.csv_mapper_type && (
                <DetailField label={t_i18n('CSV mapper type')}>
                  {node.csv_mapper_type}
                </DetailField>
              )}
              {node.authentication_type && (
                <DetailField label={t_i18n('Authentication type')}>
                  {node.authentication_type}
                </DetailField>
              )}
              {node.scheduling_period != null && (
                <DetailField label={t_i18n('Scheduling period')}>
                  <FieldOrEmpty source={node.scheduling_period}>{node.scheduling_period}</FieldOrEmpty>
                </DetailField>
              )}
              {(node.report_types?.length ?? 0) > 0 && (
                <DetailField label={t_i18n('Report types')}>
                  {(node.report_types ?? []).join(', ')}
                </DetailField>
              )}
              <DetailField label={t_i18n('User responsible for data creation')}>
                <FieldOrEmpty source={node.user?.name}>{node.user?.name}</FieldOrEmpty>
              </DetailField>
              {node.ssl_verify != null && (
                <DetailField label={t_i18n('Verify SSL certificate')}>
                  <ItemBoolean status={!!node.ssl_verify} label={node.ssl_verify ? t_i18n('Yes') : t_i18n('No')} />
                </DetailField>
              )}
              {node.listen_deletion != null && (
                <DetailField label={t_i18n('Take deletions into account')}>
                  <ItemBoolean status={!!node.listen_deletion} label={node.listen_deletion ? t_i18n('Yes') : t_i18n('No')} />
                </DetailField>
              )}
              {node.no_dependencies != null && (
                <DetailField label={t_i18n('Do not insert dependencies')}>
                  <ItemBoolean status={!!node.no_dependencies} label={node.no_dependencies ? t_i18n('Yes') : t_i18n('No')} />
                </DetailField>
              )}
              {node.synchronized != null && (
                <DetailField label={t_i18n('Use perfect synchronization')}>
                  <ItemBoolean status={!!node.synchronized} label={node.synchronized ? t_i18n('Yes') : t_i18n('No')} />
                </DetailField>
              )}
              {node.confidence_to_score != null && (
                <DetailField label={t_i18n('Copy confidence level to OpenCTI scores for indicators')}>
                  <ItemBoolean status={!!node.confidence_to_score} label={node.confidence_to_score ? t_i18n('Yes') : t_i18n('No')} />
                </DetailField>
              )}
            </Grid>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, md: 5 }}>
          <Card title={t_i18n('Activity')}>
            <Grid container spacing={3}>
              {node.queue_messages != null && (
                <DetailField label={t_i18n('Queued bundles')}>
                  {n(node.queue_messages)}
                </DetailField>
              )}
              {node.last_execution_date !== undefined && (
                <DetailField label={t_i18n('Last run')}>
                  <FieldOrEmpty source={node.last_execution_date}>{nsdt(node.last_execution_date)}</FieldOrEmpty>
                </DetailField>
              )}
              {node.current_state_date !== undefined && (
                <DetailField label={t_i18n('Current state')}>
                  <FieldOrEmpty source={node.current_state_date}>{nsdt(node.current_state_date)}</FieldOrEmpty>
                </DetailField>
              )}
              {node.current_state_cursor !== undefined && (
                <DetailField label={t_i18n('Current state cursor')}>
                  <FieldOrEmpty source={node.current_state_cursor}>{node.current_state_cursor}</FieldOrEmpty>
                </DetailField>
              )}
              {node.current_state_hash !== undefined && (
                <DetailField label={t_i18n('Current state hash')}>
                  <FieldOrEmpty source={node.current_state_hash}>{node.current_state_hash}</FieldOrEmpty>
                </DetailField>
              )}
              {node.added_after_start !== undefined && (
                <DetailField label={t_i18n('Import from date')}>
                  <FieldOrEmpty source={node.added_after_start}>{nsdt(node.added_after_start)}</FieldOrEmpty>
                </DetailField>
              )}
              {node.created_at && (
                <DetailField label={t_i18n('Creation date')}>
                  {nsdt(node.created_at)}
                </DetailField>
              )}
              {node.updated_at && (
                <DetailField label={t_i18n('Modification date')}>
                  {nsdt(node.updated_at)}
                </DetailField>
              )}
            </Grid>
          </Card>
        </Grid>
      </Grid>
    </PageContainer>
  );
};

interface FeedDetailLoaderProps {
  kind: FeedKind;
  feedId: string;
}

const FeedDetailLoader = ({ kind, feedId }: FeedDetailLoaderProps) => {
  const { query } = FEED_QUERIES[kind];
  const [queryRef, loadQuery] = useQueryLoader(query);

  useEffect(() => {
    loadQuery({ id: feedId }, { fetchPolicy: 'store-and-network' });
  }, [feedId]);

  if (!queryRef) {
    return <Loader variant={LoaderVariant.container} />;
  }

  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <FeedDetailContent kind={kind} queryRef={queryRef} />
    </Suspense>
  );
};

// Detail page of a deployed built-in feed instance. Form intakes reuse the
// full-featured form view; other kinds get the generic overview.
const FeedDetail = () => {
  const { feedKind, feedId } = useParams();

  if (!feedKind || !feedId || !isBuiltInIntegrationKind(feedKind)) {
    return <Navigate to="/dashboard/integrations/deployed" replace={true} />;
  }

  if (feedKind === 'form') {
    return <FormView formId={feedId} />;
  }

  return <FeedDetailLoader key={`${feedKind}-${feedId}`} kind={feedKind} feedId={feedId} />;
};

export default FeedDetail;
