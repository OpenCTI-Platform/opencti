import React, { Suspense, useEffect } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link, useParams } from 'react-router';
import { useTheme } from '@mui/styles';
import { ArrowBackOutlined } from '@mui/icons-material';
import { Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import Card from '../../../../components/common/card/Card';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { fetchQuery } from '../../../../relay/environment';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { PATH_HUNT, PATH_HUNTS } from '../../common/routes/paths';
import { isTerminalHuntRun } from '../hunt-utils';
import useHuntEditRight from '../useHuntEditRight';
import HuntRun from './HuntRun';
import { RootHuntRunQuery } from './__generated__/RootHuntRunQuery.graphql';

const RUN_POLL_INTERVAL_MS = 5000;

const rootHuntRunQuery = graphql`
  query RootHuntRunQuery($huntId: String!, $runId: String!) {
    hunt(id: $huntId) {
      id
      name
      currentUserAccessRight
    }
    huntRun(id: $runId) {
      id
      hunt_id
      hunt_run_status
      created_at
      ...HuntRun_run
    }
    ...HuntRunResults_data @arguments(id: $runId)
  }
`;

interface RootHuntRunComponentProps {
  queryRef: PreloadedQuery<RootHuntRunQuery>;
  huntId: string;
  runId: string;
}

const RootHuntRunComponent = ({ queryRef, huntId, runId }: RootHuntRunComponentProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const data = usePreloadedQuery<RootHuntRunQuery>(rootHuntRunQuery, queryRef);
  const { hunt, huntRun } = data;
  const canEdit = useHuntEditRight(hunt?.currentUserAccessRight);
  const run = huntRun && huntRun.hunt_id === huntId ? huntRun : null;
  const polling = !!run && !isTerminalHuntRun(run.hunt_run_status);

  useEffect(() => {
    if (!polling) return undefined;
    const timer = setInterval(() => {
      fetchQuery(rootHuntRunQuery, { huntId, runId }).toPromise().catch(() => undefined);
    }, RUN_POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [huntId, runId, polling]);

  if (!hunt) {
    return <ErrorNotFound />;
  }
  const huntElements = [
    { label: t_i18n('Defense') },
    { label: t_i18n('Hunts'), link: PATH_HUNTS },
  ];
  if (!run) {
    return (
      <div data-testid="hunt-run-page">
        <Breadcrumbs elements={[...huntElements, { label: hunt.name, current: true }]} />
        <Card>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: theme.spacing(2), flexWrap: 'wrap' }}>
            <Text variant="content-compact" data-testid="hunt-run-not-found">{t_i18n('This run cannot be found')}</Text>
            <Button variant="secondary" component={Link} to={`${PATH_HUNT(huntId)}/runs`} startIcon={<ArrowBackOutlined fontSize="small" />} data-testid="hunt-run-back">
              {t_i18n('Back to the hunt')}
            </Button>
          </div>
        </Card>
      </div>
    );
  }
  const title = t_i18n('Run of {date}', { values: { date: fldt(run.created_at) } });
  return (
    <>
      <Breadcrumbs elements={[
        ...huntElements,
        { label: hunt.name, link: PATH_HUNT(huntId) },
        { label: title, current: true },
      ]}
      />
      <HuntRun data={run} results={data} huntId={huntId} huntName={hunt.name} title={title} canEdit={canEdit} />
    </>
  );
};

const RootHuntRun = () => {
  const { huntId, runId } = useParams() as { huntId: string; runId: string };
  const queryRef = useQueryLoading<RootHuntRunQuery>(rootHuntRunQuery, { huntId, runId });
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      {queryRef && <RootHuntRunComponent queryRef={queryRef} huntId={huntId} runId={runId} />}
    </Suspense>
  );
};

export default RootHuntRun;
