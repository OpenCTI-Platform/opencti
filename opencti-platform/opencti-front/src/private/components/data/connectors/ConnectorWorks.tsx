import React, { FunctionComponent, useEffect } from 'react';
import { graphql, createRefetchContainer, RelayRefetchProp } from 'react-relay';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import { interval } from 'rxjs';
import makeStyles from '@mui/styles/makeStyles';
import ConnectorWorkLine from '@components/data/connectors/ConnectorWorkLine';
import { ConnectorWorksQuery$variables } from './__generated__/ConnectorWorksQuery.graphql';
import { ConnectorWorks_data$data } from './__generated__/ConnectorWorks_data.graphql';
import { useFormatter } from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';

const interval$ = interval(FIVE_SECONDS);

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  paper: {
    margin: '10px 0 20px 0',
    padding: '15px',
    borderRadius: 4,
    position: 'relative',
  },
}));

export const connectorWorksWorkDeletionMutation = graphql`
  mutation ConnectorWorksWorkDeletionMutation($id: ID!) {
    workEdit(id: $id) {
      delete
    }
  }
`;

export type WorkMessages = NonNullable<NonNullable<NonNullable<ConnectorWorks_data$data['works']>['edges']>[0]>['node']['errors'];

interface ConnectorWorksComponentProps {
  data: ConnectorWorks_data$data
  options: ConnectorWorksQuery$variables[]
  relay: RelayRefetchProp
  inProgress?: boolean
}

const ConnectorWorksComponent: FunctionComponent<ConnectorWorksComponentProps> = ({
  data,
  options,
  relay,
  inProgress,
}) => {
  const works = data.works?.edges ?? [];
  const { t_i18n } = useFormatter();
  const classes = useStyles();

  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch(options);
    });
    return () => subscription.unsubscribe();
  }, []);

  return (
    <>
      <Typography variant="h4" gutterBottom={true}>
        {inProgress ? t_i18n('In progress works') : t_i18n('Completed works')}{` (${works.length})`}
      </Typography>
      <div>
        {works.length === 0 && (
        <Paper
          classes={{ root: classes.paper }}
          variant="outlined"
        >
          <Typography align='center'>
            {t_i18n('No work')}
          </Typography>
        </Paper>
        )}
        {works.map((workEdge) => {
          const work = workEdge?.node;
          if (!work) return null;
          return (
            <Paper
              key={work.id}
              classes={{ root: classes.paper }}
              variant="outlined"
            >
              <ConnectorWorkLine
                workId={work.id}
                workName={work.name}
                workStatus={work.status}
                workReceivedTime={work.received_time}
                workEndTime={work.completed_time}
                workExpectedNumber={work.tracking?.import_processed_number}
                workProcessedNumber={work.tracking?.import_expected_number}
                workErrors={work.errors}
                readOnly
              />
            </Paper>
          );
        })}
      </div>
    </>
  );
};

export const connectorWorksQuery = graphql`
  query ConnectorWorksQuery(
    $count: Int
    $orderBy: WorksOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ConnectorWorks_data
      @arguments(
        count: $count
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

const ConnectorWorks = createRefetchContainer(
  ConnectorWorksComponent,
  {
    data: graphql`
      fragment ConnectorWorks_data on Query
      @argumentDefinitions(
        count: { type: "Int" }
        orderBy: { type: "WorksOrdering", defaultValue: timestamp }
        orderMode: { type: "OrderingMode", defaultValue: desc }
        filters: { type: "FilterGroup" }
      ) {
        works(
          first: $count
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) {
          edges {
            node {
              id
              name
              user {
                name
              }
              timestamp
              status
              event_source_id
              received_time
              processed_time
              completed_time
              tracking {
                import_expected_number
                import_processed_number
              }
              messages {
                timestamp
                message
                sequence
                source
              }
              errors {
                timestamp
                message
                sequence
                source
              }
            }
          }
        }
      }
    `,
  },
  connectorWorksQuery,
);

export default ConnectorWorks;
