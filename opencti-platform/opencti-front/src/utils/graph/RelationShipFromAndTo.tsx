import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../components/i18n';
import useQueryLoading from '../hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../components/Loader';
import { RelationShipFromAndToQuery } from './__generated__/RelationShipFromAndToQuery.graphql';
import { truncate } from '../String';

const useStyles = makeStyles(() => ({
  label: {
    marginTop: '20px',
  },
}));

const relationShipFromAndToQuery = graphql`
  query RelationShipFromAndToQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      entity_type
      ... on StixDomainObject {
        created
      }
      ... on AttackPattern {
        name
      }
      ... on Campaign {
        name
      }
      ... on CourseOfAction {
        name
      }
      ... on Note {
        attribute_abstract
        content
      }
      ... on ObservedData {
        name
      }
      ... on Opinion {
        opinion
      }
      ... on Report {
        name
      }
      ... on Grouping {
        name
      }
      ... on Individual {
        name
      }
      ... on Organization {
        name
      }
      ... on Sector {
        name
      }
      ... on System {
        name
      }
      ... on Indicator {
        name
      }
      ... on Infrastructure {
        name
      }
      ... on IntrusionSet {
        name
      }
      ... on Position {
        name
      }
      ... on City {
        name
      }
      ... on AdministrativeArea {
        name
      }
      ... on Country {
        name
      }
      ... on Region {
        name
      }
      ... on Malware {
        name
      }
      ... on ThreatActor {
        name
      }
      ... on Tool {
        name
      }
      ... on Vulnerability {
        name
      }
      ... on Incident {
        name
      }
      ... on StixCyberObservable {
        observable_value
      }
      ... on StixFile {
        observableName: name
      }
      ... on Event {
        name
      }
      ... on Case {
        name
      }
      ... on Narrative {
        name
      }
      ... on DataComponent {
        name
      }
      ... on DataSource {
        name
      }
      ... on Language {
        name
      }
    }
  }
`;

interface RelationShipFromAndToComponentProps {
  queryRef: PreloadedQuery<RelationShipFromAndToQuery>;
  direction: string;
}
const RelationShipFromAndToComponent: FunctionComponent<
RelationShipFromAndToComponentProps
> = ({ queryRef, direction }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const entity = usePreloadedQuery<RelationShipFromAndToQuery>(
    relationShipFromAndToQuery,
    queryRef,
  );
  const { stixCoreObject } = entity;

  if (!stixCoreObject) {
    return <div />;
  }
  return (
    <div>
      <Typography variant="h3" gutterBottom={false} className={classes.label}>
        {t(direction)}
      </Typography>
      {truncate(stixCoreObject.name, 20)}
    </div>
  );
};

interface RelationShipFromAndToProps {
  id: string;
  direction: string;
  queryRef: PreloadedQuery<RelationShipFromAndToQuery>;
}

const RelationShipFromAndTo: FunctionComponent<
Omit<RelationShipFromAndToProps, 'queryRef'>
> = ({ id, direction }) => {
  const queryRef = useQueryLoading<RelationShipFromAndToQuery>(
    relationShipFromAndToQuery,
    { id },
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <RelationShipFromAndToComponent
        queryRef={queryRef}
        direction={direction}
      />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default RelationShipFromAndTo;
