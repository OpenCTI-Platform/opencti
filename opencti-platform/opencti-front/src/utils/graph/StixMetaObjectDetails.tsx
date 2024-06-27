import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../components/i18n';
import useQueryLoading from '../hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../components/Loader';
import type { SelectedEntity } from './EntitiesDetailsRightBar';
import ErrorNotFound from '../../components/ErrorNotFound';
import { getMainRepresentative } from '../defaultRepresentatives';
import { truncate } from '../String';
import ItemCreators from '../../components/ItemCreators';
import { StixMetaObjectDetailsQuery } from './__generated__/StixMetaObjectDetailsQuery.graphql';
import ItemMarkings from '../../components/ItemMarkings';
import ItemEntityType from '../../components/ItemEntityType';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  label: {
    marginTop: '20px',
  },
}));

const stixMetaObjectDetailsQuery = graphql`
  query StixMetaObjectDetailsQuery($id: String!) {
    stixMetaObject(id: $id) {
      id
      entity_type
      parent_types
      created_at
      ... on Label {
        value
        color
        created_at
        creators {
          id
          name
        }
      }
      ... on MarkingDefinition {
        definition_type
        definition
        x_opencti_order
        x_opencti_color
        creators {
          id
          name
        }
      }
      ... on KillChainPhase {
        kill_chain_name
        phase_name
        creators {
          id
          name
        }
      }
      ... on ExternalReference {
        source_name
        creators {
          id
          name
        }
      }
    }
  }
`;

interface StixMetaObjectDetailsComponentProps {
  queryRef: PreloadedQuery<StixMetaObjectDetailsQuery>;
}

const StixMetaObjectDetailsComponent: FunctionComponent<
StixMetaObjectDetailsComponentProps
> = ({ queryRef }) => {
  const classes = useStyles();
  const { t_i18n, fldt } = useFormatter();
  const entity = usePreloadedQuery<StixMetaObjectDetailsQuery>(
    stixMetaObjectDetailsQuery,
    queryRef,
  );
  const { stixMetaObject } = entity;
  if (!stixMetaObject) {
    return <ErrorNotFound />;
  }
  return (
    <div>
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Value')}
      </Typography>
      {stixMetaObject.entity_type === 'Marking-Definition' ? (
        <Tooltip title={getMainRepresentative(stixMetaObject)}>
          <ItemMarkings
            markingDefinitions={[stixMetaObject]}
            limit={2}
          />
        </Tooltip>
      ) : (
        <Tooltip title={getMainRepresentative(stixMetaObject)}>
          <span>{truncate(getMainRepresentative(stixMetaObject), 40)}</span>
        </Tooltip>
      )}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Type')}
      </Typography>
      <ItemEntityType entityType={stixMetaObject.entity_type} />
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Platform creation date')}
      </Typography>
      {fldt(stixMetaObject.created_at)}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Creators')}
      </Typography>
      <ItemCreators creators={stixMetaObject.creators ?? []} />
    </div>
  );
};

interface StixMetaObjectDetailsProps {
  entity: SelectedEntity;
  queryRef: PreloadedQuery<StixMetaObjectDetailsQuery>;
}

const StixMetaObjectDetails: FunctionComponent<
Omit<StixMetaObjectDetailsProps, 'queryRef'>
> = ({ entity }) => {
  const queryRef = useQueryLoading<StixMetaObjectDetailsQuery>(
    stixMetaObjectDetailsQuery,
    {
      id: entity.id,
    },
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <StixMetaObjectDetailsComponent queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default StixMetaObjectDetails;
