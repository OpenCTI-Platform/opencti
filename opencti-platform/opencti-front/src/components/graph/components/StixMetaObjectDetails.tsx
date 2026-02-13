import React, { FunctionComponent } from 'react';
import Tooltip from '@mui/material/Tooltip';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../i18n';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../Loader';
import ErrorNotFound from '../../ErrorNotFound';
import { getMainRepresentative } from '../../../utils/defaultRepresentatives';
import { truncate } from '../../../utils/String';
import ItemCreators from '../../ItemCreators';
import { StixMetaObjectDetailsQuery } from './__generated__/StixMetaObjectDetailsQuery.graphql';
import ItemMarkings from '../../ItemMarkings';
import ItemEntityType from '../../ItemEntityType';
import { GraphNode } from '../graph.types';
import { Stack } from '@mui/material';
import Label from '@common/label/Label';

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
    <Stack gap={2}>
      <div>
        <Label>
          {t_i18n('Value')}
        </Label>
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
      </div>
      <div>
        <Label>
          {t_i18n('Type')}
        </Label>
        <ItemEntityType entityType={stixMetaObject.entity_type} />
      </div>
      <div>
        <Label>
          {t_i18n('Platform creation date')}
        </Label>
        {fldt(stixMetaObject.created_at)}
      </div>
      <div>
        <Label>
          {t_i18n('Creators')}
        </Label>
        <ItemCreators creators={stixMetaObject.creators ?? []} />
      </div>
    </Stack>
  );
};

interface StixMetaObjectDetailsProps {
  entity: GraphNode;
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
