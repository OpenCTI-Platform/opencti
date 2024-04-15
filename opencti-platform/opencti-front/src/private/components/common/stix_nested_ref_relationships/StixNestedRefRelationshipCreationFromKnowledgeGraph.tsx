import { stixNestedRefRelationshipCreationResolveQuery } from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreation';
import IconButton from '@mui/material/IconButton';
import { ReadMoreOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import React, { FunctionComponent } from 'react';
import {
  StixNestedRefRelationshipCreationResolveQuery$data,
} from '@components/common/stix_nested_ref_relationships/__generated__/StixNestedRefRelationshipCreationResolveQuery.graphql';
import { NodeObject } from 'react-force-graph-2d';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';

interface StixNestedRefRelationshipCreationFromKnowledgeGraphProps {
  nestedRelationExist: boolean,
  openCreateNested: boolean,
  nestedEnabled: boolean,
  relationFromObjects: NodeObject[],
  relationToObjects: NodeObject[],
  handleSetNestedRelationExist: (val: boolean) => void,
  handleOpenCreateNested: () => void,
}
const StixNestedRefRelationshipCreationFromKnowledgeGraph: FunctionComponent<StixNestedRefRelationshipCreationFromKnowledgeGraphProps> = ({
  nestedRelationExist,
  openCreateNested,
  nestedEnabled,
  relationFromObjects,
  relationToObjects,
  handleSetNestedRelationExist,
  handleOpenCreateNested,
}) => {
  const { t_i18n } = useFormatter();
  console.log('relation from', relationFromObjects);
  return (
    <Tooltip title={t_i18n('Create a nested relationship')}>
      <>
        {(nestedEnabled && relationFromObjects[0] && relationToObjects[0] && !openCreateNested) && (
        <QueryRenderer
          query={stixNestedRefRelationshipCreationResolveQuery}
          variables={{
            id: relationFromObjects[0].id,
            toType: relationToObjects[0].entity_type,
          }}
          render={({ props }: { props: StixNestedRefRelationshipCreationResolveQuery$data }) => {
            if (props && props.stixSchemaRefRelationships) {
              const { from, to } = props.stixSchemaRefRelationships;
              if ((from && from.length > 0) || (to && to.length > 0)) {
                if (nestedRelationExist === false) handleSetNestedRelationExist(true);
              } else if (nestedRelationExist) handleSetNestedRelationExist(false);
            }
          }}
        />)
                }
        <span>
          <IconButton
            color="primary"
            onClick={() => handleOpenCreateNested()}
            disabled={!nestedEnabled || !nestedRelationExist}
            size="large"
          >
            <ReadMoreOutlined />
          </IconButton>
        </span>
      </>
    </Tooltip>
  );
};

export default StixNestedRefRelationshipCreationFromKnowledgeGraph;
