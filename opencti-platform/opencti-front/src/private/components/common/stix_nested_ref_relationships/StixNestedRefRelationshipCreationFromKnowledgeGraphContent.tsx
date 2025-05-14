import { IconButton, Tooltip } from '@mui/material';
import { ReadMoreOutlined } from '@mui/icons-material';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { stixNestedRefRelationshipCreationResolveQuery } from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreation';
import {
  StixNestedRefRelationshipCreationResolveQuery,
} from '@components/common/stix_nested_ref_relationships/__generated__/StixNestedRefRelationshipCreationResolveQuery.graphql';
import React, { FunctionComponent } from 'react';
import { useFormatter } from '../../../../components/i18n';

interface StixNestedRefRelationshipCreationFromKnowledgeGraphContentProps {
  queryRef: PreloadedQuery<StixNestedRefRelationshipCreationResolveQuery>,
  nestedRelationExist: boolean,
  handleSetNestedRelationExist: (val: boolean) => void,
  handleOpenCreateNested: () => void,
}

const StixNestedRefRelationshipCreationFromKnowledgeGraphContent: FunctionComponent<StixNestedRefRelationshipCreationFromKnowledgeGraphContentProps> = ({
  queryRef,
  nestedRelationExist,
  handleSetNestedRelationExist,
  handleOpenCreateNested,
}) => {
  const { t_i18n } = useFormatter();
  const { stixSchemaRefRelationships } = usePreloadedQuery<StixNestedRefRelationshipCreationResolveQuery>(
    stixNestedRefRelationshipCreationResolveQuery,
    queryRef,
  );

  if (stixSchemaRefRelationships) {
    const { from, to } = stixSchemaRefRelationships;
    if ((from && from.length > 0) || (to && to.length > 0)) {
      if (nestedRelationExist === false) handleSetNestedRelationExist(true);
    } else if (nestedRelationExist) handleSetNestedRelationExist(false);
  }

  return (
    <Tooltip title={t_i18n('Create a nested relationship')}>
      <span>
        <IconButton
          color="primary"
          onClick={() => handleOpenCreateNested()}
          disabled={!nestedRelationExist}
        >
          <ReadMoreOutlined />
        </IconButton>
      </span>
    </Tooltip>
  );
};

export default StixNestedRefRelationshipCreationFromKnowledgeGraphContent;
