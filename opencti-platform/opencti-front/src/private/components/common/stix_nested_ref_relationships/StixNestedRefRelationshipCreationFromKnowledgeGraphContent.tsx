import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { stixNestedRefRelationshipCreationResolveQuery } from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreation';
import {
  StixNestedRefRelationshipCreationResolveQuery,
} from '@components/common/stix_nested_ref_relationships/__generated__/StixNestedRefRelationshipCreationResolveQuery.graphql';
import React, { FunctionComponent } from 'react';
import IconButton from '@mui/material/IconButton';
import { ReadMoreOutlined } from '@mui/icons-material';

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
  const { stixSchemaRefRelationships } = usePreloadedQuery<StixNestedRefRelationshipCreationResolveQuery>(stixNestedRefRelationshipCreationResolveQuery, queryRef);
  if (stixSchemaRefRelationships) {
    const { from, to } = stixSchemaRefRelationships;
    if ((from && from.length > 0) || (to && to.length > 0)) {
      if (nestedRelationExist === false) handleSetNestedRelationExist(true);
    } else if (nestedRelationExist) handleSetNestedRelationExist(false);
  }
  return (
    <span>
      <IconButton
        color="primary"
        onClick={() => handleOpenCreateNested()}
        disabled={!nestedRelationExist}
        size="large"
      >
        <ReadMoreOutlined />
      </IconButton>
    </span>
  );
};

export default StixNestedRefRelationshipCreationFromKnowledgeGraphContent;
