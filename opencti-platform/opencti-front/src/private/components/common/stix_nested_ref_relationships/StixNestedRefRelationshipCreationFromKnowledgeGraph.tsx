import { stixNestedRefRelationshipCreationResolveQuery } from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreation';
import IconButton from '@common/button/IconButton';
import { ReadMoreOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import React from 'react';
import {
  StixNestedRefRelationshipCreationResolveQuery,
} from '@components/common/stix_nested_ref_relationships/__generated__/StixNestedRefRelationshipCreationResolveQuery.graphql';
import { NodeObject } from 'react-force-graph-2d';
import StixNestedRefRelationshipCreationFromKnowledgeGraphContent
  from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromKnowledgeGraphContent';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

interface StixNestedRefRelationshipCreationFromKnowledgeGraphProps {
  nestedRelationExist: boolean;
  openCreateNested: boolean;
  nestedEnabled: boolean;
  relationFromObjects: NodeObject[];
  relationToObjects: NodeObject[];
  handleSetNestedRelationExist: (val: boolean) => void;
  handleOpenCreateNested: () => void;
}

const DisabledNestedRelationshipButton = () => {
  const { t_i18n } = useFormatter();
  return (
    <Tooltip title={t_i18n('Create a nested relationship')}>
      <IconButton
        color="primary"
        disabled={true}
        aria-label={t_i18n('Create a nested relationship')}
      >
        <ReadMoreOutlined />
      </IconButton>
    </Tooltip>
  );
};

interface NestedRelationshipResolverProps {
  fromId: string;
  toType: string;
  nestedRelationExist: boolean;
  handleSetNestedRelationExist: (val: boolean) => void;
  handleOpenCreateNested: () => void;
}

/** Resolves which nested references the selection accepts; mounted only while there is one to resolve. */
const NestedRelationshipResolver = ({
  fromId,
  toType,
  nestedRelationExist,
  handleSetNestedRelationExist,
  handleOpenCreateNested,
}: NestedRelationshipResolverProps) => {
  const queryRef = useQueryLoading<StixNestedRefRelationshipCreationResolveQuery>(
    stixNestedRefRelationshipCreationResolveQuery,
    { id: fromId, toType },
  );
  if (!queryRef) return <DisabledNestedRelationshipButton />;
  return (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <StixNestedRefRelationshipCreationFromKnowledgeGraphContent
        queryRef={queryRef}
        nestedRelationExist={nestedRelationExist}
        handleSetNestedRelationExist={handleSetNestedRelationExist}
        handleOpenCreateNested={handleOpenCreateNested}
      />
    </React.Suspense>
  );
};

const StixNestedRefRelationshipCreationFromKnowledgeGraph = ({
  nestedRelationExist,
  openCreateNested,
  nestedEnabled,
  relationFromObjects,
  relationToObjects,
  handleSetNestedRelationExist,
  handleOpenCreateNested,
}: StixNestedRefRelationshipCreationFromKnowledgeGraphProps) => {
  const from = relationFromObjects[0];
  const to = relationToObjects[0];
  if (!nestedEnabled || !from || !to || openCreateNested) return <DisabledNestedRelationshipButton />;
  const fromId = from.id as string;
  const toType = to.entity_type as string;
  return (
    <NestedRelationshipResolver
      key={`${fromId}-${toType}`}
      fromId={fromId}
      toType={toType}
      nestedRelationExist={nestedRelationExist}
      handleSetNestedRelationExist={handleSetNestedRelationExist}
      handleOpenCreateNested={handleOpenCreateNested}
    />
  );
};

export default StixNestedRefRelationshipCreationFromKnowledgeGraph;
