import { stixNestedRefRelationshipCreationResolveQuery } from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreation';
import { ReadMoreOutlined } from '@mui/icons-material';
import React from 'react';
import {
  StixNestedRefRelationshipCreationResolveQuery,
} from '@components/common/stix_nested_ref_relationships/__generated__/StixNestedRefRelationshipCreationResolveQuery.graphql';
import { NodeObject } from 'react-force-graph-2d';
import StixNestedRefRelationshipCreationFromKnowledgeGraphContent
  from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromKnowledgeGraphContent';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import GraphToolbarItem from '../../../../components/graph/components/GraphToolbarItem';

interface StixNestedRefRelationshipCreationFromKnowledgeGraphProps {
  nestedRelationExist: boolean;
  openCreateNested: boolean;
  nestedEnabled: boolean;
  relationFromObjects: NodeObject[];
  relationToObjects: NodeObject[];
  handleSetNestedRelationExist: (val: boolean) => void;
  handleOpenCreateNested: () => void;
}

type DisabledNestedRelationshipCause = 'selection' | 'loading' | 'creating';

/** The tool while it cannot run, saying why: it stays in the keyboard path of the toolbar. */
const DisabledNestedRelationshipButton = ({ cause }: { cause: DisabledNestedRelationshipCause }) => {
  const { t_i18n } = useFormatter();
  const reasons: Record<DisabledNestedRelationshipCause, string> = {
    selection: t_i18n('Select the entities to link first'),
    loading: t_i18n('Checking the nested relationships these elements accept'),
    creating: t_i18n('A nested relationship is being created'),
  };
  return (
    <GraphToolbarItem
      title={t_i18n('Create a nested relationship')}
      color="primary"
      Icon={<ReadMoreOutlined />}
      disabledReason={reasons[cause]}
    />
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
  if (!queryRef) return <DisabledNestedRelationshipButton cause="loading" />;
  return (
    <React.Suspense fallback={<DisabledNestedRelationshipButton cause="loading" />}>
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
  if (!nestedEnabled || !from || !to) return <DisabledNestedRelationshipButton cause="selection" />;
  if (openCreateNested) return <DisabledNestedRelationshipButton cause="creating" />;
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
