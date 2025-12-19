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
const StixNestedRefRelationshipCreationFromKnowledgeGraph = ({
  nestedRelationExist,
  openCreateNested,
  nestedEnabled,
  relationFromObjects,
  relationToObjects,
  handleSetNestedRelationExist,
  handleOpenCreateNested,
}: StixNestedRefRelationshipCreationFromKnowledgeGraphProps) => {
  const { t_i18n } = useFormatter();
  const queryRef = (nestedEnabled && relationFromObjects[0] && relationToObjects[0] && !openCreateNested)
    ? useQueryLoading<StixNestedRefRelationshipCreationResolveQuery>(
        stixNestedRefRelationshipCreationResolveQuery,
        {
          id: relationFromObjects[0].id as string,
          toType: relationToObjects[0].entity_type,
        },
      ) : undefined;
  return (
    <>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <StixNestedRefRelationshipCreationFromKnowledgeGraphContent
            queryRef={queryRef}
            nestedRelationExist={nestedRelationExist}
            handleSetNestedRelationExist={handleSetNestedRelationExist}
            handleOpenCreateNested={handleOpenCreateNested}
          />
        </React.Suspense>
      )
        : (
            <Tooltip title={t_i18n('Create a nested relationship')}>
              <span>
                <IconButton
                  color="primary"
                  disabled={true}
                >
                  <ReadMoreOutlined />
                </IconButton>
              </span>
            </Tooltip>
          )}
    </>
  );
};

export default StixNestedRefRelationshipCreationFromKnowledgeGraph;
