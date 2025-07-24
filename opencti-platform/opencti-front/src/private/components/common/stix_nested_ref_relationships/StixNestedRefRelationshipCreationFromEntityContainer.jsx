import React from 'react';
import StixNestedRefRelationshipCreationFromEntity, { stixNestedRefRelationResolveTypes } from './StixNestedRefRelationshipCreationFromEntity';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const StixNestedRefRelationshipCreationFromEntityContainer = ({
  entityId,
  entityType,
  paginationOptions,
  targetStixCoreObjectTypes,
  variant,
}) => {
  console.log('entityType', entityType);
  const queryRef = useQueryLoading(stixNestedRefRelationResolveTypes, { type: entityType });
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inline} />}
        >
          <StixNestedRefRelationshipCreationFromEntity
            possibleTypesQueryRef={queryRef}
            entityId={entityId}
            entityType={entityType}
            paginationOptions={paginationOptions}
            targetStixCoreObjectTypes={targetStixCoreObjectTypes}
            variant={variant}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default StixNestedRefRelationshipCreationFromEntityContainer;
