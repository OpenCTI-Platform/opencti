import React, { FunctionComponent } from 'react';
import StixNestedRefRelationshipCreationFromEntity, { stixNestedRefRelationResolveTypes } from './StixNestedRefRelationshipCreationFromEntity';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

interface StixNestedRefRelationshipCreationFromEntityContainerProps {
  entityId: string,
  entityType: string,
  // biome-ignore lint/suspicious/noExplicitAny: type unknown
  paginationOptions: any, // FIXME find the right type
  variant: string,
}

const StixNestedRefRelationshipCreationFromEntityContainer: FunctionComponent<StixNestedRefRelationshipCreationFromEntityContainerProps> = ({
  entityId,
  entityType,
  paginationOptions,
  variant,
}) => {
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
            variant={variant}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default StixNestedRefRelationshipCreationFromEntityContainer;
