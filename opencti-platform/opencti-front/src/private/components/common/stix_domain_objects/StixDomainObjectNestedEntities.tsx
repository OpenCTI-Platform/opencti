import React from 'react';
import List from '@mui/material/List';
import StixNestedRefRelationshipCreationFromEntityContainer from '../stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntityContainer';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { StixDomainObjectNestedEntitiesLinesQuery, StixDomainObjectNestedEntitiesLinesQuery$variables } from './__generated__/StixDomainObjectNestedEntitiesLinesQuery.graphql';
import StixDomainObjectNestedEntitiesLines, { stixDomainObjectNestedEntitiesLinesQuery } from './StixDomainObjectNestedEntitiesLines';
import Label from '../../../../components/common/label/Label';

interface StixDomainObjectNestedEntitiesProps {
  entityId: string;
  entityType: string;
}

const StixDomainObjectNestedEntities = ({
  entityId,
  entityType,
}: StixDomainObjectNestedEntitiesProps) => {
  const { t_i18n } = useFormatter();

  const paginationOptions = {
    fromOrToId: entityId,
    search: '',
    orderBy: null,
    orderMode: 'desc',
  };
  const queryPaginationOptions = { ...paginationOptions, count: 25 } as StixDomainObjectNestedEntitiesLinesQuery$variables;

  const queryRef = useQueryLoading<StixDomainObjectNestedEntitiesLinesQuery>(
    stixDomainObjectNestedEntitiesLinesQuery,
    queryPaginationOptions,
  );
  return (
    <div style={{ marginTop: 20 }}>
      <Label action={(
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 29 }} />}
        >
          <StixNestedRefRelationshipCreationFromEntityContainer
            paginationOptions={paginationOptions}
            entityId={entityId}
            variant="inLine"
            entityType={entityType}
          />
        </Security>
      )}
      >
        {t_i18n('Nested objects')}
      </Label>

      <List sx={{ py: 0 }}>
        {queryRef && (
          <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
            <StixDomainObjectNestedEntitiesLines
              stixDomainObjectId={entityId}
              paginationOptions={queryPaginationOptions}
              queryRef={queryRef}
            />
          </React.Suspense>
        )}
      </List>
    </div>
  );
};

export default StixDomainObjectNestedEntities;
