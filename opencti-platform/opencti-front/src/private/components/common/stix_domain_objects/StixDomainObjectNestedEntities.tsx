import React from 'react';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import StixNestedRefRelationshipCreationFromEntityContainer from '../stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntityContainer';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { StixDomainObjectNestedEntitiesLinesQuery, StixDomainObjectNestedEntitiesLinesQuery$variables } from './__generated__/StixDomainObjectNestedEntitiesLinesQuery.graphql';
import StixDomainObjectNestedEntitiesLines, { stixDomainObjectNestedEntitiesLinesQuery } from './StixDomainObjectNestedEntitiesLines';

interface StixDomainObjectNestedEntitiesProps {
  entityId: string;
  entityType: string;
}

const StixDomainObjectNestedEntities = ({
  entityId,
  entityType,
}: StixDomainObjectNestedEntitiesProps) => {
  const { t_i18n } = useFormatter();

  const paginationOptions: StixDomainObjectNestedEntitiesLinesQuery$variables = {
    fromOrToId: entityId,
    search: '',
    orderBy: null,
    orderMode: 'desc',
    count: 25,
  };

  const queryRef = useQueryLoading<StixDomainObjectNestedEntitiesLinesQuery>(
    stixDomainObjectNestedEntitiesLinesQuery,
    paginationOptions,
  );
  return (
    <div style={{ marginTop: 20 }}>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('Nested objects')}
      </Typography>
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
      <div className="clearfix" />
      <List style={{ marginTop: -10 }}>
        {queryRef && (
          <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
            <StixDomainObjectNestedEntitiesLines
              stixDomainObjectId={entityId}
              paginationOptions={paginationOptions}
              queryRef={queryRef}
            />
          </React.Suspense>
        )}
      </List>
    </div>
  );
};

export default StixDomainObjectNestedEntities;
