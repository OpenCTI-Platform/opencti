import React, { FunctionComponent, Suspense, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { StixCoreObjectFormsFormsQuery, StixCoreObjectFormsFormsQuery$variables } from '@components/common/stix_core_objects/__generated__/StixCoreObjectFormsFormsQuery.graphql';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { Assignment } from '@mui/icons-material';
import StixCoreObjectFormSelector from '@components/common/stix_core_objects/StixCoreObjectFormSelector';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';

// region types
interface StixCoreObjectFormsProps {
  entityType: string;
}

interface StixCoreObjectFormsComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectFormsFormsQuery>;
}
// endregion

const stixCoreObjectFormsFormsQuery = graphql`
  query StixCoreObjectFormsFormsQuery($filters: FilterGroup) {
    forms(filters: $filters) {
      edges {
        node {
          id
          name
          description
          active
        }
      }
    }
  }
`;

const StixCoreObjectFormsComponent: FunctionComponent<StixCoreObjectFormsComponentProps> = ({ queryRef }) => {
  const { t_i18n } = useFormatter();
  const [isFormSelectorOpen, setIsFormSelectorOpen] = useState(false);
  const data = usePreloadedQuery(stixCoreObjectFormsFormsQuery, queryRef);
  const hasForms = (data?.forms?.edges?.length ?? 0) > 0;
  return (
    <>
      {hasForms && (
        <Tooltip title={t_i18n('Use a form to create')}>
          <IconButton
            onClick={() => setIsFormSelectorOpen(true)}
            color="primary"
            size="medium"
            style={{
              border: '1px solid',
              borderRadius: '4px',
              padding: '6px',
              marginLeft: '6px',
            }}
          >
            <Assignment />
          </IconButton>
        </Tooltip>
      )}
      <StixCoreObjectFormSelector data={data} open={isFormSelectorOpen} handleClose={() => setIsFormSelectorOpen(false)} />
    </>
  );
};

const StixCoreObjectForms: FunctionComponent<StixCoreObjectFormsProps> = ({ entityType }) => {
  const [queryRef, loadQuery] = useQueryLoader<StixCoreObjectFormsFormsQuery>(stixCoreObjectFormsFormsQuery);
  const formsPaginationOptions: StixCoreObjectFormsFormsQuery$variables = {
    filters: {
      mode: 'and',
      filters: [{ key: ['main_entity_type'], values: [entityType] }],
      filterGroups: [],
    },
  };
  useEffect(() => {
    loadQuery(formsPaginationOptions, { fetchPolicy: 'store-and-network' });
  }, []);
  return (
    <>
      {queryRef && (
        <Suspense>
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <StixCoreObjectFormsComponent queryRef={queryRef} />
          </Security>
        </Suspense>
      )}
    </>
  );
};

export default StixCoreObjectForms;
