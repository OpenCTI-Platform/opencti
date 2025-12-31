import React, { FunctionComponent, Suspense, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { StixCoreObjectFormsFormsQuery, StixCoreObjectFormsFormsQuery$variables } from '@components/common/stix_core_objects/__generated__/StixCoreObjectFormsFormsQuery.graphql';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { AssignmentOutlined } from '@mui/icons-material';
import StixCoreObjectFormSelector from '@components/common/stix_core_objects/StixCoreObjectFormSelector';
import { useFormatter } from '../../../../components/i18n';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';

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
            style={{
              border: '1px solid',
              borderRadius: '4px',
              padding: '6px',
              marginLeft: '6px',
            }}
          >
            <AssignmentOutlined />
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
      filters: [{ key: ['main_entity_type'], values: [entityType] }, { key: ['active'], values: [true] }],
      filterGroups: [],
    },
  };
  useEffect(() => {
    loadQuery(formsPaginationOptions, { fetchPolicy: 'store-and-network' });
  }, []);

  // Remove create button in Draft context without the minimal right access "canEdit"
  const draftContext = useDraftContext();
  const currentAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const canDisplayButton = !draftContext || currentAccessRight.canEdit;

  return canDisplayButton && (
    <>
      {queryRef && (
        <Suspense>
          <StixCoreObjectFormsComponent queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default StixCoreObjectForms;
