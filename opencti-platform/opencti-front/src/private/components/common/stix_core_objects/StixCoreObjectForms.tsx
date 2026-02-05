import { StixCoreObjectFormsFormsQuery, StixCoreObjectFormsFormsQuery$variables } from '@components/common/stix_core_objects/__generated__/StixCoreObjectFormsFormsQuery.graphql';
import StixCoreObjectFormSelector from '@components/common/stix_core_objects/StixCoreObjectFormSelector';
import { AssignmentOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { FunctionComponent, Suspense, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import IconButton from '../../../../components/common/button/IconButton';
import { useFormatter } from '../../../../components/i18n';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import useGranted, { KNOWLEDGE_KNASKIMPORT } from '../../../../utils/hooks/useGranted';

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
            size="default"
            variant="secondary"
            value="formIntake"
            onClick={() => setIsFormSelectorOpen(true)}
          >
            <AssignmentOutlined color="primary" />
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
  const isGrantedAskImportInDraft = useGranted([], false, { capabilitiesInDraft: [KNOWLEDGE_KNASKIMPORT] });
  const currentAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const canDisplayButton = !draftContext || currentAccessRight.canEdit || isGrantedAskImportInDraft;

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
