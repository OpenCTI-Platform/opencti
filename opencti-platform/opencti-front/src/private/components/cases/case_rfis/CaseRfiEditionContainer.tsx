import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerControlledDialType, DrawerVariant } from '@components/common/drawer/Drawer';
import { CaseRfiEditionOverview_case$key } from '@components/cases/case_rfis/__generated__/CaseRfiEditionOverview_case.graphql';
import useHelper from 'src/utils/hooks/useHelper';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { CaseRfiEditionContainerCaseQuery } from './__generated__/CaseRfiEditionContainerCaseQuery.graphql';
import CaseRfiEditionOverview from './CaseRfiEditionOverview';

interface CaseRfiEditionContainerProps {
  queryRef: PreloadedQuery<CaseRfiEditionContainerCaseQuery>
  handleClose: () => void
  open?: boolean
  controlledDial?: DrawerControlledDialType
}

export const caseRfiEditionQuery = graphql`
  query CaseRfiEditionContainerCaseQuery($id: String!) {
    caseRfi(id: $id) {
      ...CaseRfiEditionOverview_case
      editContext {
        name
        focusOn
      }
    }
  }
`;

const CaseRfiEditionContainer: FunctionComponent<CaseRfiEditionContainerProps> = ({
  queryRef,
  handleClose,
  open,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const FABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { caseRfi } = usePreloadedQuery(caseRfiEditionQuery, queryRef);
  if (caseRfi === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t_i18n('Update a request for information')}
      variant={!FABReplaced && open == null ? DrawerVariant.update : undefined}
      context={caseRfi?.editContext}
      onClose={handleClose}
      open={open}
      controlledDial={FABReplaced ? controlledDial : undefined}
    >
      {({ onClose }) => (
        <CaseRfiEditionOverview
          caseRef={caseRfi as CaseRfiEditionOverview_case$key}
          context={caseRfi?.editContext}
          enableReferences={useIsEnforceReference('Case-Rfi')}
          handleClose={onClose}
        />
      )}
    </Drawer>
  );
};

export default CaseRfiEditionContainer;
