import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerControlledDialType } from '@components/common/drawer/Drawer';
import { CaseRftEditionOverview_case$key } from '@components/cases/case_rfts/__generated__/CaseRftEditionOverview_case.graphql';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { CaseRftEditionContainerCaseQuery } from './__generated__/CaseRftEditionContainerCaseQuery.graphql';
import CaseRftEditionOverview from './CaseRftEditionOverview';

interface CaseRftEditionContainerProps {
  queryRef: PreloadedQuery<CaseRftEditionContainerCaseQuery>
  handleClose: () => void
  open?: boolean
  controlledDial?: DrawerControlledDialType
}

export const caseRftEditionQuery = graphql`
  query CaseRftEditionContainerCaseQuery($id: String!) {
    caseRft(id: $id) {
      ...CaseRftEditionOverview_case
      editContext {
        name
        focusOn
      }
    }
  }
`;

const CaseRftEditionContainer: FunctionComponent<CaseRftEditionContainerProps> = ({
  queryRef,
  handleClose,
  open,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const { caseRft } = usePreloadedQuery(caseRftEditionQuery, queryRef);
  if (caseRft === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t_i18n('Update a request for takedown')}
      context={caseRft?.editContext}
      onClose={handleClose}
      open={open}
      controlledDial={controlledDial}
    >
      {({ onClose }) => (
        <CaseRftEditionOverview
          caseRef={caseRft as CaseRftEditionOverview_case$key}
          context={caseRft?.editContext}
          enableReferences={useIsEnforceReference('Case-Rft')}
          handleClose={onClose}
        />
      )}
    </Drawer>
  );
};

export default CaseRftEditionContainer;
