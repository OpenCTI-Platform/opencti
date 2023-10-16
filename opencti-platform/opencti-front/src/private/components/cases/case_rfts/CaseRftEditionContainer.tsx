import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { CaseRftEditionContainerCaseQuery } from './__generated__/CaseRftEditionContainerCaseQuery.graphql';
import CaseRftEditionOverview from './CaseRftEditionOverview';

interface CaseRftEditionContainerProps {
  queryRef: PreloadedQuery<CaseRftEditionContainerCaseQuery>
  handleClose: () => void
  open?: boolean
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

const CaseRftEditionContainer: FunctionComponent<CaseRftEditionContainerProps> = ({ queryRef, handleClose, open }) => {
  const { t } = useFormatter();
  const { caseRft } = usePreloadedQuery(caseRftEditionQuery, queryRef);
  if (caseRft === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t('Update a request for takedown')}
      variant={open == null ? DrawerVariant.update : undefined}
      context={caseRft.editContext}
      onClose={handleClose}
      open={open}
    >
      {({ onClose }) => (
        <CaseRftEditionOverview
          caseRef={caseRft}
          context={caseRft.editContext}
          enableReferences={useIsEnforceReference('Case-Rft')}
          handleClose={onClose}
        />
      )}
    </Drawer>
  );
};

export default CaseRftEditionContainer;
