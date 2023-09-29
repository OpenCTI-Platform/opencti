import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { CaseIncidentEditionContainerCaseQuery } from './__generated__/CaseIncidentEditionContainerCaseQuery.graphql';
import CaseIncidentEditionOverview from './CaseIncidentEditionOverview';

interface CaseIncidentEditionContainerProps {
  queryRef: PreloadedQuery<CaseIncidentEditionContainerCaseQuery>
  handleClose: () => void
  open?: boolean
}

export const caseIncidentEditionQuery = graphql`
  query CaseIncidentEditionContainerCaseQuery($id: String!) {
    caseIncident(id: $id) {
      ...CaseIncidentEditionOverview_case
      editContext {
        name
        focusOn
      }
    }
  }
`;

const CaseIncidentEditionContainer: FunctionComponent<
CaseIncidentEditionContainerProps
> = ({ queryRef, handleClose, open }) => {
  const { t } = useFormatter();
  const { caseIncident } = usePreloadedQuery(caseIncidentEditionQuery, queryRef);
  if (caseIncident === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t('Update an incident response')}
      variant={open == null ? DrawerVariant.update : undefined}
      context={caseIncident.editContext}
      onClose={handleClose}
      open={open}
    >
      {({ onClose }) => (
        <CaseIncidentEditionOverview
          caseRef={caseIncident}
          context={caseIncident.editContext}
          enableReferences={useIsEnforceReference('Case-Incident')}
          handleClose={onClose}
        />
      )}
    </Drawer>
  );
};

export default CaseIncidentEditionContainer;
