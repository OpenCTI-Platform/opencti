import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import {
  SecurityCoverageEditionOverview_securityCoverage$key,
} from '@components/analyses/security_coverages/__generated__/SecurityCoverageEditionOverview_securityCoverage.graphql';
import { useFormatter } from '../../../../components/i18n';
import { SecurityCoverageEditionContainerQuery } from './__generated__/SecurityCoverageEditionContainerQuery.graphql';
import SecurityCoverageEditionOverview from './SecurityCoverageEditionOverview';
import Drawer, { DrawerControlledDialType } from '../../common/drawer/Drawer';

export const securityCoverageEditionContainerQuery = graphql`
  query SecurityCoverageEditionContainerQuery($id: String!) {
    securityCoverage(id: $id) {
      id
      ...SecurityCoverageEditionOverview_securityCoverage
      editContext {
        name
        focusOn
      }
    }
  }
`;

interface SecurityCoverageEditionContainerProps {
  handleClose: () => void;
  queryRef: PreloadedQuery<SecurityCoverageEditionContainerQuery>;
  open?: boolean;
  controlledDial?: DrawerControlledDialType;
}

const SecurityCoverageEditionContainer: FunctionComponent<SecurityCoverageEditionContainerProps> = ({
  handleClose,
  queryRef,
  open,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const { securityCoverage } = usePreloadedQuery(securityCoverageEditionContainerQuery, queryRef);
  return (
    <Drawer
      title={t_i18n('Update a security coverage')}
      context={securityCoverage?.editContext}
      onClose={handleClose}
      open={open}
      controlledDial={controlledDial}
    >
      <SecurityCoverageEditionOverview
        securityCoverage={securityCoverage as SecurityCoverageEditionOverview_securityCoverage$key}
        context={securityCoverage?.editContext}
      />
    </Drawer>
  );
};

export default SecurityCoverageEditionContainer;
