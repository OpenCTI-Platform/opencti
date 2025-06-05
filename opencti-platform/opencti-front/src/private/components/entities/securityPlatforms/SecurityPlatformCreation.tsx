import { SecurityPlatformsPaginationQuery$variables } from '@components/entities/__generated__/SecurityPlatformsPaginationQuery.graphql';
import React, { FunctionComponent, useState } from 'react';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import SecurityPlatformCreationForm from '@components/entities/securityPlatforms/SecurityPlatformCreationForm';
import { useFormatter } from '../../../../components/i18n';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { insertNode } from '../../../../utils/store';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';

export const securityPlatformCreationMutation = graphql`
mutation SecurityPlatformCreationMutation($input: SecurityPlatformAddInput!) {
    securityPlatformAdd(input: $input) {
        ...SecurityPlatform_securityPlatform
    }
}
`;

interface SecurityPlatformCreationProps {
  paginationOptions: SecurityPlatformsPaginationQuery$variables
}

const SecurityPlatformCreation: FunctionComponent<SecurityPlatformCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);

  const updater = (store: RecordSourceSelectorProxy) => {
    insertNode(
      store,
      'Pagination_securityPlatforms',
      paginationOptions,
      'securityPlatformAdd',
    );
  };

  const CreateSecurityPlatformControlledDial = (
    props: DrawerControlledDialProps,
  ) => (
    <CreateEntityControlledDial entityType='SecurityPlatform' {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create a security platform')}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
      controlledDial={CreateSecurityPlatformControlledDial}
    >
      {({ onClose }) => (
        <SecurityPlatformCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
        />
      )}
    </Drawer>
  );
};

export default SecurityPlatformCreation;
