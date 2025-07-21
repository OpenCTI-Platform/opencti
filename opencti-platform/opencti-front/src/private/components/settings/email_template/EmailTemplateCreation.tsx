import React, { FunctionComponent, useState } from 'react';
import { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { EmailTemplatesLinesPaginationQuery$variables } from '@components/settings/email_template/__generated__/EmailTemplatesLinesPaginationQuery.graphql';
import EmailTemplateFormDrawer from '@components/settings/email_template/EmailTemplateFormDrawer';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { insertNode } from '../../../../utils/store';

const CreateEmailTemplateControlledDial = (
  props: DrawerControlledDialProps,
) => (
  <CreateEntityControlledDial
    entityType='EmailTemplate'
    {...props}
  />
);

interface EmailTemplateCreationProps {
  paginationOptions: EmailTemplatesLinesPaginationQuery$variables;
}

const EmailTemplateCreation: FunctionComponent<EmailTemplateCreationProps> = ({
  paginationOptions,
}) => {
  const [drawerOpen, setDrawerOpen] = useState(false);

  const updater = (store: RecordSourceSelectorProxy, rootField: string) => {
    insertNode(
      store,
      'Pagination_emailTemplates',
      paginationOptions,
      rootField,
    );
  };

  return (
    <>
      <CreateEmailTemplateControlledDial
        onOpen={() => setDrawerOpen(true)}
      />
      <EmailTemplateFormDrawer
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        updater={updater}
      />
    </>
  );
};

export default EmailTemplateCreation;
