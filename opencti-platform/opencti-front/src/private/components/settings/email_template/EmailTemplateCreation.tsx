import React, { FunctionComponent, useState } from 'react';
import { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { EmailTemplatesLinesPaginationQuery$variables } from '@components/settings/email_template/__generated__/EmailTemplatesLinesPaginationQuery.graphql';
import EmailTemplateFormDrawer from '@components/settings/email_template/EmailTemplateFormDrawer';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

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

  return (
    <>
      <CreateEmailTemplateControlledDial
        onOpen={() => setDrawerOpen(true)}
      />
      <EmailTemplateFormDrawer
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
      />
    </>
  );
};

export default EmailTemplateCreation;
