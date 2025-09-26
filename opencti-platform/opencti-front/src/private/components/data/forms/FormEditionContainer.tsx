import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import FormEdition from './FormEdition';
import { FormEditionContainerQuery } from './__generated__/FormEditionContainerQuery.graphql';
import { useFormatter } from '../../../../components/i18n';

export const formEditionContainerQuery = graphql`
  query FormEditionContainerQuery($id: ID!) {
    form(id: $id) {
      ...FormEditionFragment_form
    }
  }
`;

interface FormEditionContainerProps {
  queryRef: PreloadedQuery<FormEditionContainerQuery>;
  open: boolean;
  handleClose?: () => void;
}

const FormEditionContainer: FunctionComponent<FormEditionContainerProps> = ({
  queryRef,
  open,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();

  const { form } = usePreloadedQuery(formEditionContainerQuery, queryRef);

  if (!form) {
    return <div/>;
  }

  return (
    <Drawer
      title={t_i18n('Update a form')}
      variant={open == null ? DrawerVariant.update : undefined}
      onClose={handleClose}
      open={open}
    >
      {({ onClose }) => (
        <FormEdition
          form={form}
          handleClose={onClose}
        />
      )}
    </Drawer>
  );
};

export default FormEditionContainer;
