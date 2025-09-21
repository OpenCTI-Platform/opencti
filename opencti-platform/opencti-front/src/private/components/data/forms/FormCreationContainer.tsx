import { graphql, PreloadedQuery, useFragment, usePreloadedQuery, useQueryLoader } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { FormEditionContainerQuery } from './__generated__/FormEditionContainerQuery.graphql';
import { formEditionContainerQuery } from './FormEditionContainer';
import { FormEditionFragment_form$data, FormEditionFragment_form$key } from './__generated__/FormEditionFragment_form.graphql';
import { FormLinesPaginationQuery$variables } from './__generated__/FormLinesPaginationQuery.graphql';
import FormCreation, { formCreationQuery } from './FormCreation';
import { FormCreationQuery } from './__generated__/FormCreationQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

export const formEditionFragment = graphql`
  fragment FormEditionFragment_form on Form {
    id
    name
    description
    form_schema
    active
  }
`;

interface FormCreationContainerProps {
  queryRef?: PreloadedQuery<FormEditionContainerQuery>;
  open?: boolean;
  handleClose?: () => void;
  onOpen?: () => void;
  paginationOptions?: FormLinesPaginationQuery$variables;
  triggerButton?: boolean;
  drawerSettings?: {
    title: string;
    button: string;
  };
}

const CreateFormControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType='Form'
    {...props}
  />
);

export const FormCreationContainer: FunctionComponent<FormCreationContainerProps> = ({
  queryRef,
  handleClose,
  open = false,
  paginationOptions,
  drawerSettings,
  triggerButton = true,
}) => {
  // Load the formCreationQuery for entity settings
  const [creationQueryRef, loadCreationQuery] = useQueryLoader<FormCreationQuery>(formCreationQuery);

  React.useEffect(() => {
    loadCreationQuery({}, { fetchPolicy: 'store-and-network' });
  }, []);

  // Get the form data for duplication if queryRef is provided
  const form = queryRef
    ? usePreloadedQuery(formEditionContainerQuery, queryRef).form
    : null;
  const formDataRef = form ? useFragment<FormEditionFragment_form$key>(formEditionFragment, form) : null;

  const duplicateFormData = formDataRef ? {
    ...formDataRef,
    name: `${formDataRef.name} - copy`,
  } as FormEditionFragment_form$data : null;

  return (
    <Drawer
      title={drawerSettings?.title || 'Create a form intake'}
      open={triggerButton ? undefined : open}
      onClose={handleClose}
      controlledDial={triggerButton ? CreateFormControlledDial : undefined}
    >
      {({ onClose }) => (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          {creationQueryRef && (
            <FormCreation
              queryRef={creationQueryRef}
              handleClose={onClose}
              paginationOptions={paginationOptions || {}}
              formData={duplicateFormData}
            />
          )}
        </React.Suspense>
      )}
    </Drawer>
  );
};

export default FormCreationContainer;
