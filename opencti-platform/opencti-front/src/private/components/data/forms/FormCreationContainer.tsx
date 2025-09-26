import { PreloadedQuery, useFragment, usePreloadedQuery, useQueryLoader, graphql } from 'react-relay';
import React, { FunctionComponent, useRef } from 'react';
import { useTheme } from '@mui/styles';
import ToggleButton from '@mui/material/ToggleButton';
import { FileUploadOutlined } from '@mui/icons-material';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { FormEditionContainerQuery } from './__generated__/FormEditionContainerQuery.graphql';
import { formEditionContainerQuery } from './FormEditionContainer';
import { FormEditionFragment_form$data, FormEditionFragment_form$key } from './__generated__/FormEditionFragment_form.graphql';
import { FormLinesPaginationQuery$variables } from './__generated__/FormLinesPaginationQuery.graphql';
import FormCreation, { formCreationQuery } from './FormCreation';
import { FormCreationQuery } from './__generated__/FormCreationQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { formEditionFragment } from './FormEdition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleError } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import VisuallyHiddenInput from '../../common/VisuallyHiddenInput';
import type { FormCreationContainerImportMutation } from './__generated__/FormCreationContainerImportMutation.graphql';
import type { Theme } from '../../../../components/Theme';
import { insertNode } from '../../../../utils/store';

const formImportMutation = graphql`
  mutation FormCreationContainerImportMutation($file: Upload!) {
    formImport(file: $file) {
      id
      name
      description
      active
      form_schema
      updated_at
    }
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

interface CreateFormControlledDialProps extends DrawerControlledDialProps {
  paginationOptions?: FormLinesPaginationQuery$variables;
}

const CreateFormControlledDial = (props: CreateFormControlledDialProps) => {
  const { paginationOptions } = props;
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [commitImportMutation] = useApiMutation<FormCreationContainerImportMutation>(formImportMutation);

  const handleImport = (event: React.ChangeEvent<HTMLInputElement>) => {
    const importedFile = event.target.files?.[0];
    if (importedFile) {
      commitImportMutation({
        variables: { file: importedFile },
        updater: (store) => {
          if (paginationOptions) {
            insertNode(
              store,
              'Pagination_forms',
              paginationOptions,
              'formImport',
            );
          }
        },
        onCompleted: () => {
          if (inputRef.current) {
            inputRef.current.value = '';
          }
        },
        onError: (error) => {
          if (inputRef.current) {
            inputRef.current.value = '';
          }
          handleError(error);
        },
      });
    }
  };

  return (
    <>
      <VisuallyHiddenInput
        type="file"
        accept="application/json"
        ref={inputRef}
        onChange={handleImport}
      />
      <ToggleButton
        value="import"
        size="small"
        onClick={() => inputRef.current?.click()}
        sx={{ marginLeft: theme.spacing(1) }}
        title={t_i18n('Import form intake')}
      >
        <FileUploadOutlined fontSize="small" color="primary" />
      </ToggleButton>
      <CreateEntityControlledDial entityType='Form' {...props} />
    </>
  );
};

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
  } as FormEditionFragment_form$data : undefined;

  const createFormButton = React.useCallback((props: DrawerControlledDialProps) => (
    <CreateFormControlledDial {...props} paginationOptions={paginationOptions} />
  ), [paginationOptions]);

  return (
    <Drawer
      title={drawerSettings?.title || 'Create a form intake'}
      open={triggerButton ? undefined : open}
      onClose={handleClose}
      controlledDial={triggerButton ? createFormButton : undefined}
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
