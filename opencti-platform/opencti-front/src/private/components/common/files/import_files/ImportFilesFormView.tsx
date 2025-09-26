import React from 'react';
import { Box, Alert } from '@mui/material';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useImportFilesContext } from '@components/common/files/import_files/ImportFilesContext';
import { ImportFilesFormViewQuery } from '@components/common/files/import_files/__generated__/ImportFilesFormViewQuery.graphql';
import FormView from '../../../data/forms/view/FormView';
import { useFormatter } from '../../../../../components/i18n';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../../components/Loader';

const importFilesFormViewQuery = graphql`
  query ImportFilesFormViewQuery($id: ID!) {
    form(id: $id) {
      id
      name
      description
      form_schema
      active
    }
  }
`;

interface ImportFilesFormViewContentProps {
  queryRef: PreloadedQuery<ImportFilesFormViewQuery>;
  onSuccess?: () => void;
}

const ImportFilesFormViewContent: React.FC<ImportFilesFormViewContentProps> = ({ queryRef, onSuccess }) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery<ImportFilesFormViewQuery>(importFilesFormViewQuery, queryRef);
  const { form } = data;

  if (!form) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">
          {t_i18n('Form not found')}
        </Alert>
      </Box>
    );
  }

  if (!form.active) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="warning">
          {t_i18n('This form is currently inactive')}
        </Alert>
      </Box>
    );
  }

  // Use FormView component directly, embedded in the dialog
  return (
    <Box sx={{
      height: '100%',
      overflow: 'auto',
      '& .MuiPaper-root': {
        boxShadow: 'none',
        backgroundColor: 'transparent',
      },
    }}
    >
      <FormView formId={form.id} embedded onSuccess={onSuccess} />
    </Box>
  );
};

interface ImportFilesFormViewProps {
  onSuccess?: () => void;
}

const ImportFilesFormView: React.FC<ImportFilesFormViewProps> = ({ onSuccess }) => {
  const { t_i18n } = useFormatter();
  const { selectedFormId } = useImportFilesContext();

  if (!selectedFormId) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="warning">
          {t_i18n('No form selected. Please go back and select a form.')}
        </Alert>
      </Box>
    );
  }

  const queryRef = useQueryLoading<ImportFilesFormViewQuery>(
    importFilesFormViewQuery,
    { id: selectedFormId },
  );

  if (!queryRef) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 400 }}>
        <Loader />
      </Box>
    );
  }

  return (
    <React.Suspense fallback={
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 400 }}>
        <Loader />
      </Box>
    }
    >
      <ImportFilesFormViewContent queryRef={queryRef} onSuccess={onSuccess} />
    </React.Suspense>
  );
};

export default ImportFilesFormView;
