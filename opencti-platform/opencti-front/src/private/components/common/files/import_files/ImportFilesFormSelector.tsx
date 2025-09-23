import React, { useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Box, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Paper, Typography } from '@mui/material';
import { useImportFilesContext } from '@components/common/files/import_files/ImportFilesContext';
import { ImportFilesFormSelectorQuery } from '@components/common/files/import_files/__generated__/ImportFilesFormSelectorQuery.graphql';
import { useFormatter } from '../../../../../components/i18n';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import SearchInput from '../../../../../components/SearchInput';
import ItemIcon from '../../../../../components/ItemIcon';
import Loader from '../../../../../components/Loader';

const importFilesFormSelectorQuery = graphql`
  query ImportFilesFormSelectorQuery(
    $search: String
    $first: Int
    $orderBy: FormsOrdering
  ) {
    forms(
      search: $search
      first: $first
      orderBy: $orderBy
      filters: { mode: and, filters: [{ key: "active", values: ["true"] }], filterGroups: [] }
    ) {
      edges {
        node {
          id
          name
          description
          form_schema
        }
      }
    }
  }
`;

interface ImportFilesFormSelectorContentProps {
  queryRef: PreloadedQuery<ImportFilesFormSelectorQuery>;
  selectedFormId?: string;
  onSelectForm: (formId: string) => void;
  searchTerm: string;
  onSearchChange: (value: string) => void;
}

const ImportFilesFormSelectorContent: React.FC<ImportFilesFormSelectorContentProps> = ({
  queryRef,
  selectedFormId,
  onSelectForm,
  searchTerm,
  onSearchChange,
}) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery<ImportFilesFormSelectorQuery>(importFilesFormSelectorQuery, queryRef);
  const forms = data.forms?.edges || [];

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ mb: 2 }}>
        <Typography variant="h6" gutterBottom>
          {t_i18n('Select a form')}
        </Typography>
        <Typography variant="body2" color="textSecondary">
          {t_i18n('Choose a form to fill out and create entities')}
        </Typography>
      </Box>

      <Box sx={{ mb: 2 }}>
        <SearchInput
          variant="small"
          onSubmit={onSearchChange}
          keyword={searchTerm}
        />
      </Box>

      <Paper variant="outlined" sx={{ flex: 1, overflow: 'auto' }}>
        <List>
          {forms.length === 0 ? (
            <ListItem>
              <ListItemText
                primary={t_i18n('No forms available')}
                secondary={t_i18n('No active forms found matching your criteria')}
              />
            </ListItem>
          ) : (
            forms.map((edge) => {
              const form = edge.node;
              const schema = form.form_schema ? JSON.parse(form.form_schema) : null;
              const mainEntityType = schema?.mainEntityType || '';

              return (
                <ListItemButton
                  key={form.id}
                  selected={selectedFormId === form.id}
                  onClick={() => onSelectForm(form.id)}
                  divider
                >
                  <ListItemIcon>
                    <ItemIcon type={mainEntityType} />
                  </ListItemIcon>
                  <ListItemText
                    primary={form.name}
                    secondary={form.description || ''}
                  />
                </ListItemButton>
              );
            })
          )}
        </List>
      </Paper>
    </Box>
  );
};

const ImportFilesFormSelector = () => {
  const { selectedFormId, setSelectedFormId, setActiveStep } = useImportFilesContext();
  const [searchTerm, setSearchTerm] = useState('');
  const queryRef = useQueryLoading<ImportFilesFormSelectorQuery>(
    importFilesFormSelectorQuery,
    {
      search: searchTerm || undefined,
      first: 100,
      orderBy: 'name',
    },
  );

  if (!queryRef) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 400 }}>
        <Loader />
      </Box>
    );
  }

  const handleSelectForm = (formId: string) => {
    setSelectedFormId(formId);
    setActiveStep(2);
  };

  return (
    <React.Suspense fallback={
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 400 }}>
        <Loader />
      </Box>
    }
    >
      <ImportFilesFormSelectorContent
        queryRef={queryRef}
        selectedFormId={selectedFormId}
        onSelectForm={handleSelectForm}
        searchTerm={searchTerm}
        onSearchChange={setSearchTerm}
      />
    </React.Suspense>
  );
};

export default ImportFilesFormSelector;
