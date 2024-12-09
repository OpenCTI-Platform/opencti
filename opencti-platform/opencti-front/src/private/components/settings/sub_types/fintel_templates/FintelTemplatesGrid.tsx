import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import React, { useState } from 'react';
import { useTheme } from '@mui/styles';
import Tooltip from '@mui/material/Tooltip';
import { Add as AddIcon } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import { graphql, useFragment } from 'react-relay';
import { SubType_subType$data } from '@components/settings/sub_types/__generated__/SubType_subType.graphql';
import { FintelTemplatesGrid_templates$key } from '@components/settings/sub_types/fintel_templates/__generated__/FintelTemplatesGrid_templates.graphql';
import FintelTemplateFormDrawer from './FintelTemplateFormDrawer';
import { FintelTemplateFormInputs } from './FintelTemplateForm';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';

const fintelTemplateFragment = graphql`
  fragment FintelTemplatesGrid_template on FintelTemplate {
    id
    name
    description
    instance_filters
    content
    settings_types
    start_date
  }
`;

const fintelTemplatesFragment = graphql`
  fragment FintelTemplatesGrid_templates on EntitySetting {
    fintelTemplates {
      ...FintelTemplatesGrid_template
    }
  }
`;

interface FintelTemplatesGridProps {
  data: SubType_subType$data['settings']
}

const FintelTemplatesGrid = ({ data }: FintelTemplatesGridProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const templates = useFragment<FintelTemplatesGrid_templates$key>(
    fintelTemplatesFragment,
    data,
  );

  console.log('ccsv', templates);

  const [isDrawerOpen, setDrawerOpen] = useState(false);
  const [templateToEdit, setTemplateToEdit] = useState<FintelTemplateFormInputs>();

  return (
    <>
      <Grid item xs={6}>
        <Typography
          variant="h4"
          gutterBottom={true}
          sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
        >
          <p>{t_i18n('Templates')}</p>
          <Tooltip title={t_i18n('Create a new template')}>
            <IconButton
              onClick={() => setDrawerOpen(true)}
              size="small"
              sx={{ marginBottom: 0.25 }}
            >
              <AddIcon fontSize="small" color="primary" />
            </IconButton>
          </Tooltip>
        </Typography>

        <Paper
          variant="outlined"
          className="paper-for-grid"
          style={{
            marginTop: theme.spacing(1),
            padding: theme.spacing(2),
            borderRadius: theme.spacing(0.5),
            position: 'relative',
          }}
        >
          <button onClick={() => {
            setTemplateToEdit({
              name: 'Super template',
              description: 'pouet pouet',
              published: true,
            });
            setDrawerOpen(true);
          }}
          >
            TODO DataTable of existing templates here
          </button>
        </Paper>
      </Grid>

      <FintelTemplateFormDrawer
        isOpen={isDrawerOpen}
        template={templateToEdit}
        onClose={() => {
          setDrawerOpen(false);
          setTemplateToEdit(undefined);
        }}
      />
    </>
  );
};

export default FintelTemplatesGrid;
