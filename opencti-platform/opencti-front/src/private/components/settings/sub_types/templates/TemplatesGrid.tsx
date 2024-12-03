import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import React, { useState } from 'react';
import { useTheme } from '@mui/styles';
import Tooltip from '@mui/material/Tooltip';
import { Add as AddIcon } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import TemplateFormDrawer from '@components/settings/sub_types/templates/TemplateFormDrawer';
import { TemplateFormInputs } from '@components/settings/sub_types/templates/TemplateForm';
import { PAPER_STYLE } from '../SubType';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';

const TemplatesGrid = () => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const [isDrawerOpen, setDrawerOpen] = useState(false);
  const [templateToEdit, setTemplateToEdit] = useState<TemplateFormInputs>();

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
          style={PAPER_STYLE(theme)}
        >
          <button onClick={() => {
            setTemplateToEdit({
              name: 'Super template',
              description: 'pouet pouet',
              content: '<p>I am a template</p>',
              published: true,
            });
            setDrawerOpen(true);
          }}
          >
            TODO DataTable of existing templates here
          </button>
        </Paper>
      </Grid>

      <TemplateFormDrawer
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

export default TemplatesGrid;
