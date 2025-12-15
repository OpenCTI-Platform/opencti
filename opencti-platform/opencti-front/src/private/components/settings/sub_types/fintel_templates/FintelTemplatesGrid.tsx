import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import React, { BaseSyntheticEvent, useRef, useState } from 'react';
import { useTheme } from '@mui/styles';
import Tooltip from '@mui/material/Tooltip';
import { Add as AddIcon, CloudUploadOutlined } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import { graphql, useFragment } from 'react-relay';
import EEChip from '@components/common/entreprise_edition/EEChip';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { useNavigate } from 'react-router-dom';
import FintelTemplatesLines, { TemplateType } from './FintelTemplatesLines';
import { FintelTemplatesGrid_templates$key } from './__generated__/FintelTemplatesGrid_templates.graphql';
import FintelTemplateFormDrawer from './FintelTemplateFormDrawer';
import { FintelTemplateFormInputs } from './FintelTemplateForm';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import useFintelTemplateImport from './useFintelTemplateImport';
import { handleError, MESSAGING$ } from '../../../../../relay/environment';
import { resolveLink } from '../../../../../utils/Entity';

export const fintelTemplatesFragmentParams = { orderBy: 'name', orderMode: 'asc' };

const fintelTemplatesFragment = graphql`
  fragment FintelTemplatesGrid_templates on EntitySetting {
    id
    target_type
    fintelTemplates (orderBy: name, orderMode: asc) {
      edges {
        node {
          id
          name
          description
          instance_filters
          settings_types
          start_date
          entity_type
        }
      }
    }
  }
`;

interface FintelTemplatesGridProps {
  data: FintelTemplatesGrid_templates$key;
}

const FintelTemplatesGrid = ({ data }: FintelTemplatesGridProps) => {
  const navigate = useNavigate();
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const inputFileRef = useRef<HTMLInputElement>(null);
  const isEnterpriseEdition = useEnterpriseEdition();
  const [commitImportMutation, importMutating] = useFintelTemplateImport();

  const [dataTableRef, setDataTableRef] = useState<HTMLDivElement | null>(null);
  const [isDrawerOpen, setDrawerOpen] = useState(false);
  const [templateToEdit, setTemplateToEdit] = useState<{ id: string } & FintelTemplateFormInputs>();

  const dataResolved = useFragment(fintelTemplatesFragment, data);
  if (!dataResolved) return null;
  const { target_type, fintelTemplates, id: entitySettingId } = dataResolved;

  const onUpdate = (template: TemplateType) => {
    setTemplateToEdit({
      id: template.id,
      name: template.name,
      description: template.description ?? null,
      published: !!template.start_date,
    });
    setDrawerOpen(true);
  };

  const onUpload = (event: BaseSyntheticEvent) => {
    const importedFile = event.target.files[0];
    if (importedFile) {
      commitImportMutation({
        variables: { file: importedFile },
        onError: (e) => {
          if (inputFileRef.current) inputFileRef.current.value = '';
          handleError(e);
        },
        onCompleted: (response) => {
          if (inputFileRef.current) inputFileRef.current.value = '';
          if (response.fintelTemplateConfigurationImport) {
            const { id, entity_type } = response.fintelTemplateConfigurationImport;
            MESSAGING$.notifySuccess(t_i18n('FINTEL template created'));
            navigate(`${resolveLink(entity_type)}/${target_type}/templates/${id}`);
          }
        },
      });
    }
  };

  return (
    <>
      <VisuallyHiddenInput
        ref={inputFileRef}
        type="file"
        accept="application/JSON"
        onChange={onUpload}
      />
      <Grid item xs={6}>
        <Typography
          variant="h4"
          gutterBottom={true}
          sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
        >
          <p>{t_i18n('FINTEL Templates')}</p>
          {isEnterpriseEdition && (
            <div>
              <Tooltip title={t_i18n('Create a new template')}>
                <IconButton
                  onClick={() => setDrawerOpen(true)}
                  size="small"
                  sx={{ marginBottom: 0.25 }}
                >
                  <AddIcon fontSize="small" color="primary" />
                </IconButton>
              </Tooltip>
              <Tooltip title={t_i18n('Import a template')}>
                <IconButton
                  disabled={importMutating}
                  onClick={() => inputFileRef.current?.click()}
                  size="small"
                  sx={{ marginBottom: 0.25 }}
                >
                  <CloudUploadOutlined fontSize="small" color="primary" />
                </IconButton>
              </Tooltip>
            </div>
          )}
          <EEChip />
        </Typography>

        <Paper
          variant="outlined"
          className="paper-for-grid"
          style={{
            marginTop: theme.spacing(1),
            padding: theme.spacing(2),
            borderRadius: theme.spacing(0.5),
            position: 'relative',
            height: '235px',
          }}
        >
          <div style={{ height: '100%', width: '100%' }} ref={(r) => setDataTableRef(r)}>
            {!isEnterpriseEdition && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                textAlign: 'center',
              }}
              >
                {t_i18n('FINTEL templates are available with an Enterprise Edition subscription')}
              </div>
            )}
            {isEnterpriseEdition && (
              <FintelTemplatesLines
                fintelTemplates={fintelTemplates}
                dataTableRef={dataTableRef}
                onUpdate={onUpdate}
                entitySettingId={entitySettingId}
                targetType={target_type}
              />
            )}
          </div>
        </Paper>
      </Grid>

      {isEnterpriseEdition && (
        <FintelTemplateFormDrawer
          entitySettingId={entitySettingId}
          isOpen={isDrawerOpen}
          template={templateToEdit}
          entityType={target_type}
          onClose={() => {
            setDrawerOpen(false);
            setTemplateToEdit(undefined);
          }}
        />
      )}
    </>
  );
};

export default FintelTemplatesGrid;
