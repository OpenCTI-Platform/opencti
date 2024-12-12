import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import React, { useState } from 'react';
import { useTheme } from '@mui/styles';
import Tooltip from '@mui/material/Tooltip';
import { Add as AddIcon } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import { graphql, useFragment } from 'react-relay';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { FintelTemplatesGrid_templates$data, FintelTemplatesGrid_templates$key } from './__generated__/FintelTemplatesGrid_templates.graphql';
import FintelTemplatePopover from './FintelTemplatePopover';
import FintelTemplateFormDrawer from './FintelTemplateFormDrawer';
import { FintelTemplateFormInputs } from './FintelTemplateForm';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import { DataTableVariant } from '../../../../../components/dataGrid/dataTableTypes';
import DataTableWithoutFragment from '../../../../../components/dataGrid/DataTableWithoutFragment';
import ItemBoolean from '../../../../../components/ItemBoolean';
import { resolveLink } from '../../../../../utils/Entity';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import { deleteNodeFromEdge } from '../../../../../utils/store';

const fintelTemplatesFragment = graphql`
  fragment FintelTemplatesGrid_templates on EntitySetting {
    id
    target_type
    fintelTemplates {
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

type TemplateType = NonNullable<FintelTemplatesGrid_templates$data['fintelTemplates']>['edges'][0]['node'];

interface FintelTemplatesGridProps {
  data: FintelTemplatesGrid_templates$key
}

const FintelTemplatesGrid = ({ data }: FintelTemplatesGridProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();

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

  return (
    <>
      <Grid item xs={6}>
        <Typography
          variant="h4"
          gutterBottom={true}
          sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
        >
          <p>{t_i18n('FINTEL Templates')}</p>
          {isEnterpriseEdition && (
            <Tooltip title={t_i18n('Create a new template')}>
              <IconButton
                onClick={() => setDrawerOpen(true)}
                size="small"
                sx={{ marginBottom: 0.25 }}
              >
                <AddIcon fontSize="small" color="primary" />
              </IconButton>
            </Tooltip>
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
              <DataTableWithoutFragment
                dataColumns={{
                  name: { percentWidth: 41 },
                  description: { percentWidth: 41 },
                  start_date: {
                    percentWidth: 18,
                    label: t_i18n('Published'),
                    render: ({ start_date }) => (
                      <ItemBoolean
                        status={!!start_date}
                        label={start_date ? t_i18n('Yes') : t_i18n('No')}
                      />
                    ),
                  },
                }}
                storageKey={`fintel-templates-${target_type}`}
                useComputeLink={(t: TemplateType) => {
                  return `${resolveLink(t.entity_type)}/${target_type}/templates/${t.id}`;
                }}
                globalCount={fintelTemplates?.edges.length ?? 0}
                data={(fintelTemplates?.edges ?? []).map((e) => e.node)}
                rootRef={dataTableRef ?? undefined}
                variant={DataTableVariant.inline}
                actions={(template: TemplateType) => (
                  <FintelTemplatePopover
                    deleteUpdater={(store) => {
                      deleteNodeFromEdge(
                        store,
                        'fintelTemplates',
                        entitySettingId,
                        template.id,
                      );
                    }}
                    templateId={template.id}
                    onUpdate={() => onUpdate(template)}
                  />
                )}
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
