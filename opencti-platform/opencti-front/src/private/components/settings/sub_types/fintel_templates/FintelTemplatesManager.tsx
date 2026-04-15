import IconButton from '@common/button/IconButton';
import EEChip from '@components/common/entreprise_edition/EEChip';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { Add as AddIcon, CloudUploadOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { BaseSyntheticEvent, useRef, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import Card from '../../../../../components/common/card/Card';
import { useFormatter } from '../../../../../components/i18n';
import { handleError, MESSAGING$ } from '../../../../../relay/environment';
import { resolveLink } from '../../../../../utils/Entity';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import { FintelTemplatesManager_templates$key } from './__generated__/FintelTemplatesManager_templates.graphql';
import { FintelTemplateFormInputs } from './FintelTemplateForm';
import FintelTemplateFormDrawer from './FintelTemplateFormDrawer';
import FintelTemplatesLines, { TemplateType } from './FintelTemplatesLines';
import useFintelTemplateImport from './useFintelTemplateImport';

export const fintelTemplatesFragmentParams = { orderBy: 'name', orderMode: 'asc' };

const fintelTemplatesFragment = graphql`
  fragment FintelTemplatesManager_templates on EntitySetting {
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

const FintelTemplatesManager = () => {
  const { subType } = useSubTypeOutletContext();

  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const inputFileRef = useRef<HTMLInputElement>(null);
  const isEnterpriseEdition = useEnterpriseEdition();
  const [commitImportMutation, importMutating] = useFintelTemplateImport();

  const [dataTableRef, setDataTableRef] = useState<HTMLDivElement | null>(null);
  const [isDrawerOpen, setDrawerOpen] = useState(false);
  const [templateToEdit, setTemplateToEdit] = useState<{ id: string } & FintelTemplateFormInputs>();

  const dataResolved = useFragment<FintelTemplatesManager_templates$key>(fintelTemplatesFragment, subType.settings);
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
      <Card
        title={<>{t_i18n('FINTEL Templates')} <EEChip /></>}
        action={isEnterpriseEdition && (
          <div>
            <Tooltip title={t_i18n('Create a new template')}>
              <IconButton
                onClick={() => setDrawerOpen(true)}
                size="small"
              >
                <AddIcon fontSize="small" color="primary" />
              </IconButton>
            </Tooltip>
            <Tooltip title={t_i18n('Import a template')}>
              <IconButton
                disabled={importMutating}
                onClick={() => inputFileRef.current?.click()}
                size="small"
              >
                <CloudUploadOutlined fontSize="small" color="primary" />
              </IconButton>
            </Tooltip>
          </div>
        )}
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
      </Card>

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

export default FintelTemplatesManager;
