import IconButton from '@common/button/IconButton';
import EEChip from '@components/common/entreprise_edition/EEChip';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { Add as AddIcon, CloudUploadOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { BaseSyntheticEvent, useRef, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { useNavigate } from 'react-router';
import Card from '../../../../../components/common/card/Card';
import { useFormatter } from '../../../../../components/i18n';
import { fetchQuery, handleError, MESSAGING$ } from '../../../../../relay/environment';
import { resolveLink } from '../../../../../utils/Entity';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import { FintelTemplatesManager_templates$key } from './__generated__/FintelTemplatesManager_templates.graphql';
import { FintelTemplateFormInputs } from './FintelTemplateForm';
import FintelTemplateFormDrawer from './FintelTemplateFormDrawer';
import FintelTemplatesLines, { TemplateType } from './FintelTemplatesLines';
import useFintelTemplateImport from './useFintelTemplateImport';
import ConfigPresetPartialImportDialog from '../../config_preset/import/partial/ConfigPresetPartialImportDialog';
import useConfigPresetPartialImportAccess from '../../config_preset/import/partial/useConfigPresetPartialImportAccess';
import { subTypeQuery } from '../SubType';
import { SubTypeQuery } from '../__generated__/SubTypeQuery.graphql';

// The configuration preset type of the fintel templates
const FINTEL_TEMPLATES_CONFIG_PRESET_TYPE = 'fintelTemplates';

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
          default
          includeCoverPageByDefault
          includeBackPageByDefault
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
  // Without the partial import (not a BYPASS user, or the CONFIG_PRESET flag off), the template file import stays as it is
  const canImportFromBundle = useConfigPresetPartialImportAccess();
  const [importDialogOpen, setImportDialogOpen] = useState(false);

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
      default: !!template.default,
      include_cover_page_by_default: template.includeCoverPageByDefault ?? true,
      include_back_page_by_default: template.includeBackPageByDefault ?? true,
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

  const currentDefaultName = fintelTemplates?.edges.find(({ node }) => node.default)?.node.name;

  // After the import of templates from a configuration bundle: the entity type is read again, its templates with it
  const onBundleImported = () => {
    fetchQuery<SubTypeQuery>(subTypeQuery, { id: subType.id }, { fetchPolicy: 'network-only' }).toPromise();
  };

  return (
    <>
      <VisuallyHiddenInput
        ref={inputFileRef}
        type="file"
        accept="application/JSON"
        onChange={onUpload}
      />
      {isEnterpriseEdition && canImportFromBundle && (
        <ConfigPresetPartialImportDialog
          open={importDialogOpen}
          onClose={() => setImportDialogOpen(false)}
          title={t_i18n('Import a template')}
          type={FINTEL_TEMPLATES_CONFIG_PRESET_TYPE}
          // Only the templates of this entity type: the ones of the other types of the bundle are not offered
          scope={target_type}
          itemsLabel={t_i18n('FINTEL templates')}
          fileLabel={t_i18n('Import a template file')}
          fileDescription={t_i18n('A FINTEL template exported as a JSON file')}
          bundleDescription={t_i18n('Select the FINTEL templates to import from a full configuration bundle (zip)')}
          onBundleImported={onBundleImported}
          // The same file import as without the dialog: the dialog closes, the file picker opens, and the import tells its outcome as before
          onChooseFile={() => {
            setImportDialogOpen(false);
            inputFileRef.current?.click();
          }}
        />
      )}
      <Card
        title={<>{t_i18n('FINTEL Templates')} <EEChip /></>}
        action={isEnterpriseEdition && (
          <div>
            <Tooltip title={t_i18n('Create a new template')}>
              <IconButton
                onClick={() => setDrawerOpen(true)}
                size="small"
                aria-label={t_i18n('Create a new template')}
              >
                <AddIcon fontSize="small" color="primary" />
              </IconButton>
            </Tooltip>
            <Tooltip title={t_i18n('Import a template')}>
              <IconButton
                disabled={importMutating}
                onClick={canImportFromBundle ? () => setImportDialogOpen(true) : () => inputFileRef.current?.click()}
                size="small"
                aria-label={t_i18n('Import a template')}
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
          currentDefaultName={currentDefaultName}
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
