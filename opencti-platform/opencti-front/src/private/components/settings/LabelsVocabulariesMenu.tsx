import React, { FunctionComponent } from 'react';
import NavToolbarMenu, { MenuEntry } from '../common/menus/NavToolbarMenu';
import useGranted, {
  SETTINGS_SETCASETEMPLATES,
  SETTINGS_SETCUSTOMIZATION,
  SETTINGS_SETKILLCHAINPHASES,
  SETTINGS_SETLABELS,
  SETTINGS_SETSTATUSTEMPLATES,
  SETTINGS_SETVOCABULARIES,
} from '../../../utils/hooks/useGranted';
import useHelper from '../../../utils/hooks/useHelper';

const LabelsVocabulariesMenu: FunctionComponent = () => {
  const { isFeatureEnable } = useHelper();
  const isGrantedToLabels = useGranted([SETTINGS_SETLABELS]);
  const isGrantedToVocabularies = useGranted([SETTINGS_SETVOCABULARIES]);
  const isGrantedToKillChainPhases = useGranted([SETTINGS_SETKILLCHAINPHASES]);
  const isGrantedToCaseTemplates = useGranted([SETTINGS_SETCASETEMPLATES]);
  const isGrantedToStatusTemplates = useGranted([SETTINGS_SETSTATUSTEMPLATES]);
  const isGrantedToCustomFields = useGranted([SETTINGS_SETCUSTOMIZATION]) && isFeatureEnable('CUSTOM_FIELDS');
  const entries: MenuEntry[] = [];
  if (isGrantedToLabels) {
    entries.push({
      path: '/dashboard/settings/vocabularies/labels',
      label: 'Labels',
    });
  }
  if (isGrantedToKillChainPhases) {
    entries.push({
      path: '/dashboard/settings/vocabularies/kill_chain_phases',
      label: 'Kill chain phases',
    });
  }
  if (isGrantedToVocabularies) {
    entries.push({
      path: '/dashboard/settings/vocabularies/fields',
      label: 'Vocabularies',
    });
  }
  if (isGrantedToStatusTemplates) {
    entries.push({
      path: '/dashboard/settings/vocabularies/status_templates',
      label: 'Status templates',
    });
  }
  if (isGrantedToCaseTemplates) {
    entries.push({
      path: '/dashboard/settings/vocabularies/case_templates',
      label: 'Case templates',
    });
  }
  if (isGrantedToCustomFields) {
    entries.push({
      path: '/dashboard/settings/vocabularies/custom_fields',
      label: 'Custom fields',
    });
  }

  return <NavToolbarMenu entries={entries} />;
};

export default LabelsVocabulariesMenu;
