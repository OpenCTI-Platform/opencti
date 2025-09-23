import React, { FunctionComponent } from 'react';
import NavToolbarMenu, { MenuEntry } from '../common/menus/NavToolbarMenu';
import useGranted, {
  SETTINGS_SETCASETEMPLATES,
  SETTINGS_SETKILLCHAINPHASES,
  SETTINGS_SETLABELS,
  SETTINGS_SETSTATUSTEMPLATES,
  SETTINGS_SETVOCABULARIES,
} from '../../../utils/hooks/useGranted';

const LabelsVocabulariesMenu: FunctionComponent = () => {
  const isGrantedToLabels = useGranted([SETTINGS_SETLABELS]);
  const isGrantedToVocabularies = useGranted([SETTINGS_SETVOCABULARIES]);
  const isGrantedToKillChainPhases = useGranted([SETTINGS_SETKILLCHAINPHASES]);
  const isGrantedToCaseTemplates = useGranted([SETTINGS_SETCASETEMPLATES]);
  const isGrantedToStatusTemplates = useGranted([SETTINGS_SETSTATUSTEMPLATES]);
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

  return <NavToolbarMenu entries={entries} />;
};

export default LabelsVocabulariesMenu;
