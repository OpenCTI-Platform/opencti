import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { useFormatter } from 'src/components/i18n';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { insertNode } from 'src/utils/store';
import React from 'react';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { DecayRulesLinesPaginationQuery$variables } from './__generated__/DecayRulesLinesPaginationQuery.graphql';
import DecayExclusionRuleCreationForm from './DecayExclusionRuleCreationForm';

type DecayExclusionRuleCreationProps = {
  paginationOptions: DecayRulesLinesPaginationQuery$variables;
};

const CreateDecayExclusionRuleControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType='DecayExclusionRule'
    {...props}
  />
);
const DecayExclusionRuleCreation = ({ paginationOptions }: DecayExclusionRuleCreationProps) => {
  const { t_i18n } = useFormatter();

  const updater = (store: RecordSourceSelectorProxy, rootField: string) => {
    insertNode(
      store,
      'Pagination_decayExclusionRules',
      paginationOptions,
      rootField,
    );
  };

  return (
    <Drawer
      title={t_i18n('Create a decay exclusion rule')}
      controlledDial={CreateDecayExclusionRuleControlledDial}
    >
      {({ onClose }) => (
        <DecayExclusionRuleCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default DecayExclusionRuleCreation;
