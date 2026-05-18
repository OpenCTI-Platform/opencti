import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { useFormatter } from '../../../../components/i18n';
import { insertNode } from '../../../../utils/store';
import { DecayRulesLinesPaginationQuery$variables } from './__generated__/DecayRulesLinesPaginationQuery.graphql';
import DecayRuleCreationForm from './DecayRuleCreationForm';

interface DecayRuleCreationProps {
  paginationOptions: DecayRulesLinesPaginationQuery$variables;
}

const CreateDecayRuleControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType="DecayRule"
    {...props}
  />
);

const DecayRuleCreation = ({ paginationOptions }: DecayRuleCreationProps) => {
  const { t_i18n } = useFormatter();

  const updater = (store: RecordSourceSelectorProxy, rootField: string) => {
    insertNode(
      store,
      'Pagination_decayRules',
      paginationOptions,
      rootField,
    );
  };

  return (
    <Drawer
      title={t_i18n('Create a decay rule')}
      controlledDial={CreateDecayRuleControlledDial}
    >
      {({ onClose }) => (
        <DecayRuleCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default DecayRuleCreation;
