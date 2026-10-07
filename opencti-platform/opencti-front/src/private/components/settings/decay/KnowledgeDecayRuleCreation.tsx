import React from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { useFormatter } from '../../../../components/i18n';
import { insertNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../relay/environment';
import { notifyPayloadErrors } from '../../common/provenance/provenanceUtils';
import KnowledgeDecayRuleForm from './KnowledgeDecayRuleForm';
import { KnowledgeDecayRulesLinesPaginationQuery$variables } from './__generated__/KnowledgeDecayRulesLinesPaginationQuery.graphql';
import { KnowledgeDecayRuleCreationAddMutation } from './__generated__/KnowledgeDecayRuleCreationAddMutation.graphql';

const knowledgeDecayRuleCreationAddMutation = graphql`
  mutation KnowledgeDecayRuleCreationAddMutation($input: KnowledgeDecayRuleAddInput!) {
    knowledgeDecayRuleAdd(input: $input) {
      ...KnowledgeDecayRulesLine_node
    }
  }
`;

const CreateKnowledgeDecayRuleControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial entityType="DecayRule" {...props} />
);

interface KnowledgeDecayRuleCreationProps {
  paginationOptions: KnowledgeDecayRulesLinesPaginationQuery$variables;
}

const KnowledgeDecayRuleCreation = ({ paginationOptions }: KnowledgeDecayRuleCreationProps) => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation<KnowledgeDecayRuleCreationAddMutation>(knowledgeDecayRuleCreationAddMutation);
  const updater = (store: RecordSourceSelectorProxy) => {
    insertNode(store, 'PaginationKnowledge_decayRules', paginationOptions, 'knowledgeDecayRuleAdd');
  };
  return (
    <Drawer title={t_i18n('Create a knowledge decay rule')} controlledDial={CreateKnowledgeDecayRuleControlledDial}>
      {({ onClose }) => (
        <KnowledgeDecayRuleForm
          onCancel={onClose}
          onSubmit={(input, { setSubmitting, setErrors, resetForm }) => {
            commit({
              variables: { input },
              updater,
              onCompleted: (_, errors) => {
                setSubmitting(false);
                if (notifyPayloadErrors(errors)) return;
                resetForm();
                onClose();
              },
              onError: (error) => {
                handleErrorInForm(error, setErrors);
                setSubmitting(false);
              },
            });
          }}
        />
      )}
    </Drawer>
  );
};

export default KnowledgeDecayRuleCreation;
