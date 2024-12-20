import { graphql } from 'react-relay';
import { useState } from 'react';
import { useFintelTemplateAddMutation } from './__generated__/useFintelTemplateAddMutation.graphql';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { insertNodeFromEdge } from '../../../../../utils/store';

const fintelTemplateAddMutation = graphql`
  mutation useFintelTemplateAddMutation($input: FintelTemplateAddInput!) {
    fintelTemplateAdd(input: $input) {
      id
      name
      description
      instance_filters
      settings_types
      start_date
      entity_type
    }
  }
`;

const useFintelTemplateAdd = (entitySettingId: string) => {
  const [mutating, setMutating] = useState(false);
  const [commitAddMutation] = useApiMutation<useFintelTemplateAddMutation>(fintelTemplateAddMutation);

  const mutation: typeof commitAddMutation = ({ variables, onCompleted, onError }) => {
    setMutating(true);
    commitAddMutation({
      variables,
      updater: (store) => {
        insertNodeFromEdge(
          store,
          entitySettingId,
          'fintelTemplates',
          'fintelTemplateAdd',
        );
      },
      onError: (error) => {
        setMutating(false);
        onError?.(error);
      },
      onCompleted: (...args) => {
        setMutating(false);
        onCompleted?.(...args);
      },
    });
  };

  return [mutation, mutating] as const;
};

export default useFintelTemplateAdd;
