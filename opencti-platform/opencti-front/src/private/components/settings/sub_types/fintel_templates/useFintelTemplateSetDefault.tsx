import { graphql, useRefetchableFragment } from 'react-relay';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useFintelTemplateSetDefaultMutation } from './__generated__/useFintelTemplateSetDefaultMutation.graphql';
import { fintelTemplatesRefetchableFragment } from './FintelTemplatesManager';

const fintelTemplateSetDefaultMutation = graphql`
  mutation useFintelTemplateSetDefaultMutation($id: ID!, $settingsType: String!) {
    fintelTemplateSetDefault(id: $id, settingsType: $settingsType) {
      id
      default
    }
  }
`;

const useFintelTemplateSetDefault = () => {
  const [commitMutation, mutating] = useApiMutation<useFintelTemplateSetDefaultMutation>(fintelTemplateSetDefaultMutation);

  const [data, refetch] = useRefetchableFragment(
    fintelTemplatesRefetchableFragment,
    queryData,
  );

  const mutation: typeof commitMutation = ({ variables, onCompleted, onError }) => {
    commitMutation({
      variables,
      onCompleted: (),
      onError,
    });
  };

  return [mutation, mutating] as const;
};

export default useFintelTemplateSetDefault;
