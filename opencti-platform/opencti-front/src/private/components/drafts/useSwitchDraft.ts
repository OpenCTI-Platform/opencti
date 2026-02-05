import { UseMutationConfig } from 'react-relay';
import { graphql, MutationParameters } from 'relay-runtime';
import useApiMutation from '../../../utils/hooks/useApiMutation';

const mutation = graphql`
  mutation useSwitchDraftMutation($input: [EditInput]!) {
    meEdit(input: $input) {
      draftContext {
        ...DraftToolbarFragment
      }
    }
  }
`;

type ArgsType = Omit<UseMutationConfig<MutationParameters>, 'variables'>;

const useSwitchDraft = () => {
  const [commit] = useApiMutation(mutation);

  const exitDraft = (args: ArgsType = {}) => {
    commit({
      ...args,
      variables: {
        input: { key: 'draft_context', value: '' },
      },
    });
  };

  const enterDraft = (draftId: string, args: ArgsType = {}) => {
    commit({
      ...args,
      variables: {
        input: [{ key: 'draft_context', value: [draftId] }],
      },
    });
  };

  return {
    exitDraft,
    enterDraft,
  };
};

export default useSwitchDraft;
