import { graphql, useMutation } from 'react-relay';
import { useFormatter } from '../../../../../components/i18n';
import { MESSAGING$ } from '../../../../../relay/environment';
import {
  useTestCallBackUrlCheckMutation,
  useTestCallBackUrlCheckMutation$data,
} from '@components/settings/sso_definitions/utils/__generated__/useTestCallBackUrlCheckMutation.graphql';

export const singleSignOnUrlCheckMutation = graphql`
  mutation useTestCallBackUrlCheckMutation($url: String!) {
    singleSignOnUrlCheck(url: $url) {
      success
      message
      statusCode
    }
  }
`;

export const useUrlCheck = () => {
  const { t_i18n } = useFormatter();
  const [commit, isLoading] = useMutation<useTestCallBackUrlCheckMutation>(singleSignOnUrlCheckMutation);

  const checkUrl = (url: string) => {
    commit({
      variables: { url },
      onCompleted: (response: useTestCallBackUrlCheckMutation$data) => {
        if (response?.singleSignOnUrlCheck?.success) {
          MESSAGING$.notifySuccess(response.singleSignOnUrlCheck.message);
        } else {
          MESSAGING$.notifyError(response?.singleSignOnUrlCheck?.message ?? t_i18n('Unknown error'));
        }
      },
      onError: (error) => {
        MESSAGING$.notifyError(error.message);
      },
    });
  };

  return { checkUrl, isLoading };
};
