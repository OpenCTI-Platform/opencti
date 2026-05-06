import { useNavigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import { handleError, MESSAGING$ } from '../../../../../../relay/environment';
import useDashboardImport from '../../../../../../components/dashboard/import-export/useDashboardImport';
import { useFormatter } from '../../../../../../components/i18n';
import useApiMutation from '../../../../../../utils/hooks/useApiMutation';
import type { useCustomViewImportExport_Mutation } from '../__generated__/useCustomViewImportExport_Mutation.graphql';

const customViewImportMutation = graphql`
  mutation useCustomViewImportExport_Mutation($targetEntityType: String!, $file: Upload!) {
    customViewConfigurationImport(targetEntityType: $targetEntityType, file: $file) {
      id
    }
  }
`;

const useCustomViewImport = ({ targetEntityType }: { targetEntityType: string }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [commitImportMutation, importing] = useApiMutation<useCustomViewImportExport_Mutation>(customViewImportMutation);

  const onImport = (file: File) => new Promise<void>((resolve, reject) => {
    commitImportMutation({
      variables: { targetEntityType, file },
      onError: (e) => {
        handleError(e);
        reject();
      },
      onCompleted: (response) => {
        if (response.customViewConfigurationImport) {
          const { id } = response.customViewConfigurationImport;
          MESSAGING$.notifySuccess(t_i18n('Custom view created'));
          navigate(`/dashboard/settings/customization/entity_types/${targetEntityType}/custom-views/${id}`);
        }
        resolve();
      },
    });
  });
  const helpers = useDashboardImport({ onImport });
  return { importing, ...helpers };
};

export default useCustomViewImport;
