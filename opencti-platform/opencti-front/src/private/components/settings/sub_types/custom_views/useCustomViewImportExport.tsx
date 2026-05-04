import { useNavigate } from 'react-router-dom';
import { fetchQuery, handleError, MESSAGING$ } from '../../../../../relay/environment';
import { DashboardHiddenImportInput, useDashboardExport, useDashboardImport } from '../../../../../components/dashboard/useDashboardImportExport';
import { useFormatter } from '../../../../../components/i18n';
import { graphql } from 'react-relay';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import type { useCustomViewImportExport_Mutation } from './__generated__/useCustomViewImportExport_Mutation.graphql';
import type { useCustomViewImportExport_Query$data } from './__generated__/useCustomViewImportExport_Query.graphql';

const customViewImportMutation = graphql`
  mutation useCustomViewImportExport_Mutation($targetEntityType: String!, $file: Upload!) {
    customViewConfigurationImport(targetEntityType: $targetEntityType, file: $file) {
      id
    }
  }
`;

const customViewExportQuery = graphql`
  query useCustomViewImportExport_Query($id: ID!) {
    customView(id: $id) {
      toConfigurationExport
    }
  }
`;

export const useCustomViewImport = ({ targetEntityType }: { targetEntityType: string }) => {
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

export const CustomViewHiddenImportInput = ({ helpers }: { helpers: ReturnType<typeof useDashboardImport> }) => {
  return <DashboardHiddenImportInput helpers={helpers} />;
};

const onExport = async (id: string) => {
  const data = await fetchQuery(customViewExportQuery, { id })
    .toPromise();
  const result = data as useCustomViewImportExport_Query$data;
  const exportString = result.customView?.toConfigurationExport;
  if (!exportString) {
    throw new Error('Failed to export custom view');
  }
  return exportString;
};

export const useCustomViewExport = (customView: { id: string; name: string }) => {
  return useDashboardExport({ onExport, configType: 'custom-view', entity: customView });
};
