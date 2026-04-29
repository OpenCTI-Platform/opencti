import { graphql } from 'react-relay';
import { fetchQuery, handleError, MESSAGING$ } from '../../../../../relay/environment';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useDashboard from '../../../../../components/dashboard/useDashboard';
import { useCustomViewDashboardEdit_Mutation } from './__generated__/useCustomViewDashboardEdit_Mutation.graphql';
import { useCustomViewDashboardEdit_LayoutMutation } from './__generated__/useCustomViewDashboardEdit_LayoutMutation.graphql';
import { useCustomViewDashboardEdit_WidgetImportMutation } from './__generated__/useCustomViewDashboardEdit_WidgetImportMutation.graphql';
import { useCustomViewDashboardEdit_WidgetExportQuery$data } from './__generated__/useCustomViewDashboardEdit_WidgetExportQuery.graphql';
import { useCustomViewDashboardEdit_Query$data } from './__generated__/useCustomViewDashboardEdit_Query.graphql';

export const customViewQuery = graphql`
  query useCustomViewDashboardEdit_Query($id: ID!) {
    customView(id: $id) {
      id
      manifest
      ...CustomViewEditionHeader_customView
    }
  }
`;

const customViewLayoutMutation = graphql`
  mutation useCustomViewDashboardEdit_LayoutMutation($id: ID!, $input: [EditInput!]!) {
    customViewEdit(id: $id, input: $input) {
      id
    }
  }
`;

export const customViewMutation = graphql`
  mutation useCustomViewDashboardEdit_Mutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    customViewEdit(id: $id, input: $input) {
      id
      manifest
      ...CustomViewEditionHeader_customView
    }
  }
`;

const customViewImportWidgetMutation = graphql`
  mutation useCustomViewDashboardEdit_WidgetImportMutation(
    $id: ID!
    $input: CustomViewImportWidgetInput!
  ) {
    customViewWidgetConfigurationImport(id: $id, input: $input) {
      id
      manifest
      ...CustomViewEditionHeader_customView
    }
  }
`;

const customViewExportWidgetQuery = graphql`
  query useCustomViewDashboardEdit_WidgetExportQuery($id: ID!, $widgetId: ID!) {
    customView(id: $id) {
      toWidgetExport(widgetId: $widgetId)
    }
  }
`;

const onExportWidget = async (id: string, widget: { id: string; type: string }) => {
  const data = await fetchQuery(customViewExportWidgetQuery, { id, widgetId: widget.id })
    .toPromise();
  const result = data as useCustomViewDashboardEdit_WidgetExportQuery$data;
  const exportString = result.customView?.toWidgetExport;
  if (!exportString) {
    MESSAGING$.notifyError('Failed to export widget');
    return null;
  }
  return exportString;
};

const useCustomViewDashboardEdit = ({ customView }: {
  customView: useCustomViewDashboardEdit_Query$data['customView'];
}) => {
  const [commitSaveMutation] = useApiMutation<useCustomViewDashboardEdit_Mutation>(customViewMutation);
  const [commitSaveLayoutMutation] = useApiMutation<useCustomViewDashboardEdit_LayoutMutation>(customViewLayoutMutation);
  const [commitImportWidgetMutation] = useApiMutation<useCustomViewDashboardEdit_WidgetImportMutation>(customViewImportWidgetMutation);

  const onSave = (id: string, newManifestEncoded: string, noRefresh: boolean, onCompleted: () => void) => {
    const commitMutation = noRefresh ? commitSaveLayoutMutation : commitSaveMutation;
    commitMutation({
      variables: {
        id,
        input: [{
          key: 'manifest',
          value: [newManifestEncoded],
        }],
      },
      onCompleted,
      onError: () => {
        handleError('Failed to save custom view');
      },
    });
  };
  const onImportWidget = (id: string, widgetConfig: unknown, manifestEncoded: string) => {
    commitImportWidgetMutation({
      variables: {
        id,
        input: {
          file: widgetConfig,
          manifest: manifestEncoded,
        },
      },
      onError: () => {
        handleError('Failed to import widget');
      },
    });
  };

  return useDashboard({ entity: customView, onImportWidget, onSave, onExportWidget });
};

export default useCustomViewDashboardEdit;
