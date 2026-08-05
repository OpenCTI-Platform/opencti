import { graphql } from 'react-relay';
import { fetchQuery, handleError, MESSAGING$ } from '../../../../../relay/environment';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useDashboard from '../../../../../components/dashboard/useDashboard';
import { useCustomViewDashboardEdit_Mutation } from './__generated__/useCustomViewDashboardEdit_Mutation.graphql';
import { useCustomViewDashboardEdit_LayoutMutation } from './__generated__/useCustomViewDashboardEdit_LayoutMutation.graphql';
import { useCustomViewDashboardEdit_WidgetImportMutation } from './__generated__/useCustomViewDashboardEdit_WidgetImportMutation.graphql';
import { useCustomViewDashboardEdit_Query$data } from './__generated__/useCustomViewDashboardEdit_Query.graphql';
import { useFormatter } from 'src/components/i18n';
import { useCustomViewDashboardEdit_WidgetExportQuery } from '@components/settings/sub_types/custom_views/__generated__/useCustomViewDashboardEdit_WidgetExportQuery.graphql';

export const customViewQuery = graphql`
  query useCustomViewDashboardEdit_Query($id: ID!) {
    customView(id: $id) {
      id
      name
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
  mutation useCustomViewDashboardEdit_Mutation($id: ID!, $input: [EditInput!]!) {
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

const useCustomViewDashboardEdit = ({
  customView,
}: {
  customView: useCustomViewDashboardEdit_Query$data['customView'];
}) => {
  const { t_i18n } = useFormatter();
  const [commitSaveMutation] =
    useApiMutation<useCustomViewDashboardEdit_Mutation>(customViewMutation);
  const [commitSaveLayoutMutation] =
    useApiMutation<useCustomViewDashboardEdit_LayoutMutation>(customViewLayoutMutation);
  const [commitImportWidgetMutation] =
    useApiMutation<useCustomViewDashboardEdit_WidgetImportMutation>(customViewImportWidgetMutation);

  const onSave = (
    id: string,
    newManifestEncoded: string,
    noRefresh: boolean,
    onCompleted: () => void,
  ) => {
    const commitMutation = noRefresh ? commitSaveLayoutMutation : commitSaveMutation;
    commitMutation({
      variables: {
        id,
        input: [
          {
            key: 'manifest',
            value: [newManifestEncoded],
          },
        ],
      },
      updater: (store, data) => {
        // Set the modified manifest in local Relay store
        // as we have an optim to avoid requerying the manifest
        // (see commitSaveLayoutMutation) but we want to avoid
        // displaying the previous layout when re-rendering the
        // same custom view even for a fraction of a second.
        if (data?.customViewEdit?.id) {
          const record = store.get(data.customViewEdit.id);
          if (record) {
            record.setValue(newManifestEncoded, 'manifest');
          }
        }
      },
      onCompleted,
      onError: () => {
        handleError('Failed to save custom view');
      },
    });
  };

  const onExportWidget = async (id: string, widget: { id: string; type: string }) => {
    try {
      const result = await fetchQuery<useCustomViewDashboardEdit_WidgetExportQuery>(
        customViewExportWidgetQuery,
        { id, widgetId: widget.id },
      ).toPromise();
      const exportString = result?.customView?.toWidgetExport;
      if (!exportString) {
        MESSAGING$.notifyError(t_i18n('Failed to export widget'));
        return null;
      }
      return exportString;
    } catch (e) {
      MESSAGING$.notifyRelayError(e);
      return null;
    }
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
