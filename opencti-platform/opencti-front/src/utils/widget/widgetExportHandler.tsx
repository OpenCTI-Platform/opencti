import fileDownload from 'js-file-download';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../relay/environment';
import { widgetExportHandlerQuery$data } from './__generated__/widgetExportHandlerQuery.graphql';

interface widgetToExport {
  id: string;
  type: string;
}

const widgetExportHandlerQuery = graphql`
  query widgetExportHandlerQuery($id: String!, $widgetId: ID!) {
    workspace(id: $id) {
      toWidgetExport(widgetId: $widgetId)
    }
  }
`;

const handleWidgetExportJson = (id: string, widget: widgetToExport) => {
  fetchQuery(widgetExportHandlerQuery, { id, widgetId: widget.id })
    .toPromise()
    .then((data) => {
      const result = data as widgetExportHandlerQuery$data;
      if (result.workspace) {
        const blob = new Blob([result.workspace.toWidgetExport], {
          type: 'text/json',
        });
        const [day, month, year] = new Date()
          .toLocaleDateString('fr-FR')
          .split('/');
        const fileName = `${year}${month}${day}_octi_widget_${widget.type}.json`;
        fileDownload(blob, fileName);
      }
    });
};

export default handleWidgetExportJson;
