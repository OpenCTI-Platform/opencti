import fileDownload from 'js-file-download';
import { graphql } from 'react-relay';
import { FormExportHandlerQuery$data } from '@components/data/forms/__generated__/FormExportHandlerQuery.graphql';
import { fetchQuery } from '../../../../relay/environment';

interface formToExport {
  id: string;
  name: string;
}

const FormExportHandlerQuery = graphql`
  query FormExportHandlerQuery($id: ID!) {
    form(id: $id) {
      toConfigurationExport
    }
  }
`;

const handleExportJson = (form: formToExport) => {
  fetchQuery(FormExportHandlerQuery, { id: form.id })
    .toPromise()
    .then((data) => {
      const result = data as FormExportHandlerQuery$data;
      if (result.form) {
        const blob = new Blob([result.form.toConfigurationExport], { type: 'text/json' });
        const [day, month, year] = new Date().toLocaleDateString('fr-FR').split('/');
        const fileName = `${year}${month}${day}_octi_form_${form.name}.json`;
        fileDownload(blob, fileName);
      }
    });
};

export default handleExportJson;
