import { graphql } from 'react-relay';
import fileDownload from 'js-file-download';
import { fetchQuery } from '../../../../../relay/environment';
import { useFintelTemplateExportQuery$data } from './__generated__/useFintelTemplateExportQuery.graphql';

const fintelTemplateExportQuery = graphql`
  query useFintelTemplateExportQuery($id: ID!) {
    fintelTemplate(id: $id) {
      name
      toConfigurationExport
    }
  }
`;

const useFintelTemplateExport = () => {
  return async (templateId: string) => {
    const { fintelTemplate } = await fetchQuery(
      fintelTemplateExportQuery,
      { id: templateId },
    ).toPromise() as useFintelTemplateExportQuery$data;

    if (fintelTemplate) {
      const blob = new Blob([fintelTemplate.toConfigurationExport], { type: 'text/json' });
      const [day, month, year] = new Date().toLocaleDateString('fr-FR').split('/');
      const fileName = `${year}${month}${day}_fintel_${fintelTemplate.name}.json`;
      fileDownload(blob, fileName);
    }
  };
};

export default useFintelTemplateExport;
