import { graphql } from 'react-relay';
import { useState } from 'react';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useFintelTemplateImportMutation } from './__generated__/useFintelTemplateImportMutation.graphql';

const fintelTemplateImportMutation = graphql`
  mutation useFintelTemplateImportMutation($file: Upload!) {
    fintelTemplateImport(file: $file) {
      ...FintelTemplateTabs_template
      ...FintelTemplateHeader_template
      ...FintelTemplateContentEditor_template
      ...FintelTemplateWidgetsSidebar_template
      ...FintelTemplatePreview_template
    }
  }
`;

const useFintelTemplateImport = () => {
  const [mutating, setMutating] = useState(false);
  const [commitImportMutation] = useApiMutation<useFintelTemplateImportMutation>(fintelTemplateImportMutation);

  const mutation: typeof commitImportMutation = ({ variables, onCompleted, onError }) => {
    setMutating(true);
    commitImportMutation({
      variables,
      onError: (error) => {
        setMutating(false);
        onError?.(error);
      },
      onCompleted: (...args) => {
        setMutating(false);
        onCompleted?.(...args);
      },
    });
  };

  return [mutation, mutating] as const;
};

export default useFintelTemplateImport;