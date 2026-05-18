import { useFragment } from 'react-relay';
import { graphql } from 'relay-runtime';
import { SubTypeQuery$data } from '../__generated__/SubTypeQuery.graphql';
import { CustomViewsSettingsContext_data$key } from './__generated__/CustomViewsSettingsContext_data.graphql';

const fragment = graphql`
  fragment CustomViewsSettingsContext_data on Query
    @argumentDefinitions(entityType: {type: "String!"}) {
    customViewsSettings(entityType: $entityType) {
      canEntityTypeHaveCustomViews
    }
  }
`;

export const useProvideCustomViewsSettingsContext = ({
  data,
}: { data?: SubTypeQuery$data | null | undefined }) => {
  const result = useFragment<CustomViewsSettingsContext_data$key>(fragment, data);
  const isCustomViewsEnabled = Boolean(result?.customViewsSettings?.canEntityTypeHaveCustomViews);
  return { isCustomViewsEnabled };
};
