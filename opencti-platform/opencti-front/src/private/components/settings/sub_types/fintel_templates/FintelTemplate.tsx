import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import FintelTemplateHeader from '@components/settings/sub_types/fintel_templates/FintelTemplateHeader';
import { FintelTemplateQuery } from './__generated__/FintelTemplateQuery.graphql';
import FintelTemplateSidebar, { FINTEL_TEMPLATE_SIDEBAR_WIDTH } from './FintelTemplateSidebar';
import useHelper from '../../../../../utils/hooks/useHelper';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../../components/Loader';

export const fintelTemplateQuery = graphql`
  query FintelTemplateQuery($id: ID!) {
    fintelTemplate(id: $id) {
      ...FintelTemplateHeader_template
    }
  }
`;

interface FintelTemplateProps {
  queryRef: PreloadedQuery<FintelTemplateQuery>
}

const FintelTemplateComponent = ({ queryRef }: FintelTemplateProps) => {
  const { fintelTemplate } = usePreloadedQuery(fintelTemplateQuery, queryRef);
  if (!fintelTemplate) return <ErrorNotFound/>;

  return (
    <>
      <div style={{ marginRight: FINTEL_TEMPLATE_SIDEBAR_WIDTH }}>
        <FintelTemplateHeader data={fintelTemplate} />
      </div>
      <FintelTemplateSidebar />
    </>
  );
};

const FintelTemplate = () => {
  const { isFeatureEnable } = useHelper();
  const isFileFromTemplateEnabled = isFeatureEnable('FILE_FROM_TEMPLATE');
  if (!isFileFromTemplateEnabled) return null;

  const { templateId } = useParams<{ templateId?: string }>();
  if (!templateId) return <ErrorNotFound/>;

  const templateRef = useQueryLoading<FintelTemplateQuery>(
    fintelTemplateQuery,
    { id: templateId },
  );

  return (
    <Suspense fallback={<Loader />}>
      {templateRef && <FintelTemplateComponent queryRef={templateRef} />}
    </Suspense>
  );
};

export default FintelTemplate;
