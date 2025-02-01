import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import FintelTemplatePreview from './FintelTemplatePreview';
import { FintelTemplateProvider } from './FintelTemplateContext';
import FintelTemplateContentEditor from './FintelTemplateContentEditor';
import FintelTemplateTabs from './FintelTemplateTabs';
import FintelTemplateHeader from './FintelTemplateHeader';
import { FintelTemplateQuery } from './__generated__/FintelTemplateQuery.graphql';
import FintelTemplateWidgetsSidebar, { FINTEL_TEMPLATE_SIDEBAR_WIDTH } from './FintelTemplateWidgetsSidebar';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../../components/Loader';
import Security from '../../../../../utils/Security';
import { KNOWLEDGE } from '../../../../../utils/hooks/useGranted';

export const fintelTemplateQuery = graphql`
  query FintelTemplateQuery($id: ID!, $targetType: String!) {
    entitySettingByType(targetType: $targetType) {
      id 
    }
    fintelTemplate(id: $id) {
      ...FintelTemplateTabs_template
      ...FintelTemplateHeader_template
      ...FintelTemplateContentEditor_template
      ...FintelTemplateWidgetsSidebar_template
      ...FintelTemplatePreview_template
    }
  }
`;

interface FintelTemplateProps {
  queryRef: PreloadedQuery<FintelTemplateQuery>
}

const FintelTemplateComponent = ({ queryRef }: FintelTemplateProps) => {
  const { fintelTemplate, entitySettingByType } = usePreloadedQuery(fintelTemplateQuery, queryRef);
  if (!fintelTemplate || !entitySettingByType) return <ErrorNotFound/>;

  return (
    <FintelTemplateProvider>
      <div style={{ marginRight: FINTEL_TEMPLATE_SIDEBAR_WIDTH }}>
        <FintelTemplateHeader
          entitySettingId={entitySettingByType.id}
          data={fintelTemplate}
        />

        <FintelTemplateTabs data={fintelTemplate}>
          {({ index }) => (
            <>
              <div role="tabpanel" hidden={index !== 0}>
                <FintelTemplateContentEditor data={fintelTemplate} />
              </div>
              <Security needs={[KNOWLEDGE]}>
                <div role="tabpanel" hidden={index !== 1}>
                  <FintelTemplatePreview
                    isTabActive={index === 1}
                    data={fintelTemplate}
                  />
                </div>
              </Security>
            </>
          )}
        </FintelTemplateTabs>
      </div>

      <FintelTemplateWidgetsSidebar data={fintelTemplate} />
    </FintelTemplateProvider>
  );
};

const FintelTemplate = () => {
  const { templateId, subTypeId } = useParams<{ templateId?: string, subTypeId?: string }>();
  if (!templateId || !subTypeId) return <ErrorNotFound/>;

  const templateRef = useQueryLoading<FintelTemplateQuery>(
    fintelTemplateQuery,
    {
      id: templateId,
      targetType: subTypeId,
    },
  );

  return (
    <Suspense fallback={<Loader />}>
      {templateRef && <FintelTemplateComponent queryRef={templateRef} />}
    </Suspense>
  );
};

export default FintelTemplate;
