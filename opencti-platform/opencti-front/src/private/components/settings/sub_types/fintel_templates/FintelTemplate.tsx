import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import FintelTemplatePreview from '@components/settings/sub_types/fintel_templates/FintelTemplatePreview';
import FintelTemplateContentEditor from './FintelTemplateContentEditor';
import FintelTemplateTabs from './FintelTemplateTabs';
import FintelTemplateHeader from './FintelTemplateHeader';
import { FintelTemplateQuery } from './__generated__/FintelTemplateQuery.graphql';
import FintelTemplateSidebar, { FINTEL_TEMPLATE_SIDEBAR_WIDTH } from './FintelTemplateSidebar';
import useHelper from '../../../../../utils/hooks/useHelper';
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
    <>
      <div style={{ marginRight: FINTEL_TEMPLATE_SIDEBAR_WIDTH }}>
        <FintelTemplateHeader
          entitySettingId={entitySettingByType.id}
          data={fintelTemplate}
        />

        <FintelTemplateTabs data={fintelTemplate}>
          {({ index, setEditorValue, editorValue }) => (
            <>
              <div role="tabpanel" hidden={index !== 0}>
                <FintelTemplateContentEditor
                  data={fintelTemplate}
                  onChange={setEditorValue}
                />
              </div>
              <Security needs={[KNOWLEDGE]}>
                <div role="tabpanel" hidden={index !== 1}>
                  <FintelTemplatePreview
                    template_content={editorValue}
                    isTabActive={index === 1}
                  />
                </div>
              </Security>
            </>
          )}
        </FintelTemplateTabs>
      </div>

      <FintelTemplateSidebar />
    </>
  );
};

const FintelTemplate = () => {
  const { isFeatureEnable } = useHelper();
  const isFileFromTemplateEnabled = isFeatureEnable('FILE_FROM_TEMPLATE');
  if (!isFileFromTemplateEnabled) return null;

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