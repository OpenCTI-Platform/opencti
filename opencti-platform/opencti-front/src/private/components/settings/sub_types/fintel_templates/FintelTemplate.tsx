import React, { Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import { Tabs, Tab, Box } from '@mui/material';
import FintelTemplateContentEditor from '@components/settings/sub_types/fintel_templates/FintelTemplateContentEditor';
import FintelTemplateHeader from './FintelTemplateHeader';
import { FintelTemplateQuery } from './__generated__/FintelTemplateQuery.graphql';
import FintelTemplateSidebar, { FINTEL_TEMPLATE_SIDEBAR_WIDTH } from './FintelTemplateSidebar';
import useHelper from '../../../../../utils/hooks/useHelper';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../../components/Loader';
import { useFormatter } from '../../../../../components/i18n';

export const fintelTemplateQuery = graphql`
  query FintelTemplateQuery($id: ID!, $targetType: String!) {
    entitySettingByType(targetType: $targetType) {
      id 
    }
    fintelTemplate(id: $id) {
      ...FintelTemplateHeader_template
      ...FintelTemplateContentEditor_template
    }
  }
`;

interface FintelTemplateProps {
  queryRef: PreloadedQuery<FintelTemplateQuery>
}

const FintelTemplateComponent = ({ queryRef }: FintelTemplateProps) => {
  const { t_i18n } = useFormatter();
  const [tabIndex, setTabIndex] = useState(0);

  const { fintelTemplate, entitySettingByType } = usePreloadedQuery(fintelTemplateQuery, queryRef);
  if (!fintelTemplate || !entitySettingByType) return <ErrorNotFound/>;

  return (
    <>
      <div style={{ marginRight: FINTEL_TEMPLATE_SIDEBAR_WIDTH }}>
        <FintelTemplateHeader
          entitySettingId={entitySettingByType.id}
          data={fintelTemplate}
        />

        <Box sx={{ borderBottom: 1, borderColor: 'divider', marginBottom: 3 }}>
          <Tabs value={tabIndex} onChange={(_, i) => setTabIndex(i)}>
            <Tab label={t_i18n('Content Editor')} />
            <Tab label={t_i18n('Content Preview')} />
          </Tabs>
        </Box>

        <div role="tabpanel" hidden={tabIndex !== 0}>
          <FintelTemplateContentEditor data={fintelTemplate} />
        </div>
        <div role="tabpanel" hidden={tabIndex !== 1}>
          ccsv
        </div>
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
