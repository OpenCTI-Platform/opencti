import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { useState } from 'react';
import Alert from '@mui/material/Alert';
import parse from 'html-react-parser';
import AlertTitle from '@mui/material/AlertTitle';
import { AISummaryActivityQuery } from './__generated__/AISummaryActivityQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { getDefaultAiLanguage } from '../../../../utils/ai/Common';

const aISummaryActivityQuery = graphql`
  query AISummaryActivityQuery($id: ID!, $language: String) {
      stixCoreObjectAiActivity(id: $id, language: $language) {
        result
        trend
        updated_at
    }
  }
`;

interface AISummaryActivityComponentProps {
  queryRef: PreloadedQuery<AISummaryActivityQuery>;
  language: string;
  setLanguage: (language: string) => void;
}

const AISummaryActivityComponent = ({ queryRef }: AISummaryActivityComponentProps) => {
  const { t_i18n } = useFormatter();
  const { stixCoreObjectAiActivity } = usePreloadedQuery(
    aISummaryActivityQuery,
    queryRef,
  );
  const generateTrend = (trend: string) => {
    switch (trend) {
      case 'increasing':
        return (
          <Alert
            severity="error"
            variant="outlined"
            style={{ marginTop: 20 }}
          >
            <AlertTitle><strong>{t_i18n('Increasing')}</strong>: {t_i18n('The threat activity is showing a significant increase.')}</AlertTitle>
          </Alert>
        );
      case 'stable':
        return (
          <Alert
            severity="warning"
            variant="outlined"
            style={{ marginTop: 20 }}
          >
            <AlertTitle><strong>{t_i18n('Stable')}</strong>: {t_i18n('The threat activity is stable with minor fluctuations.')}</AlertTitle>
          </Alert>
        );
      case 'decreasing':
        return (
          <Alert
            severity="success"
            variant="outlined"
            style={{ marginTop: 20 }}
          >
            <AlertTitle><strong>{t_i18n('Decreasing')}</strong>: {t_i18n('The threat activity is showing a significant decrease.')}</AlertTitle>
          </Alert>
        );
      default:
        return (
          <Alert
            severity="info"
            variant="outlined"
            style={{ marginTop: 20 }}
          >
            <AlertTitle><strong>{t_i18n('Unknown')}</strong>: {t_i18n('The evaluation of the threat activity cannot be provided (lack of data).')}</AlertTitle>
          </Alert>
        );
    }
  };
  if (stixCoreObjectAiActivity && stixCoreObjectAiActivity.result) {
    return (
      <>
        {generateTrend(stixCoreObjectAiActivity.trend ?? 'unknown')}
        {parse(stixCoreObjectAiActivity.result)}
        <Alert severity="info" variant="outlined" style={{ marginTop: 20 }}>
          {t_i18n('This summary is based on the evolution of the activity of this entity (indicators, victimology, etc.). It has been generated by AI and can contain mistakes.')}
        </Alert>
      </>
    );
  }
  return (
    <div
      style={{
        display: 'table',
        height: '100%',
        width: '100%',
        paddingTop: 15,
        paddingBottom: 15,
      }}
    >
      <span
        style={{
          display: 'table-cell',
          verticalAlign: 'middle',
          textAlign: 'center',
        }}
      >
        {t_i18n('No AI Intelligence.')}
      </span>
    </div>
  );
};

interface AISummaryActivityProps {
  id: string
}

const AISummaryActivity = ({ id }: AISummaryActivityProps) => {
  const defaultLanguageName = getDefaultAiLanguage();
  const [language, setLanguage] = useState(defaultLanguageName);
  const queryRef = useQueryLoading<AISummaryActivityQuery>(aISummaryActivityQuery, { id, language });
  return (
    <>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <AISummaryActivityComponent
            queryRef={queryRef}
            language={language}
            setLanguage={setLanguage}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} withTopMargin={true} />
      )}
    </>
  );
};

export default AISummaryActivity;