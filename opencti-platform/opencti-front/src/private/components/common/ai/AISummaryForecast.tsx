import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { graphql, useSubscription } from 'react-relay';
import Alert from '@mui/material/Alert';
import parse from 'html-react-parser';
import Divider from '@mui/material/Divider';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { AutoModeOutlined, ContentCopyOutlined } from '@mui/icons-material';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { AISummaryForecastStixCoreObjectAskAiForecastQuery$data } from '@components/common/ai/__generated__/AISummaryForecastStixCoreObjectAskAiForecastQuery.graphql';
import { AISummaryForecastSubscription, AISummaryForecastSubscription$data } from './__generated__/AISummaryForecastSubscription.graphql';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import { getDefaultAiLanguage } from '../../../../utils/ai/Common';
import { copyToClipboard } from '../../../../utils/utils';

const subscription = graphql`
    subscription AISummaryForecastSubscription($id: ID!) {
        aiBus(id: $id) {
            content
        }
    }
`;

const aISummaryForecastQuery = graphql`
  query AISummaryForecastStixCoreObjectAskAiForecastQuery($id: ID!, $language: String, $forceRefresh: Boolean) {
      stixCoreObjectAskAiForecast(id: $id, language: $language, forceRefresh: $forceRefresh) {
        result
        updated_at
    }
  }
`;

interface AISummaryForecastComponentProps {
  refetch: () => void
  language: string;
  setLanguage: (language: string) => void;
  content: string
  loading: boolean
  result: AISummaryForecastStixCoreObjectAskAiForecastQuery$data | null
}

const AISummaryForecastComponent = ({
  refetch,
  content,
  result,
  loading,
}: AISummaryForecastComponentProps) => {
  const { t_i18n, nsdt } = useFormatter();
  return (
    <>
      <Alert severity="info" variant="outlined" style={{ marginTop: 20 }}>
        {t_i18n('This forecast is based on the evolution of the activity of this entity (indicators, victimology, etc.). It has been generated by AI and can contain mistakes.')}
      </Alert>
      {parse(content)}
      {!loading && (
        <>
          <Divider />
          <div style={{ float: 'right', marginTop: 20, display: 'flex', alignItems: 'center', gap: '5px' }}>
            <Typography variant="caption">Generated on {nsdt(result?.stixCoreObjectAskAiForecast?.updated_at)}.</Typography>
            <IconButton size="small" color="primary" onClick={() => copyToClipboard(t_i18n, content)}>
              <ContentCopyOutlined fontSize="small" />
            </IconButton>
            <IconButton size="small" color="primary" onClick={() => refetch()}>
              <AutoModeOutlined fontSize="small" />
            </IconButton>
          </div>
        </>
      )}
    </>
  );
};

interface AISummaryForecastProps {
  id: string
  loading: boolean
  setLoading: (loading: boolean) => void
}

const AISummaryForecast = ({ id, loading, setLoading }: AISummaryForecastProps) => {
  const busId = `${id}-forecast`;
  const defaultLanguageName = getDefaultAiLanguage();
  const [content, setContent] = useState('');
  const [result, setResult] = useState<AISummaryForecastStixCoreObjectAskAiForecastQuery$data | null>(null);
  const [language, setLanguage] = useState(defaultLanguageName);

  // Subscription
  const handleResponse = (response: AISummaryForecastSubscription$data | null | undefined) => {
    const newContent = response ? (response as AISummaryForecastSubscription$data).aiBus?.content : null;
    const finalContent = (newContent ?? '')
      .replace('```html', '')
      .replace('```', '')
      .replace('<html>', '')
      .replace('</html>', '')
      .replace('<body>', '')
      .replace('</body>', '')
      .trim();
    return setContent(finalContent ?? '');
  };
  const subConfig = useMemo<GraphQLSubscriptionConfig<AISummaryForecastSubscription>>(
    () => ({
      subscription,
      variables: { id: busId },
      onNext: handleResponse,
    }),
    [busId],
  );
  // TODO: Check by the engineering team
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  useSubscription(subConfig);

  // Query
  const queryParams = {
    busId,
    id,
    language,
  };
  useEffect(() => {
    setLoading(true);
    fetchQuery(aISummaryForecastQuery, queryParams).toPromise().then((data) => {
      const resultData = data as AISummaryForecastStixCoreObjectAskAiForecastQuery$data;
      if (resultData && resultData.stixCoreObjectAskAiForecast) {
        setResult(resultData);
        setContent(resultData.stixCoreObjectAskAiForecast.result ?? '');
        setLoading(false);
      }
    });
  }, []);

  const refetch = useCallback(() => {
    setContent('');
    setLoading(true);
    fetchQuery(aISummaryForecastQuery, { ...queryParams, forceRefresh: true }).toPromise().then((data) => {
      const resultData = data as AISummaryForecastStixCoreObjectAskAiForecastQuery$data;
      if (resultData && resultData.stixCoreObjectAskAiForecast) {
        setResult(resultData);
        setContent(resultData.stixCoreObjectAskAiForecast.result ?? '');
        setLoading(false);
      }
    });
  }, []);

  return (
    <AISummaryForecastComponent
      language={language}
      setLanguage={setLanguage}
      refetch={refetch}
      content={content}
      result={result}
      loading={loading}
    />
  );
};

export default AISummaryForecast;