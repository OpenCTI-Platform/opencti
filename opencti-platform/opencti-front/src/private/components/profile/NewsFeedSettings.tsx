import { ListItem, ListItemText, Switch } from '@mui/material';
import { useFormatter } from 'src/components/i18n';
import { isKnownNewsFeedType } from 'src/utils/NewsFeed';

interface NewsFeedSettingsProps {
  availableNewsFeedTypes?: string[];
  unsubscribedNewsFeedTypes?: string[];
  onSubmitField: (name: string, value: string[]) => void;
}

const isAllUnsubscribed = (unsubscribed: string[]): boolean => {
  return unsubscribed?.includes('*') ?? false;
};

const NewsFeedSettings = ({
  availableNewsFeedTypes = [],
  unsubscribedNewsFeedTypes = [],
  onSubmitField,
}: NewsFeedSettingsProps) => {
  const { t_i18n } = useFormatter();
  const allUnsubscribed = isAllUnsubscribed(unsubscribedNewsFeedTypes);

  const handleGlobalToggle = (_: unknown, value: boolean) => {
    onSubmitField('unsubscribed_news_feed_types', value ? [] : ['*']);
  };

  const handleFeedTypeToggle = (feedType: string) => (_: unknown, value: boolean) => {
    const current = unsubscribedNewsFeedTypes ?? [];
    const next = value
      ? current.filter((type) => type !== feedType)
      : [...current, feedType];
    onSubmitField('unsubscribed_news_feed_types', next);
  };

  const shouldDisplayItemsList = !allUnsubscribed && availableNewsFeedTypes.length > 0;

  return (
    <div>
      <ListItem
        divider={shouldDisplayItemsList}
        sx={!shouldDisplayItemsList ? { padding: '0' } : { padding: '0 0 10px 0' }}
      >
        <ListItemText
          primary={t_i18n('Enable News Feed notifications')}
          slotProps={{ primary: { fontWeight: 'bold' } }}
        />
        <Switch
          checked={!allUnsubscribed}
          onChange={handleGlobalToggle}
        />
      </ListItem>
      {!allUnsubscribed && availableNewsFeedTypes.map((feedType) => (
        <ListItem key={feedType} dense sx={{ padding: '4px 20px 0 20px', opacity: 0.8 }}>
          <ListItemText secondary={isKnownNewsFeedType(feedType) ? t_i18n(feedType) : t_i18n('Unsupported type')} />
          <Switch
            checked={!unsubscribedNewsFeedTypes?.includes(feedType)}
            onChange={handleFeedTypeToggle(feedType)}
          />
        </ListItem>
      ))}
    </div>
  );
};

export default NewsFeedSettings;
