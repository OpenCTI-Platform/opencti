import Card from '@common/card/Card';
import { ListItem, ListItemText, Switch } from '@mui/material';
import { useFormatter } from '../../../components/i18n';
import Box from '@mui/material/Box';

interface Props {
  availableNewsFeedTypes?: string[];
  unsubscribedNewsFeedTypes?: string[];
  onSubmitField: (name: string, value: string[]) => void;
}

const isAllUnsubscribed = (unsubscribed: string[]): boolean => {
  return unsubscribed?.includes('*') ?? false;
};

const ProfileOverviewNewsFeed = ({
  availableNewsFeedTypes = [],
  unsubscribedNewsFeedTypes = [],
  onSubmitField,
}: Props) => {
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

  return (
    <Card title={t_i18n('XTM Hub Newsfeeds')}>
      <ListItem
        divider={!allUnsubscribed}
        sx={allUnsubscribed ? { padding: '0' } : { padding: '0 0 10px 0' }}
      >
        <ListItemText primary={t_i18n('Enable news feed notifications')} />
        <Switch
          checked={!allUnsubscribed}
          onChange={handleGlobalToggle}
        />
      </ListItem>
      {!allUnsubscribed && availableNewsFeedTypes.map((feedType) => (
        <ListItem key={feedType} sx={{ padding: '10px 0 0 0', opacity: 0.8 }}>
          <Box component="span" sx={{ mr: 1, ml: 1 }}>•</Box>
          <ListItemText secondary={t_i18n(feedType)} />
          <Switch
            checked={!unsubscribedNewsFeedTypes?.includes(feedType)}
            onChange={handleFeedTypeToggle(feedType)}
          />
        </ListItem>
      ))}
    </Card>
  );
};

export default ProfileOverviewNewsFeed;
