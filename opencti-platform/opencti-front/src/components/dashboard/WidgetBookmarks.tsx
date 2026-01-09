import Grid from '@mui/material/Grid';
import CardHeader from '@mui/material/CardHeader';
import Avatar from '@mui/material/Avatar';
import { useTheme } from '@mui/styles';
import ItemIcon from '../ItemIcon';
import { resolveLink } from '../../utils/Entity';
import { useFormatter } from '../i18n';
import type { Theme } from '../Theme';
import Card from '../common/card/Card';

interface WidgetBookmarksProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  bookmarks: any[];
}

const WidgetBookmarks = ({ bookmarks }: WidgetBookmarksProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fsd } = useFormatter();

  return (
    <div
      id="container"
      style={{
        width: '100%',
        height: '100%',
        overflow: 'auto',
        paddingBottom: 10,
        marginBottom: 10,
      }}
    >
      <Grid container={true} spacing={3}>
        {bookmarks.map((bookmarkEdge) => {
          const bookmark = bookmarkEdge.node;
          const link = resolveLink(bookmark.entity_type);
          return (
            <Grid item xs={4} key={bookmark.id}>
              <Card
                padding="none"
                variant="outlined"
                to={`${link}/${bookmark.id}`}
              >
                <CardHeader
                  sx={{
                    paddingBottom: 0,
                    marginBottom: 0,
                  }}
                  avatar={(
                    <Avatar sx={{ backgroundColor: theme.palette.primary.main }}>
                      <ItemIcon
                        type={bookmark.entity_type}
                        color={theme.palette.background.default}
                      />
                    </Avatar>
                  )}
                  title={bookmark.name}
                  subheader={`${t_i18n('Updated on')} ${fsd(bookmark.modified)}`}
                />
              </Card>
            </Grid>
          );
        })}
      </Grid>
    </div>
  );
};

export default WidgetBookmarks;
