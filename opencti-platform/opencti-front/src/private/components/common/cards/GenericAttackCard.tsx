import { FunctionComponent } from 'react';
import * as R from 'ramda';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import Skeleton from '@mui/material/Skeleton';
import { CardActions, Stack } from '@mui/material';
import { useTheme } from '@mui/styles';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { renderCardTitle, toEdgesLocated } from '../../../../utils/Card';
import { emptyFilled } from '../../../../utils/String';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import Card from '../../../../components/common/card/Card';
import BookmarkToggle from '../../../../components/common/bookmark/BookmarkToggle';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  header: {
    height: 55,
    paddingBottom: 0,
    marginBottom: 0,
  },
  contentDummy: {
    width: '100%',
    height: 200,
    marginTop: 20,
    padding: 0,
  },
  description: {
    marginTop: 5,
    height: 90,
    display: '-webkit-box',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    '-webkit-line-clamp': 4,
    '-webkit-box-orient': 'vertical',
  },
}));

interface toEdges {
  edges: ReadonlyArray<{ node: { to: { name?: string } | null } }>;
}

interface fromEdges {
  edges: ReadonlyArray<{ node: { from: { name?: string } | null } }>;
}

export interface DraftVersion {
  draft_id: string;
  draft_operation: string;
}

export interface GenericAttack {
  id: string;
  draftVersion: DraftVersion | null;
  name: string;
  description: string | null;
  modified: string;
  aliases: ReadonlyArray<string | null> | null;
  objectLabel: ReadonlyArray<{ id: string; value: string | null; color: string | null | undefined }> | null | undefined;
  avatar?: { id: string; name: string } | null;
  relatedIntrusionSets?: fromEdges | null;
  usedMalware?: toEdges | null;
  targetedCountries: toEdges | null;
  targetedSectors: toEdges | null;
  countryFlag?: toEdgesLocated | null;
}

interface GenericAttackCardProps {
  cardData: GenericAttack;
  cardLink: string;
  entityType: string;
  onLabelClick: HandleAddFilter;
  bookmarksIds?: string[];
}

export const GenericAttackCard: FunctionComponent<GenericAttackCardProps> = ({
  cardData,
  cardLink,
  entityType,
  onLabelClick,
  bookmarksIds,
}) => {
  const classes = useStyles();
  const theme = useTheme<Theme>();
  const { t_i18n, fld } = useFormatter();

  const isBookmarked = !!bookmarksIds?.includes(cardData.id);

  const relatedIntrusionSets = R.uniq((cardData.relatedIntrusionSets?.edges ?? [])
    .map((n) => n?.node?.from?.name))
    .join(', ');
  const usedMalware = R.uniq((cardData.usedMalware?.edges ?? [])
    .map((n) => n?.node?.to?.name))
    .join(', ');
  const targetedCountries = R.uniq((cardData.targetedCountries?.edges ?? [])
    .map((n) => n?.node?.to?.name))
    .join(', ');
  const targetedSectors = R.uniq((cardData.targetedSectors?.edges ?? [])
    .map((n) => n?.node?.to?.name))
    .join(', ');

  const Info = (props: { title: string; value: string }) => (
    <Stack direction="row" gap={1} alignItems="center">
      <Typography
        variant="h4"
        sx={{
          margin: 0,
          color: theme.palette.text.secondary,
          whiteSpace: 'nowrap',
        }}
      >
        {props.title}:
      </Typography>
      <Typography
        variant="body2"
        sx={{
          margin: 0,
          whiteSpace: 'nowrap',
          textOverflow: 'ellipsis',
          overflow: 'hidden',
          minWidth: 0,
        }}
      >
        {props.value}
      </Typography>
    </Stack>
  );

  return (
    <Card to={cardLink}>
      <CardHeader
        title={renderCardTitle(cardData)}
        subheader={t_i18n(
          'Last modified on',
          { values: { date: fld(cardData.modified) } },
        )}
        sx={{
          padding: 0,
          mb: 2,
          '.MuiCardHeader-content': {
            minWidth: 0,
          },
          '.MuiCardHeader-subheader': {
            fontSize: 12,
            color: theme.palette.text.secondary,
          },
        }}
      />
      <CardContent sx={{ p: 0 }}>
        <div className={classes.description}>
          <MarkdownDisplay
            content={cardData.description}
            remarkGfmPlugin={true}
            commonmark={true}
            removeLinks={true}
            removeLineBreaks={true}
            limit={260}
          />
        </div>
        <div style={{ paddingTop: 12 }}>
          <Info
            title={t_i18n('Known as')}
            value={emptyFilled((cardData.aliases || []).join(', '))}
          />
          {entityType === 'Malware' ? (
            <Info
              title={t_i18n('Intrusion sets')}
              value={emptyFilled(relatedIntrusionSets)}
            />
          ) : (
            <Info
              title={t_i18n('Used malware')}
              value={emptyFilled(usedMalware)}
            />
          )}
          <Info
            title={t_i18n('Targeted countries')}
            value={emptyFilled(targetedCountries)}
          />
          <Info
            title={t_i18n('Targeted sectors')}
            value={emptyFilled(targetedSectors)}
          />
        </div>
      </CardContent>
      <CardActions sx={{ p: 0, mt: 2, justifyContent: 'space-between' }}>
        <StixCoreObjectLabels
          labels={cardData.objectLabel}
          onClick={onLabelClick}
        />
        <BookmarkToggle
          stixId={cardData.id}
          stixEntityType={entityType}
          isBookmarked={isBookmarked}
        />
      </CardActions>
    </Card>
  );
};

export const GenericAttackCardDummy = () => {
  const classes = useStyles();
  return (
    <Card>
      <CardHeader
        sx={{ padding: 0 }}
        classes={{ root: classes.header }}
        title={(
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="90%"
            style={{ marginBottom: 10 }}
          />
        )}
        subheader={(
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="90%"
            style={{ marginBottom: 10 }}
          />
        )}
        slotProps={{
          title: { color: 'inherit' },
        }}
      />
      <CardContent classes={{ root: classes.contentDummy }}>
        <div className={classes.description}>
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="90%"
            style={{ marginBottom: 10 }}
          />
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="80%"
            style={{ marginBottom: 10 }}
          />
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="90%"
            style={{ marginBottom: 10 }}
          />
        </div>
        <div>
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="100%"
            style={{ marginBottom: 10 }}
          />
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="100%"
            style={{ marginBottom: 10 }}
          />
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="100%"
            style={{ marginBottom: 10 }}
          />
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="100%"
            style={{ marginBottom: 10 }}
          />
        </div>
      </CardContent>
    </Card>
  );
};
