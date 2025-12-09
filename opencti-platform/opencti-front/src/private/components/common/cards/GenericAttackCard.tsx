import { FunctionComponent, MouseEvent } from 'react';
import * as R from 'ramda';
import CardActionArea from '@mui/material/CardActionArea';
import { Link } from 'react-router-dom';
import CardHeader from '@mui/material/CardHeader';
import IconButton from '@common/button/IconButton';
import { StarBorderOutlined } from '@mui/icons-material';
import CardContent from '@mui/material/CardContent';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import Skeleton from '@mui/material/Skeleton';
import { Stack } from '@mui/material';
import { useTheme } from '@mui/styles';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { renderCardTitle, toEdgesLocated } from '../../../../utils/Card';
import { emptyFilled } from '../../../../utils/String';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';
import { addBookmark, deleteBookMark } from '../stix_domain_objects/StixDomainObjectBookmark';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import Card from '../../../../components/common/card/Card';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  area: {
    width: '100%',
    height: '100%',
  },
  header: {
    height: 55,
    paddingBottom: 0,
    marginBottom: 0,
  },
  content: {
    width: '100%',
    padding: 0,
  },
  contentDummy: {
    width: '100%',
    height: 200,
    marginTop: 20,
    padding: 0,
  },
  description: {
    marginTop: 5,
    height: 65,
    display: '-webkit-box',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    '-webkit-line-clamp': 3,
    '-webkit-box-orient': 'vertical',
  },
  objectLabel: {
    height: 45,
    paddingTop: 14,
  },
  extras: {
    marginTop: 18,
  },
  extraColumn: {
    height: 58,
    width: '50%',
    float: 'left',
    display: '-webkit-box',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    '-webkit-line-clamp': 3,
    '-webkit-box-orient': 'vertical',
  },
  title: {
    fontWeight: 600,
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

  const handleBookmarksIds = (e: MouseEvent<HTMLElement>) => {
    e.preventDefault();
    if (bookmarksIds?.includes(cardData.id)) {
      deleteBookMark(cardData.id, entityType);
    } else {
      addBookmark(cardData.id, entityType);
    }
  };

  const Info = (props: { title: string; value: string }) => (
    <Stack direction="row" gap={1} alignItems="center">
      <Typography
        variant="h4"
        sx={{ margin: 0, color: theme.palette.text.secondary }}
      >
        {props.title}:
      </Typography>
      <Typography variant="body2">
        {props.value}
      </Typography>
    </Stack>
  );

  return (
    <Card>
      <CardActionArea
        classes={{ root: classes.area }}
        component={Link}
        to={cardLink}
      >
        <CardHeader
          sx={{ padding: 0 }}
          classes={{ root: classes.header, title: classes.title }}
          title={renderCardTitle(cardData)}
          subheader={fld(cardData.modified)}
          action={(
            <IconButton
              size="small"
              onClick={handleBookmarksIds}
              color={bookmarksIds?.includes(cardData.id) ? 'secondary' : 'primary'}
            >
              <StarBorderOutlined />
            </IconButton>
          )}
        />
        <CardContent className={classes.content}>
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
          <div className={classes.extras}>
            <Info
              title={t_i18n('Known as')}
              value={emptyFilled((cardData.aliases || []).join(', '))}
            />
            {entityType === 'Malware' ? (
              <Info
                title={t_i18n('Correlated intrusion sets')}
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
          <div className={classes.objectLabel}>
            <StixCoreObjectLabels
              labels={cardData.objectLabel}
              onClick={onLabelClick}
            />
          </div>
        </CardContent>
      </CardActionArea>
    </Card>
  );
};

export const GenericAttackCardDummy = () => {
  const classes = useStyles();
  return (
    <Card>
      <CardActionArea classes={{ root: classes.area }}>
        <CardHeader
          sx={{ padding: 0 }}
          classes={{ root: classes.header }}
          avatar={(
            <Skeleton
              animation="wave"
              variant="circular"
              width={30}
              height={30}
            />
          )}
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
          action={(
            <Skeleton
              animation="wave"
              variant="circular"
              width={30}
              height={30}
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
          <div className={classes.extras}>
            <div className={classes.extraColumn} style={{ paddingRight: 10 }}>
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
            <div className={classes.extraColumn} style={{ paddingLeft: 10 }}>
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
          </div>
        </CardContent>
      </CardActionArea>
    </Card>
  );
};
