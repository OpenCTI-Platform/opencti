import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import Card from '@mui/material/Card';
import CardActionArea from '@mui/material/CardActionArea';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import { StarBorderOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import ItemIcon from '../../../../components/ItemIcon';
import { addBookmark, deleteBookMark } from '../../common/stix_domain_objects/StixDomainObjectBookmark';
import { emptyFilled } from '../../../../utils/String';
import { ThreatActorIndividualCard_node$key } from './__generated__/ThreatActorIndividualCard_node.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  card: {
    width: '100%',
    height: 320,
    borderRadius: 6,
  },
  cardDummy: {
    width: '100%',
    height: 320,
    color: theme.palette.grey[700],
    borderRadius: 6,
  },
  avatar: {
    backgroundColor: theme.palette.primary.main,
  },
  icon: {
    margin: '10px 20px 0 0',
    fontSize: 40,
    color: '#242d30',
  },
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
    paddingTop: 0,
  },
  contentDummy: {
    width: '100%',
    height: 200,
    marginTop: 20,
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
    paddingTop: 15,
  },
  extras: {
    marginTop: 25,
  },
  extraColumn: {
    height: 45,
    width: '50%',
    float: 'left',
    display: '-webkit-box',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    '-webkit-line-clamp': 2,
    '-webkit-box-orient': 'vertical',
  },
  title: {
    fontWeight: 600,
  },
}));

const ThreatActorIndividualCardFragment = graphql`
  fragment ThreatActorIndividualCard_node on ThreatActorIndividual {
    id
    name
    aliases
    description
    created
    modified
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
    objectMarking {
      edges {
        node {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
      }
    }
    targetedCountries: stixCoreObjectsDistribution(
      operation: count
      field: "internal_id"
      relationship_type: ["targets"]
      types: ["Country"]
      limit: 5
    ) {
      label
      entity {
        ... on Country {
          name
        }
      }
    }
    targetedSectors: stixCoreObjectsDistribution(
      operation: count
      field: "internal_id"
      relationship_type: ["targets"]
      types: ["Sector"]
      limit: 5
    ) {
      label
      entity {
        ... on Sector {
          name
        }
      }
    }
    usedMalware: stixCoreObjectsDistribution(
      operation: count
      field: "internal_id"
      relationship_type: ["uses"]
      types: ["Malware"]
      limit: 5
    ) {
      label
      entity {
        ... on Malware {
          name
        }
      }
    }
  }
`;
interface ThreatActorIndividualCardProps {
  node: ThreatActorIndividualCard_node$key;
  onLabelClick: () => void;
  bookmarksIds?: string[]
}
export const ThreatActorIndividualCard: FunctionComponent<ThreatActorIndividualCardProps> = ({
  node,
  onLabelClick,
  bookmarksIds,
}) => {
  const classes = useStyles();
  const { t, fld } = useFormatter();
  const data = useFragment(ThreatActorIndividualCardFragment, node);
  const usedMalware = (data?.usedMalware ?? []).map((n) => n?.entity?.name).join(', ');
  const targetedCountries = (data?.targetedCountries ?? [])
    .map((n) => n?.entity?.name)
    .join(', ');
  const targetedSectors = (data?.targetedSectors ?? [])
    .map((n) => n?.entity?.name)
    .join(', ');

  const handleBookmarksIds = () => {
    if (bookmarksIds?.includes(data.id)) {
      deleteBookMark(data.id, 'Threat-Actor-Individual');
    } else {
      addBookmark(data.id, 'Threat-Actor-Individual');
    }
  };
  const bookMarksIdsColor = () => {
    return bookmarksIds?.includes(data.id) ? 'secondary' : 'primary';
  };
  return (
    <Card classes={{ root: classes.card }} variant="outlined">
      <CardActionArea
        classes={{ root: classes.area }}
        component={Link}
        to={`/dashboard/threats/threat_actors_individual/${data.id}`}
      >
        <CardHeader
          classes={{ root: classes.header, title: classes.title }}
          avatar={<ItemIcon type="Threat-Actor" size="large" />}
          title={data.name}
          subheader={fld(data.modified)}
          action={
            <IconButton
              size="small"
              onClick={handleBookmarksIds}
              color={bookMarksIdsColor()}
            >
              <StarBorderOutlined />
            </IconButton>
          }
        />
        <CardContent className={classes.content}>
          <div className={classes.description}>
            <MarkdownDisplay
              content={data.description}
              remarkGfmPlugin={true}
              commonmark={true}
              removeLinks={true}
              limit={260}
            />
          </div>
          <div className={classes.extras}>
            <div className={classes.extraColumn} style={{ paddingRight: 10 }}>
              <Typography variant="h4">{t('Known as')}</Typography>
              <Typography variant="body2">
                {emptyFilled((data.aliases || []).join(', '))}
              </Typography>
            </div>
            <div className={classes.extraColumn} style={{ paddingLeft: 10 }}>
              <Typography variant="h4">{t('Used malware')}</Typography>
              <Typography variant="body2">
                {emptyFilled(usedMalware)}
              </Typography>
            </div>
            <div className="clearfix" />
          </div>
          <div className={classes.extras}>
            <div className={classes.extraColumn} style={{ paddingRight: 10 }}>
              <Typography variant="h4">{t('Targeted countries')}</Typography>
              <Typography variant="body2">
                {emptyFilled(targetedCountries)}
              </Typography>
            </div>
            <div className={classes.extraColumn} style={{ paddingLeft: 10 }}>
              <Typography variant="h4">{t('Targeted sectors')}</Typography>
              <Typography variant="body2">
                {emptyFilled(targetedSectors)}
              </Typography>
            </div>
            <div className="clearfix" />
          </div>
          <div className={classes.objectLabel}>
            <StixCoreObjectLabels
              labels={data.objectLabel}
              onClick={onLabelClick}
            />
          </div>
        </CardContent>
      </CardActionArea>
    </Card>
  );
};

export const ThreatActorIndividualCardDummy = () => {
  const classes = useStyles();
  return (
    <Card classes={{ root: classes.cardDummy }} variant="outlined">
      <CardActionArea classes={{ root: classes.area }}>
        <CardHeader
          classes={{ root: classes.header }}
          avatar={
            <Skeleton
              animation="wave"
              variant="circular"
              width={30}
              height={30}
            />
          }
          title={
            <Skeleton
              animation="wave"
              variant="rectangular"
              width="90%"
              style={{ marginBottom: 10 }}
            />
          }
          titleTypographyProps={{ color: 'inherit' }}
          subheader={
            <Skeleton
              animation="wave"
              variant="rectangular"
              width="90%"
              style={{ marginBottom: 10 }}
            />
          }
          action={
            <Skeleton
              animation="wave"
              variant="circular"
              width={30}
              height={30}
            />
          }
        />
        <CardContent classes={{ root: classes.contentDummy }}>
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="90%"
            style={{ marginBottom: 10 }}
          />
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="95%"
            style={{ marginBottom: 10 }}
          />
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="90%"
            style={{ marginBottom: 10 }}
          />
        </CardContent>
      </CardActionArea>
    </Card>
  );
};
