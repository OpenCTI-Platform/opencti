import { makeStyles } from '@mui/styles';
import { Chip, Grid, Paper, Typography } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { ThreatActorIndividual_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividual_ThreatActorIndividual.graphql';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
}));

interface ThreatActorIndividualDemographicsCountryRelationships {
  country_of_residence: Array<string>,
  citizenship: Array<string>,
  nationality: Array<string>,
  place_of_birth: string | undefined,
  ethnicity: string | undefined,
}

interface ThreatActorIndividualDemographicsProps {
  threatActorIndividual: ThreatActorIndividual_ThreatActorIndividual$data
}

const ThreatActorIndividualDemographics = (
  { threatActorIndividual }: ThreatActorIndividualDemographicsProps,
) => {
  const classes = useStyles();
  const { t, fsd } = useFormatter();
  const countryRelationship: ThreatActorIndividualDemographicsCountryRelationships = {
    country_of_residence: [],
    citizenship: [],
    nationality: [],
    place_of_birth: threatActorIndividual.bornIn?.name,
    ethnicity: threatActorIndividual.ethnicity?.name,
  };
  const edges = threatActorIndividual.stixCoreRelationships?.edges ?? [];
  for (const { node } of edges) {
    const { relationship_type } = node ?? {};
    const name = node?.to?.name;
    if (name) {
      switch (relationship_type) {
        case 'resides-in':
          countryRelationship.country_of_residence.push(name);
          break;
        case 'citizen-of':
          countryRelationship.citizenship.push(name);
          break;
        case 'national-of':
          countryRelationship.nationality.push(name);
          break;
        default:
      }
    }
  }
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Demographic Information')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Country of Residence')}
            </Typography>
            <div id='mcas_country_of_residence_list'>
              {countryRelationship.country_of_residence.length > 0
                ? countryRelationship.country_of_residence.map((place: string, index: number) => (
                  <Chip
                    key={index}
                    label={t(place)}
                    style={{ margin: 1 }}
                  />
                ))
                : '-'
              }
            </div>
          </Grid>
          <Grid item={true} xs={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Citizenship')}
            </Typography>
            <div id='mcas_citizenship_list'>
              {countryRelationship.citizenship.length > 0
                ? countryRelationship.citizenship.map((place: string, index: number) => (
                  <Chip
                    key={index}
                    label={t(place)}
                    style={{ margin: 1 }}
                  />
                ))
                : '-'
              }
            </div>
          </Grid>
          <Grid item={true} xs={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Place of Birth')}
            </Typography>
            <div id='place_of_birth'>
              {t(countryRelationship.place_of_birth ?? '-')}
            </div>
          </Grid>
          <Grid item={true} xs={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Date of Birth')}
            </Typography>
            <div id='date_of_birth'>
              {threatActorIndividual.date_of_birth ? fsd(threatActorIndividual.date_of_birth) : '-'}
            </div>
          </Grid>
          <Grid item={true} xs={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Nationality')}
            </Typography>
            <div id='nationality'>
              {countryRelationship.nationality && countryRelationship.nationality.length > 0
                ? countryRelationship.nationality.map((place: string, index: number) => (
                  <Chip
                    key={index}
                    label={t(place)}
                    style={{ margin: 1 }}
                  />
                ))
                : '-'
              }
            </div>
          </Grid>
          <Grid item={true} xs={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Ethnicity')}
            </Typography>
            <div id='ethnicity'>
              {t(countryRelationship.ethnicity ?? '-')}
            </div>
          </Grid>
          <Grid item={true} xs={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Gender')}
            </Typography>
            <ItemOpenVocab
              type="gender-ov"
              value={threatActorIndividual.gender}
              small
            />
          </Grid>
          <Grid item={true} xs={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Marital Status')}
            </Typography>
            <ItemOpenVocab
              type="marital-status-ov"
              value={threatActorIndividual.marital_status}
              small
            />
          </Grid>
          <Grid item={true} xs={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Job Title')}
            </Typography>
            <div id='job_title'>
              {threatActorIndividual.job_title ?? '-'}
            </div>
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default ThreatActorIndividualDemographics;
