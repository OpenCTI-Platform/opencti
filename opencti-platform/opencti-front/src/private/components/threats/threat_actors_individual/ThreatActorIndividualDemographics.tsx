import { makeStyles } from '@mui/styles';
import { Chip, Grid, Paper, Typography } from '@mui/material';
import parse from 'html-react-parser';
import { useState } from 'react';
import { graphql } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import { ThreatActorIndividual_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividual_ThreatActorIndividual.graphql';
import { fetchQuery } from '../../../../relay/environment';
import { ThreatActorIndividualDemographicsCountryRelationshipsQuery$data } from './__generated__/ThreatActorIndividualDemographicsCountryRelationshipsQuery.graphql';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';

export const getDemographicCountryRelationship = graphql`
  query ThreatActorIndividualDemographicsCountryRelationshipsQuery($id: String!) {
    threatActorIndividual(id:$id) {
      bornIn {
        name
      }
      nationality {
        name
      }
      ethnicity {
        name
      }
      stixCoreRelationships {
        edges {
          node {
            relationship_type
            to {
              ... on Country {
                id
                name
              }
            }
          }
        }
      }
    }
  }
`;

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
  place_of_birth: string | undefined,
  nationality: string | undefined,
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

  const [countryRelationship, setCountryRelationships] = useState<ThreatActorIndividualDemographicsCountryRelationships>({
    country_of_residence: [],
    citizenship: [],
    place_of_birth: undefined,
    nationality: undefined,
    ethnicity: undefined,
  });

  fetchQuery(
    getDemographicCountryRelationship,
    { id: threatActorIndividual?.id },
  ).subscribe({
    closed: false,
    error: () => {},
    complete: () => {},
    next: (
      data: ThreatActorIndividualDemographicsCountryRelationshipsQuery$data,
    ) => {
      const fetchedCountryRelationships:
      ThreatActorIndividualDemographicsCountryRelationships = {
        country_of_residence: [],
        citizenship: [],
        place_of_birth: data?.threatActorIndividual?.bornIn?.name,
        nationality: data?.threatActorIndividual?.nationality?.name,
        ethnicity: data?.threatActorIndividual?.ethnicity?.name,
      };
      const edges = data
        ?.threatActorIndividual
        ?.stixCoreRelationships
        ?.edges
          ?? [];
      for (const { node } of edges) {
        const { relationship_type } = node ?? {};
        const name = node?.to?.name;
        if (name) {
          switch (relationship_type) {
            case 'resides-in':
              fetchedCountryRelationships.country_of_residence.push(name);
              break;
            case 'citizen-of':
              fetchedCountryRelationships.citizenship.push(name);
              break;
            default:
          }
        }
      }
      setCountryRelationships(fetchedCountryRelationships);
    },
  });

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Demographic Information')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} spacing={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Country of Residence')}
            </Typography>
            <div id='mcas_country_of_residence_list'>
              {countryRelationship?.country_of_residence && countryRelationship?.country_of_residence.length > 0
                ? countryRelationship?.country_of_residence.map((place: string, index: number) => (
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
          <Grid item={true} spacing={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Citizenship')}
            </Typography>
            <div id='mcas_citizenship_list'>
              {countryRelationship?.citizenship && countryRelationship?.citizenship.length > 0
                ? countryRelationship?.citizenship.map((place: string, index: number) => (
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
          <Grid item={true} spacing={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Place of Birth')}
            </Typography>
            <div id='place_of_birth'>
              {parse(t(countryRelationship?.place_of_birth ?? '-'))}
            </div>
          </Grid>
          <Grid item={true} spacing={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Date of Birth')}
            </Typography>
            <div id='date_of_birth'>
              {threatActorIndividual?.date_of_birth ? fsd(threatActorIndividual?.date_of_birth) : '-'}
            </div>
          </Grid>
          <Grid item={true} spacing={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Nationality')}
            </Typography>
            <div id='nationality'>
              {parse(t(countryRelationship?.nationality ?? '-'))}
            </div>
          </Grid>
          <Grid item={true} spacing={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Ethnicity')}
            </Typography>
            <div id='ethnicity'>
              {parse(t(countryRelationship?.ethnicity ?? '-'))}
            </div>
          </Grid>
          <Grid item={true} spacing={4}>
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
          <Grid item={true} spacing={4}>
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
          <Grid item={true} spacing={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Job Title')}
            </Typography>
            <div id='job_title'>
              {/* Parse to verify Safe HTML */}
              {parse(threatActorIndividual?.job_title || '-')}
            </div>
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default ThreatActorIndividualDemographics;
