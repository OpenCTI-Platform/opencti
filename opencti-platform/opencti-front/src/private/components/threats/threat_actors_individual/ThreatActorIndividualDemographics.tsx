import { makeStyles } from '@mui/styles';
import { Chip, Grid, Paper, Typography } from '@mui/material';
import parse from 'html-react-parser';
import { useState } from 'react';
import { graphql } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import Origin from '../../common/form/mcas/OriginEnum';
import { ThreatActorIndividual_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividual_ThreatActorIndividual.graphql';
import { MaritalStatus } from '../../common/form/mcas/MaritalStatusField';
import { Genders } from '../../common/form/mcas/GenderField';
import { fetchQuery } from '../../../../relay/environment';
import { ThreatActorIndividualDemographicsCountryRelationshipsQuery$data } from './__generated__/ThreatActorIndividualDemographicsCountryRelationshipsQuery.graphql';

export const getDemographicCountryRelationship = graphql`
  query ThreatActorIndividualDemographicsCountryRelationshipsQuery($id: String!) {
    threatActorIndividual(id:$id) {
      bornIn {
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
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
}));

interface ThreatActorIndividualDemographicsCountryRelationships {
  x_mcas_country_of_residence: Array<string>,
  x_mcas_citizenship: Array<string>,
  x_mcas_place_of_birth: string | undefined,
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
    x_mcas_country_of_residence: [],
    x_mcas_citizenship: [],
    x_mcas_place_of_birth: undefined,
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
        x_mcas_country_of_residence: [],
        x_mcas_citizenship: [],
        x_mcas_place_of_birth: data?.threatActorIndividual?.bornIn?.name,
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
              fetchedCountryRelationships.x_mcas_country_of_residence.push(name);
              break;
            case 'citizen-of':
              fetchedCountryRelationships.x_mcas_citizenship.push(name);
              break;
            default:
          }
        }
      }
      setCountryRelationships(fetchedCountryRelationships);
    },
  });

  function toVal(value: string, dict: Record<string, string>) {
    return t(Object.values(dict)[Object.keys(dict).indexOf(value)]);
  }

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Demographic Information')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          {/* Row #1 */}
          <Grid item={true} xs={3} style={{ marginTop: -1 }}>
            <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
              {t('Country of Residence')}
            </Typography>
          </Grid>

          <Grid item={true} xs={3} style={{ marginTop: -1 }}>
            <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
              {t('Citizenship')}
            </Typography>
          </Grid>

          <Grid item={true} xs={3} style={{ marginTop: -1 }}>
            <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
              {t('Place of Birth')}
            </Typography>
          </Grid>

          <Grid item={true} xs={3} style={{ marginTop: -1 }}>
            <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
              {t('Date of Birth')}
            </Typography>
          </Grid>

          {/* Row #2 */}
          <Grid item={true} xs={3} style={{ marginTop: -20 }}>
            <div id='mcas_country_of_residence_list'>
              {countryRelationship?.x_mcas_country_of_residence && countryRelationship?.x_mcas_country_of_residence.length > 0
                ? countryRelationship?.x_mcas_country_of_residence.map((place: string, index: number) => (
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

          <Grid item={true} xs={3} style={{ marginTop: -20 }}>
            <div id='mcas_citizenship_list'>
              {countryRelationship?.x_mcas_citizenship && countryRelationship?.x_mcas_citizenship.length > 0
                ? countryRelationship?.x_mcas_citizenship.map((place: string, index: number) => (
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

          <Grid item={true} xs={3} style={{ marginTop: -20 }}>
            <div id='mcas_place_of_birth'>
              {parse(t(countryRelationship?.x_mcas_place_of_birth ?? '-'))}
            </div>
          </Grid>
          <Grid item={true} xs={3} style={{ marginTop: -20 }}>
            <div id='mcas_date_of_birth'>
              {threatActorIndividual?.x_mcas_date_of_birth ? fsd(threatActorIndividual?.x_mcas_date_of_birth) : '-'}
            </div>
          </Grid>
          {/* Row #3 */}
          <Grid item={true} xs={3} style={{ marginTop: -1 }}>
            <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
              {t('Nationality')}
            </Typography>
          </Grid>

          <Grid item={true} xs={3} style={{ marginTop: -1 }}>
            <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
              {t('Ethnicity')}
            </Typography>
          </Grid>

          <Grid item={true} xs={3} style={{ marginTop: -1 }}>
            <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
              {t('Gender')}
            </Typography>
          </Grid>

          <Grid item={true} xs={3} style={{ marginTop: -1 }}>
            <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
              {t('Marital Status')}
            </Typography>
          </Grid>
          {/* Row #4 */}
          <Grid item={true} xs={3} style={{ marginTop: -20 }}>
            <div id="x_mcas_nationality_list">
              {/* Parse to verify Safe HTML */}
              {parse(
                threatActorIndividual?.x_mcas_nationality === null
                  ? '-'
                  : toVal(threatActorIndividual?.x_mcas_nationality, Origin),
              )}
            </div>
          </Grid>

          <Grid item={true} xs={3} style={{ marginTop: -20 }}>
            <div id="x_mcas_ethnicity_list">
              {/* Parse to verify Safe HTML */}
              {parse(
                threatActorIndividual?.x_mcas_ethnicity === null
                  ? '-'
                  : toVal(threatActorIndividual?.x_mcas_ethnicity, Origin),
              )}
            </div>
          </Grid>

          <Grid item={true} xs={3} style={{ marginTop: -20 }}>
            <div id="x_mcas_gender">
              {/* Parse to verify Safe HTML */}
              {parse(
                threatActorIndividual?.x_mcas_gender === null
                  ? '-'
                  : toVal(threatActorIndividual?.x_mcas_gender, Genders),
              )}
            </div>
          </Grid>

          <Grid item={true} xs={3} style={{ marginTop: -20 }}>
            <div id="x_mcas_marital_status">
              {/* Parse to verify Safe HTML */}
              {parse(
                threatActorIndividual?.x_mcas_marital_status === null
                  ? '-'
                  : toVal(threatActorIndividual?.x_mcas_marital_status, MaritalStatus),
              )}
            </div>
          </Grid>

          {/* Row #5 */}
          <Grid item={true} xs={12} style={{ marginTop: -1 }}>
            <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
              {t('Job Title')}
            </Typography>
          </Grid>

          {/* Row #6 */}
          <Grid item={true} xs={12} style={{ marginTop: -20 }}>
            <div id='x_mcas_job_title'>
              {/* Parse to verify Safe HTML */}
              {parse(threatActorIndividual?.x_mcas_job_title || '-')}
            </div>
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default ThreatActorIndividualDemographics;
