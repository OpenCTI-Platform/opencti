import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import inject18n from '../../../../components/i18n';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ImageCarousel from '../../../../components/ImageCarousel';
import ThreatActorGroupLocation from './ThreatActorGroupLocation';
import Card from '@common/card/Card';
import Label from '../../../../components/common/label/Label';
import Tag from '../../../../components/common/tag/Tag';
import TextList from '../../../../components/common/text/TextList';
import { Stack } from '@mui/material';

class ThreatActorGroupDetailsComponent extends Component {
  render() {
    const { t, threatActorGroup, fldt } = this.props;
    const hasImages = (threatActorGroup.images?.edges ?? []).filter(
      (n) => n?.node?.metaData?.inCarousel,
    ).length > 0;

    return (
      <Card title={t('Details')}>
        <Grid container={true} spacing={2}>
          <Grid item xs={hasImages ? 7 : 6}>
            <Grid container={true} spacing={2}>
              {hasImages && (
                <Grid item xs={4}>
                  <ImageCarousel data={threatActorGroup} />
                </Grid>
              )}
              <Grid item xs={hasImages ? 8 : 12}>
                <Label>
                  {t('Threat actor types')}
                </Label>
                <FieldOrEmpty source={threatActorGroup.threat_actor_types}>
                  <Stack direction="row" flexWrap="wrap" gap={1}>
                    {threatActorGroup.threat_actor_types
                      && threatActorGroup.threat_actor_types.map(
                        (threatActorGroupType) => (
                          <Tag
                            key={threatActorGroupType}
                            label={threatActorGroupType}
                          />
                        ),
                      )}
                  </Stack>
                </FieldOrEmpty>
                <Label
                  sx={{ marginTop: 2 }}
                >
                  {t('Description')}
                </Label>
                <ExpandableMarkdown
                  source={threatActorGroup.description}
                  limit={hasImages ? 400 : 600}
                />
              </Grid>
            </Grid>
          </Grid>
          <Grid item xs={hasImages ? 5 : 6}>
            <ThreatActorGroupLocation threatActorGroup={threatActorGroup} />
            <Label
              sx={{ marginTop: 2 }}
            >
              {t('First seen')}
            </Label>
            {fldt(threatActorGroup.first_seen)}
            <Label
              sx={{ marginTop: 2 }}
            >
              {t('Last seen')}
            </Label>
            {fldt(threatActorGroup.last_seen)}
          </Grid>
        </Grid>
        <Grid container={true} spacing={2}>
          <Grid item xs={4}>
            <Label
              sx={{ marginTop: 2 }}
            >
              {t('Sophistication')}
            </Label>
            <FieldOrEmpty source={threatActorGroup.sophistication}>
              <ItemOpenVocab
                type="threat-actor-group-sophistication-ov"
                value={threatActorGroup.sophistication}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={4}>
            <Label
              sx={{ marginTop: 2 }}
            >
              {t('Resource level')}
            </Label>
            <FieldOrEmpty source={threatActorGroup.resource_level}>
              <ItemOpenVocab
                type="attack-resource-level-ov"
                value={threatActorGroup.resource_level}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={4}>
            <Label
              sx={{ marginTop: 2 }}
            >
              {t('Primary motivation')}
            </Label>
            <FieldOrEmpty source={threatActorGroup.primary_motivation}>
              <ItemOpenVocab
                type="attack-motivation-ov"
                value={threatActorGroup.primary_motivation}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={4}>
            <Label>
              {t('Roles')}
            </Label>
            <TextList
              list={threatActorGroup.roles}
            />
          </Grid>
          <Grid item xs={4}>
            <Label>
              {t('Goals')}
            </Label>
            <TextList
              list={threatActorGroup.goals}
            />
          </Grid>
          <Grid item xs={4}>
            <Label>
              {t('Secondary motivations')}
            </Label>
            <TextList
              list={threatActorGroup.secondary_motivations}
            />
          </Grid>
        </Grid>
      </Card>
    );
  }
}

ThreatActorGroupDetailsComponent.propTypes = {
  threatActorGroup: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
};

const ThreatActorGroupDetails = createFragmentContainer(
  ThreatActorGroupDetailsComponent,
  {
    threatActorGroup: graphql`
      fragment ThreatActorGroupDetails_ThreatActorGroup on ThreatActorGroup {
        id
        first_seen
        last_seen
        description
        threat_actor_types
        sophistication
        resource_level
        primary_motivation
        secondary_motivations
        goals
        roles
        images: importFiles(prefixMimeType: "image/") {
          edges {
            node {
              id
              name
              metaData {
                mimetype
                order
                inCarousel
                description
              }
            }
          }
        }
        ...ThreatActorGroupLocations_locations
      }
    `,
  },
);

export default compose(inject18n)(ThreatActorGroupDetails);
