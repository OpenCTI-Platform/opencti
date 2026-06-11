import Card from '@common/card/Card';
import Grid from '@mui/material/Grid';
import Slide from '@mui/material/Slide';
import withStyles from '@mui/styles/withStyles';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose } from 'ramda';
import React, { Component } from 'react';
import { graphql } from 'react-relay';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemCreators from '../../../../components/ItemCreators';
import ItemMarkings from '../../../../components/ItemMarkings';
import ItemScore from '../../../../components/ItemScore';
import Label from '../../../../components/common/label/Label';
import Tag from '../../../../components/common/tag/Tag';
import inject18n from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import StixCoreObjectLabelsView from '../../common/stix_core_objects/StixCoreObjectLabelsView';
import { StixCoreObjectStandardIds } from '../../common/stix_core_objects/StixCoreObjectStandardIds';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
  standard_id: {
    padding: '5px 5px 5px 10px',
    fontFamily: 'Consolas, monaco, monospace',
    fontSize: 11,
    backgroundColor:
      theme.palette.mode === 'light'
        ? 'rgba(0, 0, 0, 0.02)'
        : 'rgba(255, 255, 255, 0.02)',
    lineHeight: '18px',
  },
});

const stixCyberObservableMutation = graphql`
  mutation StixCyberObservableOverviewMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixCyberObservableEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        x_opencti_stix_ids
      }
    }
  }
`;

class StixCyberObservableOverview extends Component {
  constructor(props) {
    super(props);
  }

  deleteStixId(stixId) {
    const { stixCyberObservable } = this.props;
    const otherStixIds = stixCyberObservable.x_opencti_stix_ids || [];
    const stixIds = R.filter(
      (n) => n !== stixCyberObservable.standard_id && n !== stixId,
      otherStixIds,
    );
    commitMutation({
      mutation: stixCyberObservableMutation,
      variables: {
        id: this.props.stixCyberObservable.id,
        input: {
          key: 'x_opencti_stix_ids',
          value: stixIds,
        },
      },
      onCompleted: () => MESSAGING$.notifySuccess(this.props.t('The STIX ID has been removed')),
    });
  }

  render() {
    const { t, fldt, stixCyberObservable } = this.props;
    return (
      <>
        <Card title={t('Basic information')}>
          <Grid container={true} spacing={2}>
            <Grid item xs={6}>
              <Label>
                {t('Marking')}
              </Label>
              <ItemMarkings
                markingDefinitions={stixCyberObservable.objectMarking ?? []}
              />
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('Score')}
              </Label>
              <ItemScore score={stixCyberObservable.x_opencti_score} />
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('Author')}
              </Label>
              <ItemAuthor
                createdBy={stixCyberObservable.createdBy}
              />
              <StixCoreObjectLabelsView
                labels={stixCyberObservable.objectLabel}
                id={stixCyberObservable.id}
                sx={{ marginTop: 2 }}
                entity_type={stixCyberObservable.entity_type}
              />
            </Grid>
            <Grid item xs={6}>
              <Label>
                {t('Observable type')}
              </Label>
              <Tag
                color="#203af6"
                label={t(`entity_${stixCyberObservable.entity_type}`)}
              />
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('Creators')}
              </Label>
              <ItemCreators creators={stixCyberObservable.creators ?? []} />
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('Platform creation date')}
              </Label>
              {fldt(stixCyberObservable.created_at)}
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('Modification date')}
              </Label>
              {fldt(stixCyberObservable.updated_at)}
              <div style={{ marginTop: 20 }}>
                <StixCoreObjectStandardIds
                  standardId={stixCyberObservable.standard_id}
                  stixIds={stixCyberObservable.x_opencti_stix_ids}
                  deleteStixId={this.deleteStixId.bind(this)}
                />
              </div>
            </Grid>
          </Grid>
        </Card>
      </>
    );
  }
}

StixCyberObservableOverview.propTypes = {
  stixCyberObservable: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCyberObservableOverview);
