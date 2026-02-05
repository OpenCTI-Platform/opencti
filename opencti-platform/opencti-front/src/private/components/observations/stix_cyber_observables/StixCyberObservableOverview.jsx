import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Card from '@common/card/Card';
import Dialog from '@common/dialog/Dialog';
import { BrushOutlined, Delete } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Slide from '@mui/material/Slide';
import Tooltip from '@mui/material/Tooltip';
import withStyles from '@mui/styles/withStyles';
import { InformationOutline } from 'mdi-material-ui';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose } from 'ramda';
import React, { Component } from 'react';
import { graphql } from 'react-relay';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemCopy from '../../../../components/ItemCopy';
import ItemCreators from '../../../../components/ItemCreators';
import ItemMarkings from '../../../../components/ItemMarkings';
import ItemScore from '../../../../components/ItemScore';
import Label from '../../../../components/common/label/Label';
import Tag from '../../../../components/common/tag/Tag';
import inject18n from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectLabelsView from '../../common/stix_core_objects/StixCoreObjectLabelsView';

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
    this.state = {
      openStixIds: false,
    };
  }

  handleToggleOpenStixIds() {
    this.setState({ openStixIds: !this.state.openStixIds });
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
    const { t, fldt, classes, stixCyberObservable } = this.props;
    const otherStixIds = stixCyberObservable.x_opencti_stix_ids || [];
    const stixIds = R.filter(
      (n) => n !== stixCyberObservable.standard_id,
      otherStixIds,
    );
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
                <Label action={(
                  <>
                    <Tooltip
                      title={t(
                        'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                      )}
                    >
                      <InformationOutline fontSize="small" color="primary" />
                    </Tooltip>
                    <Security needs={[KNOWLEDGE_KNUPDATE]}>
                      <IconButton
                        aria-label="Close"
                        disableRipple={true}
                        size="small"
                        disabled={stixIds.length === 0}
                        onClick={this.handleToggleOpenStixIds.bind(this)}
                      >
                        <BrushOutlined
                          fontSize="small"
                          color={stixIds.length === 0 ? 'inherit' : 'secondary'}
                        />
                      </IconButton>
                    </Security>
                  </>
                )}
                >
                  {t('Standard STIX ID')}
                </Label>
                <div className={classes.standard_id}>
                  <ItemCopy content={stixCyberObservable.standard_id} />
                </div>
              </div>
            </Grid>
          </Grid>
        </Card>
        <Dialog
          open={this.state.openStixIds}
          onClose={this.handleToggleOpenStixIds.bind(this)}
          title={t('Other STIX IDs')}
        >
          <List>
            {stixIds.map(
              (stixId) => stixId.length > 0 && (
                <ListItem
                  key={stixId}
                  disableGutters={true}
                  dense={true}
                  secondaryAction={(
                    <IconButton
                      edge="end"
                      aria-label="delete"
                      onClick={this.deleteStixId.bind(this, stixId)}
                    >
                      <Delete />
                    </IconButton>
                  )}
                >
                  <ListItemText primary={stixId} />
                </ListItem>
              ),
            )}
          </List>
          <DialogActions>
            <Button
              onClick={this.handleToggleOpenStixIds.bind(this)}
            >
              {t('Close')}
            </Button>
          </DialogActions>
        </Dialog>
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
