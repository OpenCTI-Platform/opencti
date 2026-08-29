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
import React, { useState } from 'react';
import { graphql } from 'react-relay';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemCopy from '../../../../components/ItemCopy';
import ItemCreators from '../../../../components/ItemCreators';
import ItemMarkings from '../../../../components/ItemMarkings';
import ItemScore from '../../../../components/ItemScore';
import Label from '../../../../components/common/label/Label';
import Tag from '../../../../components/common/tag/Tag';
import { useFormatter } from '../../../../components/i18n';
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

const StixCyberObservableOverview = (props) => {
  const { t_i18n, fldt } = useFormatter();
  const [openStixIds, setOpenStixIds] = useState(false);
  const handleToggleOpenStixIds = () => {
    setOpenStixIds((current) => !current);
  };

  const deleteStixId = (stixId) => {
    const { stixCyberObservable } = props;
    const otherStixIds = stixCyberObservable.x_opencti_stix_ids || [];
    const stixIds = R.filter(
      (n) => n !== stixCyberObservable.standard_id && n !== stixId,
      otherStixIds,
    );
    commitMutation({
      mutation: stixCyberObservableMutation,
      variables: {
        id: props.stixCyberObservable.id,
        input: {
          key: 'x_opencti_stix_ids',
          value: stixIds,
        },
      },
      onCompleted: () => MESSAGING$.notifySuccess(t_i18n('The STIX ID has been removed')),
    });
  };

  const { classes, stixCyberObservable } = props;
  const otherStixIds = stixCyberObservable.x_opencti_stix_ids || [];
  const stixIds = R.filter(
    (n) => n !== stixCyberObservable.standard_id,
    otherStixIds,
  );
  return (
    <>
      <Card title={t_i18n('Basic information')}>
        <Grid container={true} spacing={2}>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Marking')}
            </Label>
            <ItemMarkings
              markingDefinitions={stixCyberObservable.objectMarking ?? []}
            />
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Score')}
            </Label>
            <ItemScore score={stixCyberObservable.x_opencti_score} />
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Author')}
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
              {t_i18n('Observable type')}
            </Label>
            <Tag
              color="#203af6"
              label={t_i18n(`entity_${stixCyberObservable.entity_type}`)}
            />
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Creators')}
            </Label>
            <ItemCreators creators={stixCyberObservable.creators ?? []} />
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Platform creation date')}
            </Label>
            {fldt(stixCyberObservable.created_at)}
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Modification date')}
            </Label>
            {fldt(stixCyberObservable.updated_at)}
            <div style={{ marginTop: 20 }}>
              <Label action={(
                <>
                  <Tooltip
                    title={t_i18n(
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
                      onClick={handleToggleOpenStixIds}
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
                {t_i18n('Standard STIX ID')}
              </Label>
              <div className={classes.standard_id}>
                <ItemCopy content={stixCyberObservable.standard_id} />
              </div>
            </div>
          </Grid>
        </Grid>
      </Card>
      <Dialog
        open={openStixIds}
        onClose={handleToggleOpenStixIds}
        title={t_i18n('Other STIX IDs')}
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
                    onClick={deleteStixId.bind(null, stixId)}
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
            onClick={handleToggleOpenStixIds}
          >
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

StixCyberObservableOverview.propTypes = {
  stixCyberObservable: PropTypes.object,
  classes: PropTypes.object,
};

export default withStyles(styles)(StixCyberObservableOverview);
