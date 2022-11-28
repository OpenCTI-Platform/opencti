import React, { useState } from 'react';
import { v4 as uuid } from 'uuid';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Stepper from '@mui/material/Stepper';
import Step from '@mui/material/Step';
import StepButton from '@mui/material/StepButton';
import StepLabel from '@mui/material/StepLabel';
import Slide from '@mui/material/Slide';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Card from '@mui/material/Card';
import CardActionArea from '@mui/material/CardActionArea';
import CardContent from '@mui/material/CardContent';
import Button from '@mui/material/Button';
import Fab from '@mui/material/Fab';
import { Add, AddOutlined, MapOutlined } from '@mui/icons-material';
import {
  ChartTimeline,
  ChartAreasplineVariant,
  ChartBar,
  ChartDonut,
  ChartBubble,
  AlignHorizontalLeft,
  ViewListOutline,
  Counter,
} from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const useStyles = makeStyles((theme) => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1001,
  },
  card: {
    height: 180,
    backgroundColor: theme.palette.background.paperLight,
    textAlign: 'center',
  },
  card2: {
    height: 100,
    backgroundColor: theme.palette.background.paperLight,
  },
  card3: {
    height: 100,
    backgroundColor: theme.palette.background.paperLight,
    textAlign: 'center',
  },
  dialog: {
    height: 600,
  },
  step: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.background.accent}`,
    borderRadius: 5,
    display: 'flex',
  },
  stepCloseButton: {
    position: 'absolute',
    top: -20,
    right: -20,
  },
}));

const WidgetConfig = ({ variant, onComplete }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const [stepIndex, setStepIndex] = useState(0);
  const [type, setType] = useState(null);
  const [filters, setFilters] = useState(null);
  const [attribute, setAttribute] = useState('');
  const handleClose = () => {
    setStepIndex(0);
    setType(null);
    setFilters(null);
    setAttribute(null);
    setOpen(false);
  };
  const handleSelectType = (selectedType) => {
    setType(selectedType);
    setStepIndex(1);
  };
  const handleSelectFilters = (selectedFilters) => {
    if (attribute.length > 0) {
      setFilters(selectedFilters);
      setStepIndex(2);
    }
  };
  const completeSetup = () => {
    onComplete({
      id: uuid(),
      type,
      filters,
      attributes,
    });
    handleClose();
  };
  const renderIcon = (key) => {
    switch (key) {
      case 'map':
        return <MapOutlined fontSize="large" color="primary" />;
      case 'horizontal-bar':
        return <AlignHorizontalLeft fontSize="large" color="primary" />;
      case 'vertical-bar':
        return <ChartBar fontSize="large" color="primary" />;
      case 'donut':
        return <ChartDonut fontSize="large" color="primary" />;
      case 'area':
        return <ChartAreasplineVariant fontSize="large" color="primary" />;
      case 'timeline':
        return <ChartTimeline fontSize="large" color="primary" />;
      case 'list':
        return <ViewListOutline fontSize="large" color="primary" />;
      case 'number':
        return <Counter fontSize="large" color="primary" />;
      case 'heatmap':
        return <ChartBubble fontSize="large" color="primary" />;
      default:
        return 'Go away';
    }
  };
  const renderTypes = () => {
    const visualizationTypes = [
      { key: 'number', name: 'Number' },
      { key: 'list', name: 'List' },
      { key: 'vertical-bar', name: 'Vertical Bar' },
      { key: 'area', name: 'Area' },
      { key: 'donut', name: 'Donut' },
      { key: 'horizontal-bar', name: 'Horizontal Bar' },
      { key: 'timeline', name: 'Timeline' },
      { key: 'heatmap', name: 'Heatmap' },
      { key: 'map', name: 'Map' },
    ];
    return (
      <Grid
        container={true}
        spacing={3}
        style={{ marginTop: 20, marginBottom: 20 }}
      >
        {visualizationTypes.map((visualizationType) => (
          <Grid key={visualizationType.key} item={true} xs="4">
            <Card variant="outlined" className={classes.card3}>
              <CardActionArea
                onClick={() => handleSelectType(visualizationType.key)}
                style={{ height: '100%' }}
              >
                <CardContent>
                  {renderIcon(visualizationType.key)}
                  <Typography
                    gutterBottom
                    variant="body1"
                    style={{ marginTop: 8 }}
                  >
                    {t(visualizationType.name)}
                  </Typography>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>
    );
  };
  const renderDataSelection = () => {
    return (
       <div>
         <div className={classes.add}>
           <Button
               disabled={!areAttributesValid()}
               variant="contained"
               color="secondary"
               size="small"
               onClick={() => handleAddAttribute()}
               classes={{ root: classes.buttonAdd }}
           >
             <AddOutlined fontSize="small" />
           </Button>
         </div>
       </div>
    );
  };
  const getStepContent = () => {
    switch (stepIndex) {
      case 0:
        return renderTypes();
      case 1:
        return renderDataSelection();
      case 2:
        return renderTypes();
      case 3:
        return renderTypes();
      default:
        return 'Go away!';
    }
  };
  return (
    <div>
      <Fab
        onClick={() => setOpen(true)}
        color="secondary"
        aria-label="Add"
        className={classes.createButton}
      >
        <Add />
      </Fab>
      <Dialog
        open={open}
        PaperProps={{ elevation: 1 }}
        TransitionComponent={Transition}
        onClose={handleClose}
        fullWidth={true}
        maxWidth="md"
      >
        <DialogTitle>
          <Stepper linear={false} activeStep={stepIndex}>
            <Step>
              <StepButton
                onClick={() => setStepIndex(0)}
                disabled={stepIndex === 0}
              >
                <StepLabel>{t('Visualization')}</StepLabel>
              </StepButton>
            </Step>
            <Step>
              <StepButton
                onClick={() => setStepIndex(1)}
                disabled={stepIndex <= 1}
              >
                <StepLabel>{t('Entity')}</StepLabel>
              </StepButton>
            </Step>
            <Step>
              <StepButton
                onClick={() => setStepIndex(2)}
                disabled={stepIndex <= 2}
              >
                <StepLabel>{t('Data type')}</StepLabel>
              </StepButton>
            </Step>
            <Step>
              <StepButton
                onClick={() => setStepIndex(3)}
                disabled={stepIndex <= 3}
              >
                <StepLabel>{t('Visualization')}</StepLabel>
              </StepButton>
            </Step>
          </Stepper>
        </DialogTitle>
        <DialogContent>{getStepContent(stepIndex)}</DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>{t('Cancel')}</Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default WidgetConfig;
