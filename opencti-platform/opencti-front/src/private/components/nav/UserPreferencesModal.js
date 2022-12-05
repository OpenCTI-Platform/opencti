/* eslint-disable */
import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import Paper from '@material-ui/core/Paper';
import Grid from '@material-ui/core/Grid';
import Card from '@material-ui/core/Card';
import Avatar from '@material-ui/core/Avatar';
import CircularProgress from '@material-ui/core/CircularProgress';
import CardHeader from '@material-ui/core/CardHeader';
import CardActions from '@material-ui/core/CardActions';
import CardContent from '@material-ui/core/CardContent';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import MoreVertIcon from '@material-ui/icons/MoreVert';
import InputLabel from '@material-ui/core/InputLabel';
import MenuItem from '@material-ui/core/MenuItem';
import Radio from '@material-ui/core/Radio';
import RadioGroup from '@material-ui/core/RadioGroup';
import FormLabel from '@material-ui/core/FormLabel';
import FormControl from '@material-ui/core/FormControl';
import FormGroup from '@material-ui/core/FormGroup';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import FormHelperText from '@material-ui/core/FormHelperText';
import Select from '@material-ui/core/Select';
import Typography from '@material-ui/core/Typography';
import {
  getAccount,
  getOrganizationSettings,
  updateOrganizationSettings,
} from '../../../services/account.service';

const customSvg = require('../../../assets/severity-scores/custom.svg').default;
const tenableSvg =
  require('../../../assets/severity-scores/tenable.svg').default;
const nvdSvg = require('../../../assets/severity-scores/nvd.svg').default;

let currentSeverityLevel = 'custom';

const classes = {
  root: {
    flexGrow: 1,
  },
  card: {
    width: '100%',
    marginBottom: 20,
    borderRadius: 6,
    position: 'relative',
  },
  cardHeader: {
    marginBottom: '0',
  },
  paper: {
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  item: {
    height: 50,
    minHeight: 50,
    maxHeight: 50,
    paddingRight: 0,
  },
  itemText: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 24,
  },
  itemIconSecondary: {
    marginRight: 0,
  },
  number: {
    marginTop: 10,
    float: 'left',
    fontSize: 30,
  },
  title: {
    marginTop: 5,
    textTransform: 'uppercase',
    fontSize: 12,
    fontWeight: 500,
  },
  icon: {
    position: 'absolute',
    top: 35,
    right: 20,
  },
  graphContainer: {
    width: '100%',
    padding: '20px 20px 0 0',
  },
  labelsCloud: {
    width: '100%',
    height: 300,
  },
  label: {
    width: '100%',
    height: 100,
    padding: 15,
  },
  labelNumber: {
    fontSize: 30,
    fontWeight: 500,
  },
  labelValue: {
    fontSize: 15,
  },
  itemAuthor: {
    width: 200,
    minWidth: 200,
    maxWidth: 200,
    paddingRight: 24,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    textAlign: 'left',
  },
  itemType: {
    width: 100,
    minWidth: 100,
    maxWidth: 100,
    paddingRight: 24,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    textAlign: 'left',
  },
  itemDate: {
    width: 120,
    minWidth: 120,
    maxWidth: 120,
    paddingRight: 24,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    textAlign: 'left',
  },
};

const UserPreferencesModal = (props) => {
  const me = props.me;

  const [isLoading, setIsLoading] = useState(props.isLoading);
  const [currentClient_id, setCurrentClient_id] = useState(localStorage.getItem('client_id'));
  const [severityLevel, setSeverityLevel] = useState();
  const [user] = useState(props.user);
  const [orgSettings, setOrgSettings] = useState([])

  const location = useLocation();

  const handleSubmit = () => {
   const param = { vsa_severity_score_method: severityLevel}
    updateOrganizationSettings(currentClient_id, param).then((results) =>{

      localStorage.setItem('client_id', currentClient_id);
      props.setClientId(currentClient_id);
      if(location.pathname === '/activities/vulnerability_assessment/scans/explore results'){
       props.history.push('/activities/vulnerability_assessment/scans');
      } else {
        props.history.push('/dashboard');
      }
      handleCancel();

    }).catch((error) => {
      console.log(error)
    })
  };

  const handleCancel = () => {
    props.action();
  }

  useEffect(() => {
    user.clients.forEach((item) => {
          getOrganizationSettings(item.client_id).then((result) => {
            // eslint-disable-next-line no-param-reassign
            if(result){
              if(item.client_id == currentClient_id){
                 setSeverityLevel(result.data.vsa_severity_score_method);
              }
               setOrgSettings(oldArray => [...oldArray, {
                  client_id: result.data.client_id,
                  vsa_severity_score_method: result.data.vsa_severity_score_method,
               }]);
             }
          }).catch((error) => {
            console.log(error)
          });
    });

    setIsLoading(false);
  }, []);

  const handleOrgChange = (event) => {

    setSeverityLevel(orgSettings.find(obj => { return obj.client_id === currentClient_id}).vsa_severity_score_method);
    setCurrentClient_id(event.target.value);
  }

  const handleSeverityLevelChange = (event) => {
    setSeverityLevel(event.target.value);
  }

  return (
    <Paper
      classes={{ root: classes.paper }}
      elevation={2}
      style={{ width: '400px' }}
    >
      {!isLoading ? (
        <Card>
          <CardHeader
            avatar={
              <Avatar aria-label="recipe" className={classes.avatar}>
                D
              </Avatar>
            }
            title={me.name}
            subheader={me.user_email}
          />
          <CardContent>
            <Typography gutterBottom variant="h5" component="h2">
              Organization
            </Typography>
            <Select
              labelId="organization-label"
              id="organization"
              value={currentClient_id}
              onChange={(e) => handleOrgChange(e)}
              data-cy='org selection'
             >
            { user &&
              user.clients.map((item,i) => {
               return ( <MenuItem value={item.client_id} data-cy='an org'>{item.name}</MenuItem> )
              })
            }
            </Select>
          </CardContent>
          <CardContent>
            <Typography gutterBottom variant="h5" component="h2">
              Vulnerability Severity Scoring Preference
            </Typography>
            {severityLevel === 'custom' && <img src={customSvg} alt="Custom" />}
            {severityLevel === 'tenable' && (
              <img src={tenableSvg} alt="Tenable" />
            )}
            {severityLevel === 'nvd' && <img src={nvdSvg} alt="NVD" />}
           {severityLevel &&
            <RadioGroup
              row
              aria-label="severityLevel"
              name="severityLevel"
              defaultValue="bottom"
              value={severityLevel}
              onChange={(e) => handleSeverityLevelChange(e)}
            >
              <FormControlLabel
                value="custom"
                control={<Radio color="primary" />}
                label="Custom"
                labelPlacement="Bottom"
              />
              <FormControlLabel
                value="tenable"
                control={<Radio color="primary" />}
                label="Tenable"
                labelPlacement="Bottom"
              />
              <FormControlLabel
                value="nvd"
                control={<Radio color="primary" />}
                label="NVD"
                labelPlacement="Bottom"
              />
            </RadioGroup>
          }
          </CardContent>
          <CardContent>
            <Typography gutterBottom variant="caption">
              Applies to Charts and Reports that assign CVSS scores to labels.
            </Typography>
          </CardContent>
          <CardActions style={{ justifyContent: 'right' }}>
            <Button
              size="small"
              color="secondary"
              onClick={() => handleCancel()}
              >
              Cancel
            </Button>
            <Button
              size="small"
              color="primary"
              onClick={() => handleSubmit()}
            >
              Ok
            </Button>
          </CardActions>
        </Card>
      ) : (
        <Card>
          <CardContent>
            <CircularProgress />
          </CardContent>
        </Card>
      )}
    </Paper>
  );
};

export default UserPreferencesModal;
