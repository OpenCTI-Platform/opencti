import React, { useState, useEffect } from 'react';
import Grid from '@mui/material/Grid';
import * as R from 'ramda';
import TextField from '@mui/material/TextField';
import { useField } from 'formik';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import { v4 as uuid } from 'uuid';
import { fetchQuery } from '../../../../relay/environment';
import { stixDomainObjectsLinesSearchQuery } from '../stix_domain_objects/StixDomainObjectsLines';
import ItemIcon from '../../../../components/ItemIcon';
import ItemBoolean from '../../../../components/ItemBoolean';
import { convertToStixType } from '../../../../utils/String';
import { useFormatter } from '../../../../components/i18n';

const inlineStyles = {
  type: {
    fontSize: 13,
    float: 'left',
    width: '30%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  default_value: {
    fontSize: 13,
    float: 'left',
    width: '50%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  in_platform: {
    fontSize: 13,
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

const DynamicResolutionField = (props) => {
  const {
    form: { setFieldValue },
    field,
    title,
    types,
  } = props;
  const { t } = useFormatter();
  const [textFieldValue, setTextFieldValue] = useState(
    field.value.map((n) => n.name).join('\n'),
  );
  // Similar to componentDidMount and componentDidUpdate:
  useEffect(() => {
    const fetchData = async () => {
      const currentValueIndexed = R.indexBy(R.prop('name'), field.value);
      const resolvedEntities = await Promise.all(
        textFieldValue
          .split('\n')
          .filter((n) => n.length > 1)
          .map((val) => fetchQuery(stixDomainObjectsLinesSearchQuery, {
            types,
            filters: [
              {
                key: ['name', 'aliases', 'x_opencti_aliases', 'x_mitre_id'],
                values: val,
              },
            ],
            count: 1,
          })
            .toPromise()
            .then((data) => {
              const stixDomainObjectsEdges = data.stixDomainObjects.edges;
              const firstStixDomainObject = R.head(
                stixDomainObjectsEdges,
              )?.node;
              if (firstStixDomainObject) {
                return {
                  id: firstStixDomainObject.standard_id,
                  type: firstStixDomainObject.entity_type,
                  name: firstStixDomainObject.name,
                  in_platform: true,
                };
              }
              return currentValueIndexed[val]
                ? {
                  id: currentValueIndexed[val].id,
                  type: currentValueIndexed[val].type,
                  name: currentValueIndexed[val].name,
                  in_platform: false,
                }
                : {
                  id: `${convertToStixType(R.head(types))}--${uuid()}`,
                  type: R.head(types),
                  name: val,
                  in_platform: false,
                };
            })),
      );
      setFieldValue(field.name, resolvedEntities);
    };
    fetchData();
  }, [textFieldValue, setFieldValue, field.name]);
  const handleChangeTextField = (event) => {
    const { value } = event.target;
    setTextFieldValue(
      value
        .split('\n')
        .map((n) => n
          .split(',')
          .map((o) => o.split(';'))
          .flat())
        .flat()
        .map((n) => n.trim())
        .join('\n'),
    );
  };
  const handleChangeType = (id, event) => {
    setFieldValue(
      field.name,
      field.value.map((n) => (n.id === id
        ? {
          ...n,
          id: `${convertToStixType(event.target.value)}--${uuid()}`,
          type: event.target.value,
        }
        : n)),
    );
  };
  const [, meta] = useField(field.name);
  return (
    <div>
      <Typography variant="h2">{title}</Typography>
      <Grid container={true} spacing={3}>
        <Grid item={true} xs={5}>
          <TextField
            error={!R.isNil(meta.error)}
            helperText={props.helperText}
            onChange={handleChangeTextField}
            value={textFieldValue}
            multiline={true}
            fullWidth={true}
            minRows={6}
            inputProps={{ style: { lineHeight: '34px' } }}
          />
        </Grid>
        <Grid item={true} xs={7}>
          <List style={{ marginTop: 0 }}>
            {(field.value || []).map((item) => (
              <ListItem key={item.id} dense={true} divider={true}>
                <ListItemIcon>
                  <ItemIcon type={item.type} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div style={inlineStyles.type}>
                        {item.in_platform ? (
                          t(`entity_${item.type}`)
                        ) : (
                          <Select
                            variant="standard"
                            labelId="type"
                            value={item.type}
                            onChange={(event) => handleChangeType(item.id, event)
                            }
                            style={{
                              margin: 0,
                              width: '80%',
                              height: '100%',
                            }}
                          >
                            {types.map((n) => (
                              <MenuItem key={n} value={n}>
                                {t(`entity_${n}`)}
                              </MenuItem>
                            ))}
                          </Select>
                        )}
                      </div>
                      <div style={inlineStyles.default_value}>{item.name}</div>
                      <div style={inlineStyles.in_platform}>
                        <ItemBoolean
                          variant="inList"
                          status={item.in_platform}
                          label={
                            item.in_platform ? t('In platform') : t('To create')
                          }
                        />
                      </div>
                    </div>
                  }
                />
              </ListItem>
            ))}
          </List>
        </Grid>
      </Grid>
    </div>
  );
};

export default DynamicResolutionField;
