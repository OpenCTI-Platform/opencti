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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import { v4 as uuid } from 'uuid';
import { fetchQuery } from '../../../../relay/environment';
import { stixDomainObjectsLinesSearchQuery } from '../stix_domain_objects/StixDomainObjectsLines';
import ItemIcon from '../../../../components/ItemIcon';
import ItemBoolean from '../../../../components/ItemBoolean';
import { convertFromStixType, convertToStixType, splitIntoLines } from '../../../../utils/String';
import { useFormatter } from '../../../../components/i18n';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { isEmptyField } from '../../../../utils/utils';

// Floated cells capped at 20px cut the 36px select and the chip; flex row now.
const inlineStyles = {
  row: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
  },
  type: {
    fontSize: 13,
    width: '36%',
    minWidth: 0,
    flexShrink: 0,
  },
  typeText: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  default_value: {
    fontSize: 13,
    flex: 1,
    minWidth: 0,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  in_platform: {
    fontSize: 13,
    flexShrink: 0,
  },
};

const DynamicResolutionField = ({
  form: { setFieldValue },
  field,
  title,
  types,
  style,
  stixDomainObjects,
  helperText,
}) => {
  const { t_i18n } = useFormatter();
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
          .map((val) => {
            const filteredStixDomainObjects = stixDomainObjects.filter(
              (n) => (types.includes(convertFromStixType(n.type))
                || types.includes(n.x_opencti_location_type)
                || types.includes(n.identity_class))
              && (n.name === val.trim() || n.value === val.trim()),
            );

            if (filteredStixDomainObjects.length > 0) {
              const firstStixDomainObject = R.head(filteredStixDomainObjects);
              const targetSelectedType = firstStixDomainObject.x_opencti_location_type
                ?? filteredStixDomainObjects.identity_class ?? firstStixDomainObject.type;
              return {
                id: firstStixDomainObject.id,
                type: targetSelectedType,
                name: getMainRepresentative(firstStixDomainObject),
                in_platform: null,
              };
            }
            return fetchQuery(stixDomainObjectsLinesSearchQuery, {
              types,
              filters: {
                mode: 'and',
                filters: [
                  {
                    key: ['name', 'aliases', 'x_opencti_aliases', 'x_mitre_id'],
                    values: [val.trim()],
                  },
                ],
                filterGroups: [],
              },
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
                      name: val.trim(),
                      in_platform: false,
                    };
              });
          }),
      );
      setFieldValue(field.name, resolvedEntities);
    };
    fetchData();
  }, [textFieldValue, setFieldValue, field.name]);
  const handleChangeTextField = (event) => {
    const { value } = event.target;
    setTextFieldValue(splitIntoLines(value));
  };
  // Takes the value directly: `onValueChange` hands over the string, so the
  // handler no longer reaches into an event to find it.
  const handleChangeType = (id, value) => {
    setFieldValue(
      field.name,
      field.value.map((n) => (n.id === id
        ? {
            ...n,
            id: `${convertToStixType(value)}--${uuid()}`,
            type: value,
          }
        : n)),
    );
  };
  const [, meta] = useField(field.name);
  return (
    <div style={style}>
      <Typography variant="h4">{title}</Typography>
      <Grid container={true} spacing={3}>
        <Grid item xs={5}>
          <TextField
            error={!R.isNil(meta.error)}
            helperText={helperText}
            onChange={handleChangeTextField}
            value={textFieldValue}
            multiline={true}
            fullWidth={true}
            minRows={6}
            slotProps={{
              htmlInput: { style: { lineHeight: '34px' } },
            }}
          />
        </Grid>
        <Grid item xs={7}>
          {(field.value || []).length > 0 ? (
            <List style={{ marginTop: 0 }}>
              {(field.value || []).map((item) => (
                <ListItem key={item.id} dense={true} divider={true}>
                  <ListItemIcon>
                    <ItemIcon type={convertFromStixType(item.type)} />
                  </ListItemIcon>
                  <ListItemText
                    primary={(
                      <div style={inlineStyles.row}>
                        <div style={inlineStyles.type}>
                          {item.in_platform ? (
                            <div style={inlineStyles.typeText}>
                              {t_i18n(`entity_${item.type}`)}
                            </div>
                          ) : (
                            <Select
                              value={convertFromStixType(item.type)}
                              onValueChange={(value) => handleChangeType(item.id, value)}
                            >
                              <SelectTrigger aria-label={t_i18n('Entity type')}>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent aria-label={t_i18n('Entity type')}>
                                {types.map((n) => (
                                  <SelectItem key={n} value={n}>
                                    {t_i18n(`entity_${n}`)}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          )}
                        </div>
                        <div style={inlineStyles.default_value}>
                          {item.name}
                        </div>
                        <div style={inlineStyles.in_platform}>
                          <ItemBoolean
                            variant="inList"
                            status={isEmptyField(item.in_platform) || item.in_platform}
                            label={

                              item.in_platform
                                ? t_i18n('In platform')
                                : item.in_platform === null
                                  ? t_i18n('In workbench')
                                  : t_i18n('To create')
                            }
                          />
                        </div>
                      </div>
                    )}
                  />
                </ListItem>
              ))}
            </List>
          ) : (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t_i18n('No entities added in this context.')}
              </span>
            </div>
          )}
        </Grid>
      </Grid>
    </div>
  );
};

export default DynamicResolutionField;
