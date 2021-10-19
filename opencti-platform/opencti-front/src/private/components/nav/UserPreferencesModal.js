import React, { useState, useEffect } from 'react';
import { useHistory } from 'react-router-dom';
import { useForm, Controller } from 'react-hook-form';
import { Modal, Form, Button } from 'react-bootstrap';
import { toast } from 'react-toastify';
import {
  getAccount,
  getOrganizationSettings,
  updateOrganizationSettings,
} from '../../../services/account.service';
import Dropdown from '../ux/Dropdown';
import { ReactComponent as Shield } from '../../../assets/svg-icons/shield.svg';
import { ReactComponent as UserIcon } from '../../../assets/svg-icons/user.svg';
import { ReactComponent as Building } from '../../../assets/svg-icons/building.svg';

const customSvg = require('../../../assets/severity-scores/custom.svg').default;
const tenableSvg = require('../../../assets/severity-scores/tenable.svg').default;
const nvdSvg = require('../../../assets/severity-scores/nvd.svg').default;

const UserPreferencesModal = (props) => {
  const history = useHistory();

  // const { user, setCurrentClient, setCurrentClientName, currentClient } = store;
  const me = { props };
  const { handleSubmit, setValue, control } = useForm();
  const currentClient = localStorage.getItem('client_id');
  let clientSelected = {
    id: currentClient,
    title: '',
    vsa_severity_score_method: '',
  };
  let user;
  let clients;
  let currentSeverityLevel = '';
  getAccount().then((res) => {
    user = {
      email: res.data.email,
      clients: res.data.clients,
      first_name: me.name,
      last_name: me.lastname,
    };
    clients = user.clients.map((item) => {
      if (currentClient === item.clientId) {
        clientSelected = {
          id: item.clientId,
          title: item.name,
          vsa_severity_score_method: item.vsa_severity_score_method,
        };
        currentSeverityLevel = item.vsa_severity_score_method;
      }
      return {
        id: item.clientId,
        title: item.name,
        vsa_severity_score_method: item.vsa_severity_score_method,
      };
    });
  });

  const [client, setClient] = useState(clientSelected);

  const [severityLevel, setSeverityLevel] = useState(currentSeverityLevel);

  const updateFormValue = (key, value, action) => {
    setValue(key, value);
    action();
  };

  useEffect(() => {
    if (props.isOpen) {
      // Get Org Settings
      if (user && user.clients) {
        user.clients.forEach((item) => {
          getOrganizationSettings(item.client_id).then((result) => {
            // eslint-disable-next-line no-param-reassign
            item.vsa_severity_score_method = result.data.vsa_severity_score_method;
            if (currentClient === item.client_id) {
              const clientItem = {
                id: item.client_id,
                title: item.name,
                vsa_severity_score_method: result.data.vsa_severity_score_method,
              };
              updateFormValue('client', clientItem, () => setClient(clientItem));
              updateFormValue(
                'severityLevel',
                result.data.vsa_severity_score_method,
                () => setSeverityLevel(result.data.vsa_severity_score_method),
              );
            }
            return true;
          });
        });
      }
    }
    // eslint-disable-next-line
  }, [props.isOpen]);

  const onFormSubmit = () => {
    // Update
    if (client && client.id && severityLevel) {
      updateOrganizationSettings(client.id, {
        vsa_severity_score_method: severityLevel,
      });
      localStorage.setItem('client_id', client.id);
      localStorage.setItem('client_name', client.title);
      // setCurrentClient(client.id);
      // setCurrentClientName(client.title);
      // Redirect
      if (currentClient === client.id) {
        toast.success('Updated scoring preferences.', { autoClose: 10000 });
        toast.info('Reloading page', { autoClose: 2000 });
        setTimeout(() => {
          history.go(0);
        }, 2000);
      } else {
        history.push('/defense/scan');
        toast.success(`Switched to ${client.title} organization.`, {
          autoClose: 10000,
        });
      }
      props.onClose();
    }
  };

  return (
    <Modal
      animation={false}
      scrollable={false}
      show={props.isOpen}
      onHide={props.onClose}
      backdrop='static'
      keyboard={false}
      dialogClassName='bg-secondary'
    >
      <Modal.Header closeButton>
        <Modal.Title>Account Details</Modal.Title>
      </Modal.Header>
      <Form onSubmit={handleSubmit(() => onFormSubmit())}>
        <Modal.Body>
          <h5>
            <UserIcon className='account-icon' /> User Account
          </h5>
          <p className='mb-5'>
            <span>
              {user && user.first_name} {user && user.last_name}
            </span>
            <br />
            <span>{user && user.email}</span>
          </p>
          <h5 className='mt-4'>
            <Building className='account-icon' /> Organization
          </h5>
          <Controller
            as={Dropdown}
            name='client'
            control={control}
            items={clients}
            selected={client}
            onSelect={(i) => updateFormValue('client', i, () => setClient(i))
            }
            placeholder='Select Organization'
            defaultValue={client}
            rules={{ required: true }}
          />
          <h5 className='mt-5'>
            <Shield className='account-icon' /> Vulnerability Severity Scoring
            Preference
          </h5>
          {severityLevel === 'custom' && (
            <img
              src={customSvg}
              alt='Custom'
            />
          )}
          {severityLevel === 'tenable' && (
            <img
              src={tenableSvg}
              alt='Tenable'
            />
          )}
          {severityLevel === 'nvd' && (
            <img
              src={nvdSvg}
              alt='NVD'
            />
          )}
          <div key='inline-radio' className='my-3'>
            <Form.Check
              inline
              custom
              name='severityLevel'
              checked={severityLevel === 'custom'}
              onChange={() => updateFormValue('severityLevel', 'custom', () => setSeverityLevel('custom'))
              }
              label='Custom'
              type='radio'
              id='custom'
              value='custom'
            />
            <Form.Check
              inline
              custom
              name='severityLevel'
              checked={severityLevel === 'tenable'}
              onChange={() => updateFormValue('severityLevel', 'tenable', () => setSeverityLevel('tenable'))
              }
              label='Tenable'
              type='radio'
              id='tenable'
              value='tenable'
            />
            <Form.Check
              inline
              custom
              name='severityLevel'
              checked={severityLevel === 'nvd'}
              onChange={() => updateFormValue('severityLevel', 'nvd', () => setSeverityLevel('nvd'))
              }
              label='NVD'
              type='radio'
              id='nvd'
              value='nvd'
            />
          </div>
          <Form.Label>
            <small>
              Applies to Charts and Reports that assign CVSS scores to labels.
            </small>
          </Form.Label>
          <div className='d-none pre-load'>
            <img
              src={customSvg}
              alt='Custom'
            />
            <img
              src={tenableSvg}
              alt='Tenable'
            />
            <img
              src={nvdSvg}
              alt='NVD'
            />
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button
            variant='outline-light'
            className='btn-outline-light-blue'
            onClick={props.onClose}
          >
            Cancel
          </Button>
          <Button variant='primary' type='submit'>
            Save
          </Button>
        </Modal.Footer>
      </Form>
    </Modal>
  );
};

export default UserPreferencesModal;
