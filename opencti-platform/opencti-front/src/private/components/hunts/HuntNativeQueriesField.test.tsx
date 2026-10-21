import React from 'react';
import { Formik } from 'formik';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import HuntNativeQueriesField from './HuntNativeQueriesField';

vi.mock('./useHuntAI', () => ({ default: () => ({ isEnterpriseEdition: true, xtmOneConfigured: true, available: true }) }));

const renderField = (infrastructure: boolean) => testRender(
  <Formik initialValues={{ native_queries: [{ platform: '', language: '', query: '', pipeline: '' }] }} onSubmit={() => undefined}>
    <HuntNativeQueriesField label={infrastructure ? 'Fingerprint documents' : 'Native queries'} infrastructure={infrastructure} />
  </Formik>,
);

describe('Native queries of a hunt', () => {
  it('should word the native queries of a hunt on the detection stack as overrides of the Sigma translation', () => {
    renderField(false);
    expect(screen.getByText('Native queries override the Sigma translation on their platform.')).toBeInTheDocument();
    expect(screen.getByTestId('hunt-native-query-add')).toHaveTextContent('Add a native query');
    expect(screen.getByText('The language of the query, SPL for Splunk or KQL for Microsoft Sentinel')).toBeInTheDocument();
    expect(screen.getByLabelText('pySigma pipeline (optional)')).toBeInTheDocument();
  });

  it('should offer the native queries of a hunt on the detection stack the security platforms only, never an internet scanning service', async () => {
    const { user } = renderField(false);
    await user.click(screen.getByRole('combobox', { name: /Platform/ }));
    const platforms = screen.getAllByRole('option').map((option) => option.textContent);
    expect(platforms).toHaveLength(10);
    expect(platforms).toContain('Splunk');
    expect(platforms).toContain('SentinelOne Singularity');
    ['Censys Platform', 'Silent Push', 'urlscan.io', 'Team Cymru Scout', 'Shodan'].forEach((service) => expect(platforms).not.toContain(service));
    await user.keyboard('{Escape}');
    await user.click(screen.getByRole('combobox', { name: /Query language/ }));
    const languages = screen.getAllByRole('option').map((option) => option.textContent);
    expect(languages).toContain('SPL');
    expect(languages).not.toContain('Internet fingerprints');
  });

  it('should word the logic of an infrastructure hunt as fingerprint documents, without a Sigma pipeline', () => {
    renderField(true);
    expect(screen.getByText('Each internet scanning service runs the fingerprint document written for it, or else the first one.')).toBeInTheDocument();
    expect(screen.getByTestId('hunt-native-query-add')).toHaveTextContent('Add a fingerprint document');
    expect(screen.getByText('The internet scanning service this document is written for')).toBeInTheDocument();
    expect(screen.getByText('Internet fingerprints, the same for every service')).toBeInTheDocument();
    expect(screen.getByText('The fingerprints to look for and, optionally, a raw query per service, in YAML or JSON')).toBeInTheDocument();
    expect(screen.queryByLabelText('pySigma pipeline (optional)')).not.toBeInTheDocument();
    expect(screen.queryByText(/Sigma/)).not.toBeInTheDocument();
  });
});
