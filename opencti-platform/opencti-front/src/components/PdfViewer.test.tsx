import React, { Component, ReactNode, Suspense } from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { Document } from 'react-pdf';
import PdfViewer from './PdfViewer';

const brokenPdf = () => new File(
  [new Uint8Array([1, 2, 3, 4])],
  'broken.pdf',
  { type: 'application/pdf' },
);

class TestErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { failed: false };
  }

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    if (this.state.failed) return <div>BOUNDARY</div>;
    return this.props.children;
  }
}

describe('PdfViewer', () => {
  it('renders its own loader instead of suspending to the surrounding fallback', () => {
    render(
      <Suspense fallback={<div>ROUTE_FALLBACK</div>}>
        <PdfViewer pdf={brokenPdf()} />
      </Suspense>,
    );

    expect(screen.getByRole('progressbar')).toBeInTheDocument();
    expect(screen.queryByText('ROUTE_FALLBACK')).not.toBeInTheDocument();
  });
});

describe('Document load failure', () => {
  it('reaches onLoadError without escaping to the Error Boundary', async () => {
    const onLoadError = vi.fn();

    render(
      <TestErrorBoundary>
        <Document
          file={brokenPdf()}
          suspense={false}
          loading={<div>DOCUMENT_LOADING</div>}
          onLoadError={onLoadError}
        />
      </TestErrorBoundary>,
    );

    expect(screen.getByText('DOCUMENT_LOADING')).toBeInTheDocument();
    await waitFor(() => expect(onLoadError).toHaveBeenCalled());
    expect(screen.queryByText('BOUNDARY')).not.toBeInTheDocument();
  });
});
