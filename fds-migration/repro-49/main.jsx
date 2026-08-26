// Minimal repro for LIBRARY-FEEDBACK #49, outside OpenCTI: React + the built
// design system, no product code. Measures document.body's pointer-events after
// each close path, for the library Select AND the library Combobox.
import { useState } from 'react';
import { createRoot } from 'react-dom/client';
import * as RawSelect from '@radix-ui/react-select';
import {
  Combobox, ComboboxChips, ComboboxContent, ComboboxControls, ComboboxField, ComboboxInput,
  ComboboxLabel, ComboboxTrigger,
  Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue,
} from '@filigran/design-system';

const OPTIONS = [
  { value: 'a', label: 'Alpha' },
  { value: 'b', label: 'Bravo' },
  { value: 'c', label: 'Charlie' },
];

function App() {
  const [sel, setSel] = useState('a');
  const [cbx, setCbx] = useState(null);
  const [mountSelect, setMountSelect] = useState(true);
  const [mountCbx, setMountCbx] = useState(true);
  const [idf, setIdf] = useState([]);
  const [dflt, setDflt] = useState([]);
  const [theme, setTheme] = useState('dark');

  return (
    <div className={theme} data-theme={theme} id="probe-root">
      <button id="toggle-theme" onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}>
        theme: {theme}
      </button>
      {/* The control the E2E specs click AFTER interacting with a field. If body
          keeps pointer-events:none this button resolves and never becomes
          actionable — the exact CI signature. */}
      <button id="after-button" onClick={() => { window.__afterClicked = (window.__afterClicked ?? 0) + 1; }}>
        after-button
      </button>

      <h3>library Select</h3>
      {mountSelect && (
        <Select value={sel} onValueChange={setSel}>
          <SelectLabel>Probe select</SelectLabel>
          <SelectTrigger id="sel-trigger"><SelectValue /></SelectTrigger>
          <SelectContent aria-label="Probe select">
            {OPTIONS.map((o) => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
          </SelectContent>
        </Select>
      )}
      <button id="unmount-select" onClick={() => setMountSelect(false)}>unmount select</button>
      <button id="remount-select" onClick={() => setMountSelect(true)}>remount select</button>

      <h3>library Combobox</h3>
      {mountCbx && (
        <Combobox options={OPTIONS} value={cbx} onValueChange={setCbx}
          getOptionLabel={(o) => o?.label ?? ''}
          isOptionEqualToValue={(a, b) => a.value === b.value}
        >
          <ComboboxLabel>Probe combobox</ComboboxLabel>
          <ComboboxField>
            <ComboboxInput id="cbx-input" />
            <ComboboxControls><ComboboxTrigger id="cbx-trigger" /></ComboboxControls>
          </ComboboxField>
          <ComboboxContent listAriaLabel="Probe combobox" />
        </Combobox>
      )}
      <button id="unmount-cbx" onClick={() => setMountCbx(false)}>unmount combobox</button>
      <button id="remount-cbx" onClick={() => setMountCbx(true)}>remount combobox</button>

      {/* Control: RAW Radix Select, no design system involved. Distinguishes a
          library defect from an upstream Radix behaviour. */}
      <h3>raw Radix Select (control)</h3>
      <RawSelect.Root value={sel} onValueChange={setSel}>
        <RawSelect.Trigger id="raw-trigger"><RawSelect.Value /></RawSelect.Trigger>
        <RawSelect.Portal>
          <RawSelect.Content>
            <RawSelect.Viewport>
              {OPTIONS.map((o) => (
                <RawSelect.Item key={o.value} value={o.value}>
                  <RawSelect.ItemText>{o.label}</RawSelect.ItemText>
                </RawSelect.Item>
              ))}
            </RawSelect.Viewport>
          </RawSelect.Content>
        </RawSelect.Portal>
      </RawSelect.Root>

      {/* Does a create row still appear when filterOptions is the identity
          function? ExternalReferencesField uses it because its search is
          server-side, and incidentResponse fails clicking the Create row. */}
      <h3>Combobox with identity filterOptions</h3>
      <Combobox
        options={OPTIONS}
        multiple
        value={idf}
        onValueChange={setIdf}
        getOptionLabel={(o) => o?.label ?? ''}
        isOptionEqualToValue={(a, b) => a.value === b.value}
        filterOptions={(options) => options}
        onCreateOption={(input) => { window.__created = input; }}
      >
        <ComboboxLabel>Identity filter</ComboboxLabel>
        <ComboboxField>
          <ComboboxChips aria-label="Identity filter" />
          <ComboboxInput id="idf-input" />
          <ComboboxControls><ComboboxTrigger /></ComboboxControls>
        </ComboboxField>
        <ComboboxContent listAriaLabel="Identity filter" />
      </Combobox>

      {/* Control: same field WITHOUT filterOptions. */}
      <h3>Combobox with default filtering</h3>
      <Combobox
        options={OPTIONS}
        multiple
        value={dflt}
        onValueChange={setDflt}
        getOptionLabel={(o) => o?.label ?? ''}
        isOptionEqualToValue={(a, b) => a.value === b.value}
        onCreateOption={(input) => { window.__created = input; }}
      >
        <ComboboxLabel>Default filter</ComboboxLabel>
        <ComboboxField>
          <ComboboxChips aria-label="Default filter" />
          <ComboboxInput id="dflt-input" />
          <ComboboxControls><ComboboxTrigger /></ComboboxControls>
        </ComboboxField>
        <ComboboxContent listAriaLabel="Default filter" />
      </Combobox>

      <div id="log" />
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
