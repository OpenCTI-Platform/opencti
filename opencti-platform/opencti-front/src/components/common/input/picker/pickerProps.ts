// The object form of a slot's props: the wrappers merge their own props into it.
type ObjectForm<T> = Exclude<T, (...args: never[]) => unknown>;

/**
 * Props of an x-date-pickers picker once wrapped: the wrapper owns the section selection, and the
 * field's `fieldRef` and `onKeyUpCapture` (see `useFieldSectionSelection`), so a caller cannot
 * pass them, and passes the field slot's props in their object form.
 */
export type WithSectionSelection<P extends { slotProps?: { field?: unknown } }> = Omit<P, 'selectedSections' | 'onSelectedSectionsChange' | 'slotProps'> & {
  slotProps?: Omit<NonNullable<P['slotProps']>, 'field'> & {
    field?: Omit<ObjectForm<NonNullable<NonNullable<P['slotProps']>['field']>>, 'fieldRef' | 'onKeyUpCapture'>;
  };
};
