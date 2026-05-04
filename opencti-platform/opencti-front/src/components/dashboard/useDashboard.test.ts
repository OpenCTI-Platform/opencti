import { assert, describe, it, expect, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import fileDownload from 'js-file-download';
import { emptyFilterGroup } from 'src/utils/filters/filtersUtils';
import { Widget } from 'src/utils/widget/widget';
import { dayAgo, formatDate } from 'src/utils/Time';
import { DashboardLike, DashboardManifest, DashboardWidget } from './dashboard-types';
import useDashboard from './useDashboard';

// Bypass JSON & B64 serilization from the process to make it
// easier (and faster) to run & debug tests
vi.mock(import('./dashboard-utils'), async (importOriginal) => {
  const mockedSerialize = (manifest: DashboardManifest) => manifest as unknown as string;
  const mockedDeserialize = (manifest: string | null | undefined) => manifest as unknown as DashboardManifest;
  const originalModule = await importOriginal();
  return {
    ...originalModule,
    serializeDashboardManifestForBackend: mockedSerialize,
    deserializeDashboardManifestForFrontend: mockedDeserialize,
  };
});
const fakeSerialize = (manifest: DashboardManifest) => manifest as unknown as string;

vi.mock('js-file-download');

describe('useDashboard', () => {
  describe('reading an empty dashboard', () => {
    it('returns empty data structures', () => {
      const entity = {
        id: '8b5aa367-3ed7-40ca-a3ff-3dc326327b49',
        manifest: fakeSerialize({
          config: {},
          widgets: {},
        }),
      };
      const { result } = renderHook(() => useDashboard({ entity }));
      const { widgetsArray, widgetsLayouts } = result.current;
      expect(widgetsArray).toStrictEqual([]);
      expect(widgetsLayouts).toStrictEqual({});
    });
  });

  describe('using handleAddWidget to insert a widget', () => {
    const widget = {
      id: 'cf12d6b4-2884-4c68-9afa-79b2242651f3',
      type: 'text',
      perspective: 'entities',
      parameters: {
        title: 'Some title',
        interval: null,
        stacked: false,
        legend: true,
        distributed: false,
        content: 'Some content',
      },
      dataSelection: [{
        label: 'Some data',
        number: 10,
        sort_by: 'created_at',
        sort_mode: 'desc',
        attribute: 'entity_type',
        date_attribute: 'created_at',
        perspective: null,
        isTo: true,
        filters: emptyFilterGroup,
        dynamicFrom: emptyFilterGroup,
        dynamicTo: emptyFilterGroup,
      }],
    } satisfies Widget;

    it('adds a first widget to the layout', () => {
      const entity = {
        id: '802cbd27-7af4-4eb8-a5d2-3eee65f7049f',
        manifest: fakeSerialize({
          config: {},
          widgets: {},
        }),
      };
      const saveSpy = vi.fn();
      const { result, rerender } = renderHook((entity: Pick<DashboardLike, 'id' | 'manifest'>) => useDashboard({
        entity,
        onSave: saveSpy,
      }), { initialProps: entity });

      // Act: add widget to the dashboard
      act(() => result.current.handleAddWidget(widget));

      const addedWidget = {
        ...widget,
        layout: {
          i: widget.id,
          x: 0,
          y: 0,
          w: 4,
          h: 2,
          moved: false,
          static: false,
        },
      };
      const expectedSerializedManifest = fakeSerialize({
        config: {},
        widgets: { [addedWidget.id]: addedWidget },
      });
      expect(saveSpy).toHaveBeenCalledExactlyOnceWith(
        entity.id,
        expectedSerializedManifest,
        false,
        expect.any(Function),
      );

      // Re-render to mimick entity getting updated in the store
      rerender({ ...entity, manifest: expectedSerializedManifest });
      expect(result.current.widgetsArray).toContainEqual(addedWidget);
      expect(result.current.widgetsLayouts).toStrictEqual({
        [addedWidget.id]: addedWidget.layout,
      });
    });

    it('adds a widget at the bottom of the layout', () => {
      const existingWidget = {
        id: '474752bc-4a56-4b05-8230-633b0ca97cb2',
        type: 'text',
        perspective: 'entities',
        dataSelection: [],
        layout: {
          i: '474752bc-4a56-4b05-8230-633b0ca97cb2',
          x: 0,
          y: 7,
          w: 4,
          h: 4,
          moved: false,
          static: false,
        },
      } as DashboardWidget;
      const entity = {
        id: '802cbd27-7af4-4eb8-a5d2-3eee65f7049f',
        manifest: fakeSerialize({
          config: {},
          widgets: {
            [existingWidget.id]: existingWidget,
          },
        }),
      };
      const saveSpy = vi.fn();
      const { result, rerender } = renderHook((entity: Pick<DashboardLike, 'id' | 'manifest'>) => useDashboard({
        entity,
        onSave: saveSpy,
      }), { initialProps: entity });

      // Act: add widget to the dashboard
      act(() => result.current.handleAddWidget(widget));

      const addedWidget = {
        ...widget,
        layout: {
          i: widget.id,
          x: 0,
          y: 11, // Added at the bottom of the dashboard
          w: 4,
          h: 2,
          moved: false,
          static: false,
        },
      };
      const expectedSerializedManifest = fakeSerialize({
        config: {},
        widgets: {
          [existingWidget.id]: existingWidget,
          [addedWidget.id]: addedWidget,
        },
      });
      expect(saveSpy).toHaveBeenCalledExactlyOnceWith(
        entity.id,
        expectedSerializedManifest,
        false,
        expect.any(Function),
      );

      // Re-render to mimick entity getting updated in the store
      rerender({ ...entity, manifest: expectedSerializedManifest });
      expect(result.current.widgetsArray).toContainEqual(existingWidget);
      expect(result.current.widgetsArray).toContainEqual(addedWidget);
      expect(result.current.widgetsLayouts).toStrictEqual({
        [existingWidget.id]: existingWidget.layout,
        [addedWidget.id]: addedWidget.layout,
      });
    });
  });

  describe('using handleDateChange to configure the date range of the dashboard', () => {
    it('applies absolute date range and relative range', () => {
      const entity = {
        id: '802cbd27-7af4-4eb8-a5d2-3eee65f7049f',
        manifest: fakeSerialize({
          config: {},
          widgets: {},
        }),
      };
      const saveSpy = vi.fn();
      const { result, rerender } = renderHook((entity: Pick<DashboardLike, 'id' | 'manifest'>) => useDashboard({
        entity,
        onSave: saveSpy,
      }), { initialProps: entity });

      // Act: change date range
      const startDate = formatDate('2026-04-27 22:39');
      act(() => result.current.handleDateChange('startDate', startDate));

      let expectedSerializedManifest = fakeSerialize({
        config: {
          startDate,
        },
        widgets: {},
      });
      expect(saveSpy).toHaveBeenCalledWith(
        entity.id,
        expectedSerializedManifest,
        false,
        expect.any(Function),
      );

      // Re-render to mimick entity getting updated in the store
      rerender({ ...entity, manifest: expectedSerializedManifest });
      expect(result.current.config).toMatchObject({ startDate });

      // Act: change endDate
      const endDate = formatDate('2026-04-27 23:39');
      act(() => result.current.handleDateChange('endDate', endDate));

      expectedSerializedManifest = fakeSerialize({
        config: {
          startDate,
          endDate,
        },
        widgets: {},
      });
      expect(saveSpy).toHaveBeenCalledWith(
        entity.id,
        expectedSerializedManifest,
        false,
        expect.any(Function),
      );

      // Re-render to mimick entity getting updated in the store
      rerender({ ...entity, manifest: expectedSerializedManifest });
      expect(result.current.config).toMatchObject({
        startDate,
        endDate,
      });

      // Act: apply relativeDate
      const relativeDate = dayAgo();
      act(() => result.current.handleDateChange('relativeDate', relativeDate));

      expectedSerializedManifest = fakeSerialize({
        config: {
          startDate: null,
          endDate: null,
          relativeDate,
        },
        widgets: {},
      });
      expect(saveSpy).toHaveBeenCalledWith(
        entity.id,
        expectedSerializedManifest,
        false,
        expect.any(Function),
      );

      // Re-render to mimick entity getting updated in the store
      rerender({ ...entity, manifest: expectedSerializedManifest });
      expect(result.current.config).toMatchObject({
        startDate: null,
        endDate: null,
        relativeDate,
      });
    });
  });

  describe('using handleUpdateWidget to update a widget in the dashboard', () => {
    it('applies the updated config', () => {
      const existingWidget = {
        id: '474752bc-4a56-4b05-8230-633b0ca97cb2',
        type: 'text',
        perspective: 'entities',
        dataSelection: [],
        layout: {
          i: '474752bc-4a56-4b05-8230-633b0ca97cb2',
          x: 0,
          y: 7,
          w: 4,
          h: 4,
          moved: false,
          static: false,
        },
        parameters: {
          title: 'Initial title',
        },
      } as DashboardWidget;
      const entity = {
        id: '802cbd27-7af4-4eb8-a5d2-3eee65f7049f',
        manifest: fakeSerialize({
          config: {},
          widgets: {
            [existingWidget.id]: existingWidget,
          },
        }),
      };
      const saveSpy = vi.fn();
      const { result, rerender } = renderHook((entity: Pick<DashboardLike, 'id' | 'manifest'>) => useDashboard({
        entity,
        onSave: saveSpy,
      }), { initialProps: entity });

      // Act: update widget
      const updatedWidget = {
        ...existingWidget,
        parameters: {
          title: 'Modified title',
        },
      };
      act(() => result.current.handleUpdateWidget(updatedWidget));

      const expectedSerializedManifest = fakeSerialize({
        config: {},
        widgets: {
          [existingWidget.id]: updatedWidget,
        },
      });
      expect(saveSpy).toHaveBeenCalledExactlyOnceWith(
        entity.id,
        expectedSerializedManifest,
        false,
        expect.any(Function),
      );

      // Re-render to mimick entity getting updated in the store
      rerender({ ...entity, manifest: expectedSerializedManifest });
      expect(result.current.widgetsArray).not.toContainEqual(existingWidget);
      expect(result.current.widgetsArray).toContainEqual(updatedWidget);
    });
  });

  describe('using handleDeleteWidget to delete a widget in the dashboard', () => {
    it('applies the deletion', () => {
      const existingWidget = {
        id: '474752bc-4a56-4b05-8230-633b0ca97cb2',
        type: 'text',
        perspective: 'entities',
        dataSelection: [],
        layout: {
          i: '474752bc-4a56-4b05-8230-633b0ca97cb2',
          x: 0,
          y: 7,
          w: 4,
          h: 4,
          moved: false,
          static: false,
        },
      } as DashboardWidget;
      const entity = {
        id: '802cbd27-7af4-4eb8-a5d2-3eee65f7049f',
        manifest: fakeSerialize({
          config: {},
          widgets: {
            [existingWidget.id]: existingWidget,
          },
        }),
      };
      const saveSpy = vi.fn();
      const { result, rerender } = renderHook((entity: Pick<DashboardLike, 'id' | 'manifest'>) => useDashboard({
        entity,
        onSave: saveSpy,
      }), { initialProps: entity });

      // Act: delete widget
      act(() => result.current.handleDeleteWidget(existingWidget.id));

      const expectedSerializedManifest = fakeSerialize({
        config: {},
        widgets: {},
      });
      expect(saveSpy).toHaveBeenCalledExactlyOnceWith(
        entity.id,
        expectedSerializedManifest,
        false,
        expect.any(Function),
      );

      // Re-render to mimick entity getting updated in the store
      rerender({ ...entity, manifest: expectedSerializedManifest });
      expect(result.current.widgetsArray).toStrictEqual([]);
      expect(result.current.widgetsLayouts).toStrictEqual({});
    });
  });

  describe('using handleDuplicateWidget to duplicate a widget in the dashboard', () => {
    it('applies the duplication', () => {
      const existingWidget = {
        id: '474752bc-4a56-4b05-8230-633b0ca97cb2',
        type: 'text',
        perspective: 'entities',
        dataSelection: [],
        layout: {
          i: '474752bc-4a56-4b05-8230-633b0ca97cb2',
          x: 0,
          y: 7,
          w: 4,
          h: 4,
          moved: false,
          static: false,
        },
      } as DashboardWidget;
      const entity = {
        id: '802cbd27-7af4-4eb8-a5d2-3eee65f7049f',
        manifest: fakeSerialize({
          config: {},
          widgets: {
            [existingWidget.id]: existingWidget,
          },
        }),
      };
      const saveSpy = vi.fn();
      const { result, rerender } = renderHook((entity: Pick<DashboardLike, 'id' | 'manifest'>) => useDashboard({
        entity,
        onSave: saveSpy,
      }), { initialProps: entity });

      // Act: duplicate widget
      act(() => result.current.handleDuplicateWidget(existingWidget));

      const duplicatedWidget = {
        ...existingWidget,
        id: '9d6dfe5d-0471-4f6c-a578-9468d83ccfca',
        layout: {
          i: '9d6dfe5d-0471-4f6c-a578-9468d83ccfca',
          x: 0,
          y: 11, // Added at the bottom of the dashboard
          w: 4,
          h: 2,
          moved: false,
          static: false,
        },
      };
      const expectedSerializedManifest = fakeSerialize({
        config: {},
        widgets: {
          [existingWidget.id]: existingWidget,
          [duplicatedWidget.id]: {
            ...duplicatedWidget,
          },
        },
      });

      // Re-render to mimick entity getting updated in the store
      rerender({ ...entity, manifest: expectedSerializedManifest });
      expect(result.current.widgetsArray).toContainEqual(existingWidget);
      expect(result.current.widgetsArray).toContainEqual(duplicatedWidget);
      expect(result.current.widgetsLayouts).toStrictEqual({
        [existingWidget.id]: existingWidget.layout,
        [duplicatedWidget.id]: duplicatedWidget.layout,
      });
    });
  });

  describe('using handleLayoutChange to edit the layout of the dashboard', () => {
    it('applies the layout change and calls onSave with noRefresh=true', () => {
      const existingWidget = {
        id: '474752bc-4a56-4b05-8230-633b0ca97cb2',
        type: 'text',
        perspective: 'entities',
        dataSelection: [],
        layout: {
          i: '474752bc-4a56-4b05-8230-633b0ca97cb2',
          x: 0,
          y: 7,
          w: 4,
          h: 4,
          moved: false,
          static: false,
        },
      } as DashboardWidget;
      const entity = {
        id: '802cbd27-7af4-4eb8-a5d2-3eee65f7049f',
        manifest: fakeSerialize({
          config: {},
          widgets: {
            [existingWidget.id]: existingWidget,
          },
        }),
      };
      const saveSpy = vi.fn();
      const { result } = renderHook((entity: Pick<DashboardLike, 'id' | 'manifest'>) => useDashboard({
        entity,
        onSave: saveSpy,
      }), { initialProps: entity });

      expect(result.current.widgetsLayouts).toStrictEqual({
        [existingWidget.id]: existingWidget.layout,
      });

      // Act: change layout
      act(() => result.current.handleLayoutChange([{
        ...existingWidget.layout,
        x: 2,
        w: 7,
      }]));
      // Call twice to check noop when layouts are equal
      act(() => result.current.handleLayoutChange([{
        ...existingWidget.layout,
        x: 2,
        w: 7,
      }]));

      const expectedSerializedManifest = fakeSerialize({
        config: {},
        widgets: {
          [existingWidget.id]: {
            ...existingWidget,
            layout: {
              ...existingWidget.layout,
              x: 2,
              w: 7,
            },
          },
        },
      });
      expect(saveSpy).toHaveBeenCalledExactlyOnceWith(
        entity.id,
        expectedSerializedManifest,
        true,
        expect.any(Function),
      );
      expect(result.current.widgetsLayouts).toStrictEqual({
        [existingWidget.id]: {
          ...existingWidget.layout,
          x: 2,
          w: 7,
        },
      });
    });
  });

  describe('using handleImportWidget to import a widget into the dashboard', () => {
    it('calls onImportWidget prop if provided with synced widget layouts', () => {
      const existingWidget = {
        id: '474752bc-4a56-4b05-8230-633b0ca97cb2',
        type: 'text',
        perspective: 'entities',
        dataSelection: [],
        layout: {
          i: '474752bc-4a56-4b05-8230-633b0ca97cb2',
          x: 0,
          y: 7,
          w: 4,
          h: 4,
          moved: false,
          static: false,
        },
      } as DashboardWidget;
      const entity = {
        id: '802cbd27-7af4-4eb8-a5d2-3eee65f7049f',
        manifest: fakeSerialize({
          config: {},
          widgets: {
            [existingWidget.id]: existingWidget,
          },
        }),
      };
      const importWidgetSpy = vi.fn();
      const { result } = renderHook((entity: Pick<DashboardLike, 'id' | 'manifest'>) => useDashboard({
        entity,
        onImportWidget: importWidgetSpy,
      }), { initialProps: entity });

      // Act: change layout
      act(() => result.current.handleLayoutChange([{
        ...existingWidget.layout,
        x: 2,
        w: 7,
      }]));

      const fakeFile = {} as unknown as File;

      // Act: import widget
      act(() => result.current.handleImportWidget(fakeFile));

      const expectedSerializedManifest = fakeSerialize({
        config: {},
        widgets: {
          [existingWidget.id]: {
            ...existingWidget,
            layout: {
              ...existingWidget.layout,
              x: 2,
              w: 7,
            },
          },
        },
      });
      expect(importWidgetSpy).toHaveBeenCalledExactlyOnceWith(
        entity.id,
        fakeFile,
        expectedSerializedManifest,
      );
    });
  });

  describe('using handleExportWidget to export a widget from the dashboard', () => {
    it('does not crash when onExportWidget is not provided', async () => {
      const existingWidget = {
        id: '474752bc-4a56-4b05-8230-633b0ca97cb2',
        type: 'text',
        perspective: 'entities',
        dataSelection: [],
        layout: {
          i: '474752bc-4a56-4b05-8230-633b0ca97cb2',
          x: 0,
          y: 7,
          w: 4,
          h: 4,
          moved: false,
          static: false,
        },
      } as DashboardWidget;
      const entity = {
        id: '802cbd27-7af4-4eb8-a5d2-3eee65f7049f',
        manifest: fakeSerialize({
          config: {},
          widgets: {
            [existingWidget.id]: existingWidget,
          },
        }),
      };
      const { result } = renderHook((entity: Pick<DashboardLike, 'id' | 'manifest'>) => useDashboard({
        entity,
        onExportWidget: undefined, // Intentionally not provided
      }), { initialProps: entity });

      // Act: export widget
      assert.doesNotThrow(async () => {
        await act(async () => result.current.handleExportWidget(entity.id, {
          id: existingWidget.id,
          type: existingWidget.type,
        }));
      });
    });

    it('triggers a file download with a correctly formatted name', async () => {
      const existingWidget = {
        id: '474752bc-4a56-4b05-8230-633b0ca97cb2',
        type: 'text',
        perspective: 'entities',
        dataSelection: [],
        layout: {
          i: '474752bc-4a56-4b05-8230-633b0ca97cb2',
          x: 0,
          y: 7,
          w: 4,
          h: 4,
          moved: false,
          static: false,
        },
      } as DashboardWidget;
      const entity = {
        id: '802cbd27-7af4-4eb8-a5d2-3eee65f7049f',
        manifest: fakeSerialize({
          config: {},
          widgets: {
            [existingWidget.id]: existingWidget,
          },
        }),
      };
      const exportWidgetStub = vi.fn().mockResolvedValue('some-string');
      const { result } = renderHook((entity: Pick<DashboardLike, 'id' | 'manifest'>) => useDashboard({
        entity,
        onExportWidget: exportWidgetStub,
      }), { initialProps: entity });

      // Act: export widget
      await act(async () => result.current.handleExportWidget(entity.id, {
        id: existingWidget.id,
        type: existingWidget.type,
      }));

      expect(vi.mocked(fileDownload)).toHaveBeenCalledExactlyOnceWith(
        expect.any(Blob),
        expect.stringMatching(new RegExp(`^[0-9]{8}_octi_widget_${existingWidget.type}.json$`, 'i')),
      );
    });
  });

  describe('using handleResize to notify a resize is occurring', () => {
    it('mutates the idToResize value', () => {
      const existingWidget = {
        id: '474752bc-4a56-4b05-8230-633b0ca97cb2',
        type: 'text',
        perspective: 'entities',
        dataSelection: [],
        layout: {
          i: '474752bc-4a56-4b05-8230-633b0ca97cb2',
          x: 0,
          y: 7,
          w: 4,
          h: 4,
          moved: false,
          static: false,
        },
      } as DashboardWidget;
      const entity = {
        id: '802cbd27-7af4-4eb8-a5d2-3eee65f7049f',
        manifest: fakeSerialize({
          config: {},
          widgets: {
            [existingWidget.id]: existingWidget,
          },
        }),
      };
      const saveSpy = vi.fn();
      const { result } = renderHook((entity: Pick<DashboardLike, 'id' | 'manifest'>) => useDashboard({
        entity,
        onSave: saveSpy,
      }), { initialProps: entity });

      expect(result.current.idToResize).toBe(null);

      // Act: resize
      act(() => result.current.handleResize(existingWidget.id));

      expect(result.current.idToResize).toBe(existingWidget.id);
    });
  });
});
