import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  type SortingState,
  useReactTable,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDown, ArrowUp } from "./icons";
import { type ReactNode, useRef, useState } from "react";

/**
 * Sortable, filterable, virtualized table. Only the visible rows are rendered, so tens of
 * thousands of assets stay smooth.
 */
export function DataTable<T>(props: {
  data: T[];
  columns: Array<ColumnDef<T, any> & { width?: string }>;
  filter?: string;
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  selected?: string;
  rowClassName?: (row: T) => string;
  empty?: ReactNode;
  initialSort?: SortingState;
}) {
  const [sorting, setSorting] = useState<SortingState>(props.initialSort ?? []);
  const table = useReactTable({
    data: props.data,
    columns: props.columns,
    state: { sorting, globalFilter: props.filter ?? "" },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    globalFilterFn: "includesString",
    getRowId: (row) => props.rowKey(row),
  });
  const rows = table.getRowModel().rows;
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 35,
    overscan: 12,
  });
  const template = props.columns.map((c) => c.width ?? "1fr").join(" ");

  if (props.data.length === 0 && props.empty) return <>{props.empty}</>;

  return (
    <div className="table-wrap" ref={scrollRef}>
      <div className="thead">
        {table.getHeaderGroups().map((hg) => (
          <div className="tr" key={hg.id} style={{ gridTemplateColumns: template }}>
            {hg.headers.map((h) => (
              <div key={h.id} className="th" onClick={h.column.getToggleSortingHandler()}>
                {flexRender(h.column.columnDef.header, h.getContext())}
                {h.column.getIsSorted() === "asc" ? <ArrowUp size={11} /> : h.column.getIsSorted() === "desc" ? <ArrowDown size={11} /> : null}
              </div>
            ))}
          </div>
        ))}
      </div>
      <div className="tbody" style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
        {virtualizer.getVirtualItems().map((v) => {
          const row = rows[v.index]!;
          return (
            <div
              key={row.id}
              className={`tr ${props.selected === row.id ? "selected" : ""} ${props.rowClassName?.(row.original) ?? ""}`}
              style={{ gridTemplateColumns: template, position: "absolute", top: 0, left: 0, right: 0, transform: `translateY(${v.start}px)`, height: v.size }}
              onClick={() => props.onRowClick?.(row.original)}
            >
              {row.getVisibleCells().map((cell) => (
                <div key={cell.id} className="td">
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}
