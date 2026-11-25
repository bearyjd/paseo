import { useCallback, useRef } from "react";
import type { EditingTextInputHandle } from "@/components/ui/text-input";
import type { AddProjectTabView } from "./tab-view";
import { directoryQueryFor } from "./options";

/**
 * The Existing tab's search field, driven from outside it: Tab completion, opening a folder row,
 * and starting at the home folder. Each one types a new query into the field and searches for it.
 */
export function useExistingQueryInput(input: {
  rows: AddProjectTabView["rows"];
  changeQuery: (query: string) => void;
}) {
  const { rows, changeQuery } = input;
  const inputRef = useRef<EditingTextInputHandle>(null);
  const rowsRef = useRef(rows);
  rowsRef.current = rows;

  const setQuery = useCallback(
    (query: string) => {
      const field = inputRef.current;
      field?.replaceText(query, { start: query.length, end: query.length });
      field?.focus();
      changeQuery(query);
    },
    [changeQuery],
  );
  const openRow = useCallback(
    (index: number) => {
      const row = rowsRef.current[index];
      if (row) setQuery(directoryQueryFor(row.id));
    },
    [setQuery],
  );
  const browseHome = useCallback(() => setQuery("~/"), [setQuery]);
  /** Types `completion` when the field has focus; false leaves Tab to move focus as usual. */
  const complete = useCallback(
    (completion: string | null): boolean => {
      if (!completion || !inputRef.current?.isFocused()) return false;
      setQuery(completion);
      return true;
    },
    [setQuery],
  );
  return { inputRef, openRow, browseHome, complete };
}
