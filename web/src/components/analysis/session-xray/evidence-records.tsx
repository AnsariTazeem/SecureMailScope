"use client";

import { useState } from "react";
import { Input } from "@/components/ui/input";
import { EvidenceInspector } from "./evidence-inspector";
import type { XRayEvidence } from "./session-xray-view-model";

export function EvidenceRecords({ evidence }: { evidence: XRayEvidence[] }) {
  const [query, setQuery] = useState("");
  const needle = query.trim().toLowerCase();
  const rows = evidence.filter((item) =>
    [
      item.evidenceId,
      item.sourceField,
      item.safeExcerpt ?? "",
      ...item.frameNumbers.map(String),
    ]
      .join(" ")
      .toLowerCase()
      .includes(needle),
  );
  return (
    <div className="space-y-4 border-t border-border p-4">
      <label className="block text-sm font-medium" htmlFor="evidence-search">
        Search evidence records
      </label>
      <Input
        id="evidence-search"
        placeholder="Frame, field, evidence ID or safe excerpt"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
      />
      <p role="status" className="text-xs text-muted-foreground">
        {rows.length} of {evidence.length} records
      </p>
      {rows.length ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <caption className="sr-only">
              Evidence references for the current session
            </caption>
            <thead>
              <tr className="border-b border-border">
                <th scope="col" className="p-3">
                  Frames
                </th>
                <th scope="col" className="p-3">
                  Source field
                </th>
                <th scope="col" className="p-3">
                  Reference
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => (
                <tr
                  key={item.evidenceId}
                  className="border-b border-border last:border-0"
                >
                  <td className="p-3 font-mono">
                    {item.frameNumbers.join(", ")}
                  </td>
                  <td className="break-all p-3 font-mono">
                    {item.sourceField}
                  </td>
                  <td className="p-3">
                    <EvidenceInspector
                      evidence={item}
                      label={item.evidenceId}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="py-5 text-sm text-muted-foreground">
          {evidence.length
            ? "No evidence matches this search."
            : "No evidence references were supplied for this session."}
        </p>
      )}
    </div>
  );
}
