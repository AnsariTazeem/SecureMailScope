"use client";

import { useEffect, useLayoutEffect, useRef, useState, type RefObject } from "react";
import { usePathname } from "next/navigation";
import { Info, LockKeyhole, TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { getAnalysisDataSourceForId } from "@/lib/api/client";
import {
  analysisResultSchema,
  DATASET_LABEL,
  type AnalysisResult,
} from "@/lib/contracts/analysis";
import { validateProofMapIntegrity } from "@/components/analysis/proof-map/proof-map-integrity";

type DetailsState =
  | { status: "loading" }
  | { status: "error" }
  | { status: "ready"; result: AnalysisResult };

function stateLabel(value: string): string {
  const readable = value.replaceAll("_", " ");
  return readable.charAt(0).toUpperCase() + readable.slice(1);
}

function DetailsContent({
  analysisId,
  entry,
  entryReady,
  scrollRegionRef,
}: {
  analysisId: string;
  entry: "top" | "coverage";
  entryReady: boolean;
  scrollRegionRef: RefObject<HTMLDivElement | null>;
}) {
  const [state, setState] = useState<DetailsState>({ status: "loading" });
  const coverageHeadingRef = useRef<HTMLHeadingElement>(null);
  const enteredRef = useRef(false);
  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const result = analysisResultSchema.parse(
          await getAnalysisDataSourceForId(analysisId).getResult(analysisId),
        );
        const consistentSource =
          result.data_source === "mock"
            ? result.dataset_kind === "prototype_analysis_dataset" &&
              result.dataset_label === DATASET_LABEL
            : result.dataset_kind === "production_analysis_result" &&
              result.dataset_label === null;
        if (
          result.chain.analysis.analysis_id !== analysisId ||
          !consistentSource
        )
          throw new Error("Result identity mismatch");
        validateProofMapIntegrity(result);
        if (!cancelled) setState({ status: "ready", result });
      } catch {
        if (!cancelled) setState({ status: "error" });
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [analysisId]);
  useLayoutEffect(() => {
    // Opening and loading may finish in either order. Navigate just once for
    // this opening, after the dialog's focus entry and transition have settled.
    if (!entryReady) {
      enteredRef.current = false;
      return;
    }
    if (state.status !== "ready" || enteredRef.current) return;

    const body = scrollRegionRef.current;
    if (!body) return;
    if (entry === "coverage") {
      const heading = coverageHeadingRef.current;
      if (!heading) return;
      // scrollIntoView can also move the popup/background ancestors. Compute
      // the target within the actual scroll owner and move only that element.
      const top = body.scrollTop + heading.getBoundingClientRect().top -
        body.getBoundingClientRect().top - body.clientTop;
      heading.focus({ preventScroll: true });
      body.scrollTop = top;
    } else {
      body.scrollTop = 0;
    }
    enteredRef.current = true;
  }, [entry, entryReady, scrollRegionRef, state.status]);
  if (state.status === "loading")
    return <p role="status">Loading analysis details…</p>;
  if (state.status === "error")
    return (
      <p role="alert">
        Analysis details could not be loaded. Close and reopen this panel to
        retry.
      </p>
    );
  const { chain, data_source } = state.result;
  const analysis = chain.analysis;
  const rows = [
    { label: "Analysis ID", value: analysis.analysis_id },
    {
      label: "Source",
      value:
        data_source === "mock"
          ? (state.result.dataset_label ?? DATASET_LABEL)
          : "Production API",
    },
    {
      label: "Analysis status",
      value: stateLabel(analysis.analysis_status),
      rawState: analysis.analysis_status,
    },
    { label: "Started (UTC)", value: analysis.started_at },
    {
      label: "Completed (UTC)",
      value: analysis.completed_at ?? "Not available",
    },
    { label: "Analyzer", value: analysis.analyzer_version },
    { label: "TShark", value: analysis.tshark_version ?? "Not available" },
    { label: "Schema", value: chain.chain_schema_version },
    {
      label: "Rule pack",
      value:
        [analysis.rule_pack_id, analysis.rule_pack_version]
        .filter(Boolean)
        .join(" · ") || "Not available",
    },
    {
      label: "Policy engine",
      value: stateLabel(analysis.rule_engine_status),
      rawState: analysis.rule_engine_status,
    },
    {
      label: "ML engine",
      value: stateLabel(analysis.ml_engine_status),
      rawState: analysis.ml_engine_status,
    },
    {
      label: "TLS 1.3 authorized secrets",
      value: stateLabel(analysis.tls13_authorized_secrets),
      rawState: analysis.tls13_authorized_secrets,
    },
    { label: "Configuration digest", value: analysis.configuration_digest },
  ];
  const tls13Unavailable = chain.crypto_observations.filter(
    (observation) => observation.kind === "tls13_certificate_unavailable",
  );
  return (
    <div className="space-y-6">
      <dl className="space-y-3">
        {rows.map((row) => (
          <div key={row.label}>
            <dt className="text-xs text-muted-foreground">{row.label}</dt>
            <dd className="mt-1 break-all text-xs leading-5">
              <span className={row.rawState ? "font-medium" : "font-mono"}>
                {row.value}
              </span>
              {row.rawState ? (
                <span className="mt-0.5 block text-[11px] text-muted-foreground">
                  Raw state: <code>{row.rawState}</code>
                </span>
              ) : null}
            </dd>
          </div>
        ))}
      </dl>
      {chain.captures.map((capture) => (
        <section
          key={capture.capture_id}
          className="space-y-3 border-t border-border pt-5"
        >
          <h3 className="break-all font-semibold">
            {capture.original_filename_sanitized}
          </h3>
          <dl className="space-y-3">
            {[
              ["Capture ID", capture.capture_id],
              ["Capture SHA-256", capture.sha256],
              ["Format", capture.format],
              ["Size", `${capture.size_bytes.toLocaleString("en")} bytes`],
              ["Packets", capture.packet_count.toLocaleString("en")],
              [
                "Truncated packets",
                capture.truncated_packet_count.toLocaleString("en"),
              ],
              [
                "Capture start (UTC)",
                capture.captured_at_start ?? "Not available",
              ],
              ["Capture end (UTC)", capture.captured_at_end ?? "Not available"],
              [
                "Link layers",
                capture.link_layer_types.join(", ") || "Not available",
              ],
              [
                "Snapshot length",
                capture.snaplen === null
                  ? "Not available"
                  : String(capture.snaplen),
              ],
            ].map(([label, value]) => (
              <div key={label}>
                <dt className="text-xs text-muted-foreground">{label}</dt>
                <dd className="mt-1 break-all font-mono text-xs leading-5">
                  {value}
                </dd>
              </div>
            ))}
          </dl>
          {Object.keys(capture.ingestion_tool_versions).length ? (
            <div>
              <h4 className="text-xs font-semibold">Ingestion tools</h4>
              <dl className="mt-2 space-y-2">
                {Object.entries(capture.ingestion_tool_versions).map(
                  ([tool, version]) => (
                    <div key={tool}>
                      <dt className="text-xs text-muted-foreground">{tool}</dt>
                      <dd className="mt-0.5 break-all font-mono text-xs">
                        {version}
                      </dd>
                    </div>
                  ),
                )}
              </dl>
            </div>
          ) : null}
        </section>
      ))}
      <section className="space-y-5 border-t border-border pt-5">
        <div>
          <h3
            ref={coverageHeadingRef}
            tabIndex={-1}
            className="font-semibold outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
          >
            Assessment coverage
          </h3>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">
            Capture warnings, evidence boundaries and analysis limitations.
          </p>
        </div>
        {chain.captures.some((capture) => capture.capture_warnings.length) ? (
          <div className="space-y-3">
            <h4 className="flex items-center gap-2 text-sm font-semibold">
              <TriangleAlert className="size-4 text-amber-800" aria-hidden />
              Capture warnings
            </h4>
            {chain.captures.map((capture) =>
              capture.capture_warnings.length ? (
                <div
                  key={capture.capture_id}
                  className="rounded-md border border-amber-200 bg-amber-50 p-3"
                >
                  <p className="break-all text-xs font-semibold text-neutral-950">
                    {capture.original_filename_sanitized || capture.capture_id}
                  </p>
                  <ul className="mt-2 list-disc space-y-2 pl-4 text-xs">
                    {capture.capture_warnings.map((warning, i) => (
                      <li key={i}>{warning}</li>
                    ))}
                  </ul>
                </div>
              ) : null,
            )}
          </div>
        ) : (
          <div>
            <h4 className="text-sm font-semibold">Capture warnings</h4>
            <p className="mt-1 text-xs text-muted-foreground">
              No capture warnings were supplied.
            </p>
          </div>
        )}
        <div className="space-y-3 border-t border-border pt-5">
          <div className="flex items-start gap-2">
            <LockKeyhole
              className="mt-0.5 size-4 shrink-0 text-amber-800"
              aria-hidden
            />
            <div>
              <h4 className="font-semibold">Evidence boundary</h4>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">
                Passive observation establishes visible transport events, not
                decrypted message content.
              </p>
            </div>
          </div>
          <p className="text-xs leading-5">
            Packet payloads, message bodies, AUTH credentials and secrets are
            not displayed here. Encrypted application data remains encrypted;
            its presence does not imply decryption.
          </p>
          <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-xs leading-5">
            <p className="font-semibold text-neutral-950">
              TLS 1.3 certificate visibility
            </p>
            <p className="mt-1">
              Without authorized session secrets, certificate contents after
              ServerHello are not observable. This does not mean a certificate
              is missing, invalid, expired or trusted.
            </p>
            {tls13Unavailable.length ? (
              <ul className="mt-2 space-y-2">
                {tls13Unavailable.map((observation) => (
                  <li key={observation.observation_id}>
                    <span>{stateLabel(observation.observability)}</span>
                    <span className="block text-[11px] text-muted-foreground">
                      <code>{observation.observability}</code> ·{" "}
                      <code>{observation.observation_id}</code>
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-2 text-muted-foreground">
                No TLS 1.3 certificate visibility constraint is recorded.
              </p>
            )}
          </div>
        </div>
        <div className="border-t border-border pt-5">
          <h4 className="font-semibold">Analysis limitations</h4>
          {analysis.limitations.length ? (
            <ul className="mt-3 space-y-3">
              {analysis.limitations.map((item, i) => (
                <li key={i} className="text-sm">
                  <p>{item.summary}</p>
                  {item.detail ? (
                    <p className="mt-1 text-xs leading-5 text-muted-foreground">
                      {item.detail}
                    </p>
                  ) : null}
                  <p className="mt-1 text-[11px] text-muted-foreground">
                    Raw state: <code>{item.code}</code>
                  </p>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-2 text-sm text-muted-foreground">
              No analysis-level limitations were supplied.
            </p>
          )}
        </div>
      </section>
    </div>
  );
}

export function AnalysisDetails({
  trigger = "navigation",
}: {
  trigger?: "navigation" | "coverage";
}) {
  const pathname = usePathname();
  const analysisId = pathname.match(
    /^\/analysis\/(ana_[0-9a-f]{16})(?:\/|$)/,
  )?.[1];
  const [open, setOpen] = useState(false);
  const [openingComplete, setOpeningComplete] = useState(false);
  const [focusEntered, setFocusEntered] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const titleRef = useRef<HTMLHeadingElement>(null);
  const scrollRegionRef = useRef<HTMLDivElement>(null);
  if (!analysisId) return null;
  return (
    <Sheet
      open={open}
      onOpenChange={(nextOpen) => {
        setOpeningComplete(false);
        setFocusEntered(false);
        setOpen(nextOpen);
      }}
      onOpenChangeComplete={setOpeningComplete}
    >
      <SheetTrigger
        render={
          <Button
            ref={triggerRef}
            variant={trigger === "coverage" ? "outline" : "ghost"}
            className={
              trigger === "coverage"
                ? "shrink-0 bg-white"
                : "w-full justify-start text-sm"
            }
          />
        }
      >
        <Info className="size-4" aria-hidden />
        {trigger === "coverage" ? "Review analysis details" : "Analysis details"}
      </SheetTrigger>
      <SheetContent
        initialFocus={() => {
          // Own focus entry so Base UI cannot enqueue another focus/scroll
          // after coverage navigation. Keep focus inside while data loads.
          titleRef.current?.focus({ preventScroll: true });
          if (scrollRegionRef.current) scrollRegionRef.current.scrollTop = 0;
          setFocusEntered(true);
          return false;
        }}
        finalFocus={triggerRef}
        className="w-full gap-0 overflow-hidden sm:max-w-lg"
      >
        <SheetHeader className="shrink-0 border-b border-border pr-12">
          <SheetTitle ref={titleRef} tabIndex={-1}>Analysis details</SheetTitle>
          <SheetDescription>
            Capture provenance, tool versions and assessment limitations.
          </SheetDescription>
        </SheetHeader>
        <div
          ref={scrollRegionRef}
          className="min-h-0 flex-1 overflow-y-auto p-5"
        >
          {open ? (
            <DetailsContent
              key={`${analysisId}:${trigger}`}
              analysisId={analysisId}
              entry={trigger === "coverage" ? "coverage" : "top"}
              entryReady={open && openingComplete && focusEntered}
              scrollRegionRef={scrollRegionRef}
            />
          ) : null}
        </div>
      </SheetContent>
    </Sheet>
  );
}
