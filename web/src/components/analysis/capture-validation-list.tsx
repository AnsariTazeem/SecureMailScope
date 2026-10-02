import { CheckCircle2 } from "lucide-react";

export type CaptureValidationItem = {
  label: string;
  detail: string;
  passed: boolean;
};

export function CaptureValidationList({
  items,
}: {
  items: readonly CaptureValidationItem[];
}) {
  return (
    <section aria-labelledby="capture-validation-heading">
      <h2
        id="capture-validation-heading"
        className="text-xs font-bold uppercase tracking-[0.06em] text-neutral-900"
      >
        Validation results
      </h2>
      <ul
        aria-live="polite"
        className="mt-3 divide-y divide-neutral-200 rounded-lg border border-neutral-200"
      >
        {items.map((item) => (
          <li key={item.label} className="flex items-start gap-3 px-4 py-3">
            <CheckCircle2
              className={
                item.passed
                  ? "mt-0.5 size-4 shrink-0 text-[#027a48]"
                  : "mt-0.5 size-4 shrink-0 text-neutral-300"
              }
              aria-hidden
            />
            <div>
              <p className="text-sm font-medium text-neutral-900">{item.label}</p>
              <p className="mt-0.5 text-xs text-neutral-500">{item.detail}</p>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
