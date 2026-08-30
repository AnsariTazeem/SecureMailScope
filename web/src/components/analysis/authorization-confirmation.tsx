"use client";

import { Checkbox } from "@/components/ui/checkbox";

type AuthorizationConfirmationProps = {
  confirmed: boolean;
  onConfirmedChange: (confirmed: boolean) => void;
};

export function AuthorizationConfirmation({
  confirmed,
  onConfirmedChange,
}: AuthorizationConfirmationProps) {
  return (
    <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-neutral-200 p-4 transition-colors hover:bg-neutral-50 focus-within:ring-2 focus-within:ring-neutral-950 focus-within:ring-offset-2">
      <Checkbox
        checked={confirmed}
        onCheckedChange={onConfirmedChange}
        aria-describedby="authorization-description"
      />
      <span>
        <span className="block text-sm font-semibold text-neutral-900">
          I am authorized to analyze this capture
        </span>
        <span
          id="authorization-description"
          className="mt-1 block text-xs leading-5 text-neutral-500"
        >
          I confirm that I have permission to process the capture and review its
          network metadata.
        </span>
      </span>
    </label>
  );
}
