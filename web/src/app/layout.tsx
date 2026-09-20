import type { Metadata } from "next";
import Script from "next/script";
import { SubmissionCaptureGuard } from "@/components/analysis/submission-capture-guard";
import { applicationCapabilities } from "@/lib/config/env";
import { AppProviders } from "@/components/layout/app-providers";
import { AppShell } from "@/components/layout/app-shell";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "SecureMailScope",
    template: "%s · SecureMailScope",
  },
  description:
    "Evidence-bound cryptographic posture assessment for email transport captures.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full">
        {!applicationCapabilities.liveAnalysis ? (
          <Script id="submission-file-drop-safety" strategy="beforeInteractive">{`
            (() => {
              const preventFileNavigation = (event) => {
                const transfer = event.dataTransfer;
                if (transfer && (Array.from(transfer.types).some(type => type === 'Files' || type === 'application/x-moz-file') || Array.from(transfer.items || []).some(item => item.kind === 'file'))) event.preventDefault();
              };
              document.addEventListener('dragover', preventFileNavigation, true);
              document.addEventListener('drop', preventFileNavigation, true);
              document.addEventListener('submission-guard-ready', () => {
                document.removeEventListener('dragover', preventFileNavigation, true);
                document.removeEventListener('drop', preventFileNavigation, true);
              }, { once: true });
            })();
          `}</Script>
        ) : null}
        <AppProviders>
          <SubmissionCaptureGuard>
            <AppShell>{children}</AppShell>
          </SubmissionCaptureGuard>
        </AppProviders>
      </body>
    </html>
  );
}
