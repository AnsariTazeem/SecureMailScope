import type { Metadata } from "next";
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
        <AppProviders>
          <AppShell>{children}</AppShell>
        </AppProviders>
      </body>
    </html>
  );
}
