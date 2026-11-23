import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { Providers } from "@/components/providers";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "KEVlar — CVE, CISA KEV & Lifecycle Intelligence",
  description:
    "Look up CVEs by identifier, branded name (Log4Shell, Heartbleed) or product version. Live CISA KEV exploitation status, end-of-life checks, and one-click report copy formats.",
};

// Daily accent colour, shared with pikaroot.github.io: green -> orange -> blue ->
// violet, switching at the visitor's local midnight. Runs in <head> before first
// paint; also points the tab icon at the matching >_ logo. ?accent=<colour>
// previews one for the tab, ?accent=auto resets.
const ACCENT_SCRIPT = `(function(){var A=['green','orange','blue','violet'],a;
try{var q=new URLSearchParams(location.search).get('accent');
if(q==='auto')sessionStorage.removeItem('pk-accent');else if(A.indexOf(q)>=0)sessionStorage.setItem('pk-accent',q);
a=sessionStorage.getItem('pk-accent')}catch(e){}
if(A.indexOf(a)<0){var d=new Date();a=A[Math.floor(Date.UTC(d.getFullYear(),d.getMonth(),d.getDate())/864e5)%A.length]}
if(a!=='green')document.documentElement.setAttribute('data-accent',a);
var L=document.querySelectorAll('link[data-pk-icon]');
for(var i=0;i<L.length;i++)L[i].href=L[i].getAttribute('href').replace('green',a)})()`;

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable} dark`}
      suppressHydrationWarning // data-accent is added by ACCENT_SCRIPT before hydration
    >
      <head>
        <link rel="icon" href="/favicon-green.ico" sizes="48x48" data-pk-icon="" />
        <link rel="icon" type="image/svg+xml" href="/icon-green.svg" data-pk-icon="" />
        <script dangerouslySetInnerHTML={{ __html: ACCENT_SCRIPT }} />
      </head>
      <body className="min-h-screen font-sans antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
