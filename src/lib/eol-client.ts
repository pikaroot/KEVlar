import { EolStatus } from "@/types/vulnerability";
import { compareVersions } from "@/lib/version-search";

/**
 * End-of-life / outdated-release lookups backed by endoflife.date.
 *
 * Given a parsed "<product> <version>" query, resolve the product to an
 * endoflife.date slug, fetch its release cycles, locate the branch the version
 * belongs to, and report whether that branch is end-of-life, merely behind on
 * patches, or current — with an upgrade recommendation. Everything is cached
 * in-memory and degrades gracefully: any miss or network error returns null so
 * the lookup is purely additive and never blocks a CVE result.
 */

const EOL_API = "https://endoflife.date/api";
const PRODUCT_TTL_MS = 6 * 60 * 60 * 1000; // 6h
const CATALOG_TTL_MS = 24 * 60 * 60 * 1000; // 24h

interface EolCycle {
  cycle: string;
  releaseDate?: string;
  eol?: string | boolean;
  latest?: string;
  latestReleaseDate?: string;
  support?: string | boolean;
  lts?: string | boolean;
}

// --- Caches -----------------------------------------------------------------

let catalogCache: { at: number; slugs: string[] } | null = null;
const productCache = new Map<string, { at: number; cycles: EolCycle[] | null }>();

// Common product-name aliases → endoflife.date slug. Anything not listed falls
// back to catalog matching (spaces→hyphens, substring), so this is only for the
// cases where the natural term differs from the slug.
const SLUG_ALIASES: Record<string, string> = {
  node: "nodejs",
  "node.js": "nodejs",
  nodejs: "nodejs",
  apache: "apache",
  "apache http server": "apache",
  "apache httpd": "apache",
  httpd: "apache",
  "apache tomcat": "tomcat",
  tomcat: "tomcat",
  openssl: "openssl",
  php: "php",
  python: "python",
  python3: "python",
  go: "go",
  golang: "go",
  dotnet: "dotnet",
  ".net": "dotnet",
  mysql: "mysql",
  mariadb: "mariadb",
  postgres: "postgresql",
  postgresql: "postgresql",
  django: "django",
  laravel: "laravel",
  symfony: "symfony",
  rails: "rails",
  "ruby on rails": "rails",
  ruby: "ruby",
  wordpress: "wordpress",
  drupal: "drupal",
  joomla: "joomla",
  jquery: "jquery",
  angular: "angular",
  angularjs: "angularjs",
  react: "react",
  vue: "vue",
  bootstrap: "bootstrap",
  spring: "spring-framework",
  "spring framework": "spring-framework",
  "spring boot": "spring-boot",
  kubernetes: "kubernetes",
  k8s: "kubernetes",
  docker: "docker-engine",
  nginx: "nginx",
  redis: "redis",
  mongodb: "mongodb",
  elasticsearch: "elasticsearch",
  ubuntu: "ubuntu",
  debian: "debian",
  centos: "centos",
  rhel: "rhel",
  "red hat enterprise linux": "rhel",
  fedora: "fedora",
  openssh: "openssh",
  curl: "curl",
  jenkins: "jenkins",
  gitlab: "gitlab",
  grafana: "grafana",
  terraform: "terraform",
  log4j: "log4j",
  tenables: "nessus",
};

async function fetchJson<T>(url: string): Promise<T | null> {
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/json" },
      next: { revalidate: 21600 },
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

async function getCatalog(): Promise<string[]> {
  if (catalogCache && Date.now() - catalogCache.at < CATALOG_TTL_MS) {
    return catalogCache.slugs;
  }
  const slugs = (await fetchJson<string[]>(`${EOL_API}/all.json`)) ?? [];
  catalogCache = { at: Date.now(), slugs };
  return slugs;
}

/** Map a free-text product term to an endoflife.date slug, or null. */
async function resolveSlug(product: string): Promise<string | null> {
  const key = product.toLowerCase().trim();
  if (SLUG_ALIASES[key]) return SLUG_ALIASES[key];

  const catalog = await getCatalog();
  if (catalog.length === 0) {
    // Catalog unavailable; fall back to a hyphenated guess.
    return key.replace(/\s+/g, "-");
  }
  const set = new Set(catalog);
  const hyphen = key.replace(/\s+/g, "-");
  const nospace = key.replace(/\s+/g, "");
  if (set.has(hyphen)) return hyphen;
  if (set.has(nospace)) return nospace;

  const firstWord = key.split(/\s+/)[0];
  if (set.has(firstWord)) return firstWord;

  // Prefer the shortest slug that contains the whole hyphenated term, then the
  // shortest that starts with the first word — avoids grabbing an unrelated
  // longer slug that merely shares a substring.
  const contains = catalog
    .filter((s) => s.includes(hyphen))
    .sort((a, b) => a.length - b.length);
  if (contains.length) return contains[0];

  const starts = catalog
    .filter((s) => s.startsWith(firstWord))
    .sort((a, b) => a.length - b.length);
  if (starts.length) return starts[0];

  return null;
}

async function getCycles(slug: string): Promise<EolCycle[] | null> {
  const cached = productCache.get(slug);
  if (cached && Date.now() - cached.at < PRODUCT_TTL_MS) return cached.cycles;

  const cycles = await fetchJson<EolCycle[]>(`${EOL_API}/${slug}.json`);
  productCache.set(slug, { at: Date.now(), cycles: cycles ?? null });
  return cycles ?? null;
}

/** Find the cycle whose branch string is the longest prefix of `version`. */
function matchCycle(cycles: EolCycle[], version: string): EolCycle | null {
  let best: EolCycle | null = null;
  for (const c of cycles) {
    const branch = String(c.cycle);
    if (!/^\d/.test(branch)) continue; // skip named cycles ("latest", etc.)
    if (version === branch || version.startsWith(`${branch}.`)) {
      if (!best || branch.length > String(best.cycle).length) best = c;
    }
  }
  return best;
}

function isEolValue(eol: string | boolean | undefined): {
  isEol: boolean;
  date: string | null;
} {
  if (eol === true) return { isEol: true, date: null };
  if (eol === false || eol == null) return { isEol: false, date: null };
  // Date string: EOL has passed if the date is today or earlier.
  const d = new Date(`${eol}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return { isEol: false, date: null };
  return { isEol: d.getTime() <= Date.now(), date: eol };
}

function prettyDate(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const d = new Date(`${iso}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });
}

function titleCase(slug: string): string {
  const special: Record<string, string> = {
    php: "PHP",
    openssl: "OpenSSL",
    nodejs: "Node.js",
    mysql: "MySQL",
    mariadb: "MariaDB",
    postgresql: "PostgreSQL",
    rhel: "RHEL",
    openssh: "OpenSSH",
    dotnet: ".NET",
    angularjs: "AngularJS",
    "spring-framework": "Spring Framework",
    "spring-boot": "Spring Boot",
    "apache-http-server": "Apache HTTP Server",
    jquery: "jQuery",
    "jquery-ui": "jQuery UI",
    nginx: "nginx",
    mongodb: "MongoDB",
    "docker-engine": "Docker Engine",
    gitlab: "GitLab",
  };
  if (special[slug]) return special[slug];
  return slug
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/**
 * Resolve the end-of-life posture for a `<product> <version>` query.
 * Returns null when the product can't be resolved or data is unavailable.
 */
export async function fetchEolStatus(
  product: string,
  version: string
): Promise<EolStatus | null> {
  const slug = await resolveSlug(product);
  if (!slug) return null;

  const cycles = await getCycles(slug);
  if (!cycles || cycles.length === 0) return null;

  const sourceUrl = `https://endoflife.date/${slug}`;
  const displayName = titleCase(slug);
  const latestOverall = cycles.find((c) => c.latest)?.latest;

  const cycle = matchCycle(cycles, version);

  if (!cycle) {
    // The version predates the oldest tracked branch → treat as EOL; otherwise
    // we genuinely don't know this branch.
    const branches = cycles
      .map((c) => String(c.cycle))
      .filter((b) => /^\d/.test(b));
    const oldest = branches[branches.length - 1];
    const predatesTracked =
      oldest != null && compareVersions(version, oldest) < 0;

    return {
      product: displayName,
      slug,
      queriedVersion: version,
      level: predatesTracked ? "eol" : "unknown",
      isEol: predatesTracked,
      outdatedPatch: false,
      latestOverall,
      recommendation: predatesTracked
        ? `${displayName} ${version} predates every tracked release branch and is long past end-of-life. Upgrade to a supported release${
            latestOverall ? ` (latest: ${latestOverall})` : ""
          }.`
        : `No release-lifecycle data matched ${displayName} ${version}. Verify the version against ${displayName}'s support policy.`,
      sourceUrl,
    };
  }

  const branch = String(cycle.cycle);
  const { isEol, date } = isEolValue(cycle.eol);
  const eolDate = date;
  const supportedUntil =
    typeof cycle.support === "string" ? cycle.support : null;
  const latestInCycle = cycle.latest;
  const outdatedPatch =
    !!latestInCycle && compareVersions(version, latestInCycle) < 0;

  let level: EolStatus["level"];
  let recommendation: string;

  if (isEol) {
    level = "eol";
    recommendation = `${displayName} ${branch} reached end-of-life${
      eolDate ? ` on ${prettyDate(eolDate)}` : ""
    } and no longer receives security fixes. Upgrade to a supported release${
      latestOverall ? ` (latest: ${latestOverall})` : ""
    }.`;
  } else if (outdatedPatch) {
    level = "outdated";
    recommendation = `${displayName} ${branch} is still supported, but ${version} is behind the latest patch ${latestInCycle}. Update to ${latestInCycle}${
      supportedUntil
        ? `; this branch is supported until ${prettyDate(supportedUntil)}`
        : ""
    }.`;
  } else {
    level = "supported";
    recommendation = `${displayName} ${branch} is current and supported${
      supportedUntil ? ` until ${prettyDate(supportedUntil)}` : ""
    }. You are on the latest patch for this branch.`;
  }

  return {
    product: displayName,
    slug,
    queriedVersion: version,
    cycle: branch,
    level,
    isEol,
    eolDate,
    supportedUntil,
    latestInCycle,
    latestOverall,
    outdatedPatch,
    recommendation,
    sourceUrl,
  };
}
