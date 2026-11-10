import ipaddr from "ipaddr.js";

/**
 * Content delivery networks in front of a site. Port-scanning their addresses measures the CDN's
 * edge, not the client's servers: slow (every port answers) and of no use for the report.
 * Cloudflare publishes its ranges (https://www.cloudflare.com/ips/); they change rarely.
 */
const RANGES: Record<string, string[]> = {
  Cloudflare: [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
  ],
};

const PARSED = Object.entries(RANGES).flatMap(([provider, cidrs]) => cidrs.map((c) => ({ provider, range: ipaddr.parseCIDR(c) })));

/** The CDN an address belongs to, if any. */
export function cdnOf(ip: string): string | undefined {
  if (!ipaddr.isValid(ip)) return undefined;
  let addr = ipaddr.parse(ip);
  if (addr.kind() === "ipv6" && (addr as ipaddr.IPv6).isIPv4MappedAddress()) addr = (addr as ipaddr.IPv6).toIPv4Address();
  return PARSED.find((p) => p.range[0].kind() === addr.kind() && addr.match(p.range))?.provider;
}
