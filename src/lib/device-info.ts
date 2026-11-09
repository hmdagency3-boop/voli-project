/** Browser-only: a stable per-phone ID plus the phone details the browser exposes. Call from effects. */
export function getDeviceId(): string {
  const key = "voli-device-id";
  let id = localStorage.getItem(key);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(key, id);
  }
  return id;
}

type UAData = {
  platform?: string;
  getHighEntropyValues?: (h: string[]) => Promise<{ model?: string; platformVersion?: string; brands?: { brand: string }[] }>;
};

export async function getDeviceDetails() {
  const nav = navigator as Navigator & { userAgentData?: UAData; connection?: { effectiveType?: string; type?: string } };
  const ua = navigator.userAgent;
  let model = "", osVersion = "", brand = "";
  let platform = nav.userAgentData?.platform ?? "";
  try {
    const hi = await nav.userAgentData?.getHighEntropyValues?.(["model", "platformVersion"]);
    model = hi?.model ?? "";
    osVersion = hi?.platformVersion ?? "";
  } catch { /* not supported */ }
  const android = ua.match(/Android\s([\d.]+);\s*([^;)]+?)(?:\sBuild|\))/);
  if (android) {
    platform ||= "Android";
    osVersion ||= android[1] ?? "";
    model ||= android[2]?.trim() ?? "";
  }
  const ios = ua.match(/(iPhone|iPad).*?OS\s([\d_]+)/);
  if (ios) {
    platform ||= "iOS";
    model ||= ios[1] ?? "";
    brand = "Apple";
    osVersion ||= (ios[2] ?? "").replace(/_/g, ".");
  }
  platform ||= navigator.platform ?? "";
  const connection = nav.connection?.type ?? nav.connection?.effectiveType ?? "";
  return { platform, model, brand, osVersion, connection };
}
