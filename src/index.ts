const VERIFY_URL = "https://neocaptcha.com/api/v1/verify";

export interface VerifyTokenOptions {
  solution: string;
  siteKey: string;
  siteSecret: string;
}

export interface VerifyTokenResult {
  success: boolean;
  error?: string;
}

export async function verifyToken(opts: VerifyTokenOptions): Promise<VerifyTokenResult> {
  const response = await fetch(VERIFY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      solution: opts.solution,
      siteKey: opts.siteKey,
      secret: opts.siteSecret,
    }),
  });

  return response.json() as Promise<VerifyTokenResult>;
}
