import { verifyToken } from '@neocaptcha/server-sdk';
import { NextRequest, NextResponse } from 'next/server';

const siteKey = process.env['SITE_KEY']!;
const siteSecret = process.env['SITE_SECRET']!;

export async function POST(request: NextRequest) {
  const { captchaToken } = await request.json();

  if (!captchaToken) {
    return NextResponse.json({ error: 'Captcha token required' }, { status: 400 });
  }

  const result = await verifyToken({ solution: captchaToken, siteKey, siteSecret });

  if (!result.success) {
    return NextResponse.json({ error: 'Captcha verification failed' }, { status: 400 });
  }

  return NextResponse.json({ success: true });
}
