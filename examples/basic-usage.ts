import { verifyToken } from '../src';

const siteKey = process.env['SITE_KEY']!;
const siteSecret = process.env['SITE_SECRET']!;

export async function handleSubmit(captchaToken: string) {
  const result = await verifyToken({ solution: captchaToken, siteKey, siteSecret });

  if (result.success) {
    console.log('Captcha verified');
    return true;
  } else {
    console.error('Captcha verification failed:', result.error);
    return false;
  }
}
