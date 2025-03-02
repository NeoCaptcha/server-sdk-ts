import express from 'express';
import { verifyToken } from '@neocaptcha/server-sdk';

const app = express();
app.use(express.json());

const siteKey = process.env.SITE_KEY;
const siteSecret = process.env.SITE_SECRET;

app.post('/api/submit', async (req, res) => {
  const { captchaToken } = req.body;

  if (!captchaToken) {
    return res.status(400).json({ error: 'Captcha token required' });
  }

  const result = await verifyToken({ solution: captchaToken, siteKey, siteSecret });

  if (!result.success) {
    return res.status(400).json({ error: 'Captcha verification failed' });
  }

  res.json({ success: true });
});

app.listen(process.env.PORT || 3000);
