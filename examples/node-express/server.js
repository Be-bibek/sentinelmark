import express from 'express';
import { SentinelMark, SentinelMarkError } from 'sentinelmark';
import crypto from 'crypto';

const app = express();
app.use(express.json());

const smClient = new SentinelMark({
  apiKey: process.env.SENTINELMARK_API_KEY || 'sm_test_1234',
});

app.post('/upload-scan', async (req, res) => {
  const { modality, uid } = req.body;

  try {
    const decision = await smClient.events.evaluate({
      productSlug: 'dicom-trace',
      eventType: 'scan_upload',
      payload: {
        modality,
        affected_instance_uid: uid,
        z_score: 1.2
      },
      idempotencyKey: crypto.randomUUID()
    });

    const action = decision.data.decision;

    if (action === 'BLOCK') {
      return res.status(403).json({ error: 'Upload rejected due to watermark failure.' });
    }

    res.status(200).json({ status: 'Upload successful.' });

  } catch (error) {
    if (error instanceof SentinelMarkError) {
      console.error(`SentinelMark Error: ${error.message}`);
    }
    // Fail open or closed depending on compliance
    res.status(500).json({ error: 'Internal system error.' });
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));
