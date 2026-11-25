
const express = require('express');
const router = express.Router();

const {
    startBatchMeasurement,
    endBatchMeasurement
} = require('../utils/metrics');

/**
 * Memulai pengukuran batch.
 * POST /api/measurement/batch/start
 */
router.post('/batch/start', (req, res) => {
    try {
        const batchId = startBatchMeasurement();

        res.status(200).json({
            status: 'started',
            batchId,
            message: 'Pengukuran batch berhasil dimulai.'
        });

    } catch (error) {
        res.status(409).json({
            status: 'error',
            message: error.message
        });
    }
});

/**
 * Mengakhiri pengukuran batch.
 * POST /api/measurement/batch/end
 */
router.post('/batch/end', (req, res) => {
    try {
        const { batchId } = req.body;

        if (!batchId) {
            return res.status(400).json({
                status: 'error',
                message: 'Batch ID wajib disertakan.'
            });
        }

        const metrics = endBatchMeasurement(batchId);

        res.status(200).json({
            status: 'completed',
            batchId,
            metrics
        });

    } catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message
        });
    }
});

module.exports = router;
