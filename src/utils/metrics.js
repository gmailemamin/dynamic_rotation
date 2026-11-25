
const { performance } = require('perf_hooks');

/**
 * Konversi nanosecond menjadi millisecond.
 * Tidak melakukan pembulatan agar presisi tetap terjaga.
 */
function nanosecondsToMs(start, end) {
    return Number(end - start) / 1e6;
}

/**
 * Mengambil snapshot kondisi proses Node.js.
 */
function getSystemSnapshot() {
    const memory = process.memoryUsage();
    const cpu = process.cpuUsage();

    return {
        timestamp: performance.now(),
        cpuUserMs: cpu.user / 1000,
        cpuSystemMs: cpu.system / 1000,
        cpuTotalMs: (cpu.user + cpu.system) / 1000,
        memory: {
            rss: memory.rss,
            heapUsed: memory.heapUsed,
            heapTotal: memory.heapTotal,
            external: memory.external
        }
    };
}

/**
 * Memulai pengukuran backend.
 *
 * Metrik:
 * - Server Processing Time
 * - CPU Server
 * - Memory RSS
 * - Memory Heap
 */
function startMeasurement() {
    return {
        startTime: process.hrtime.bigint(),
        startCpu: process.cpuUsage(),
        startMemory: process.memoryUsage()
    };
}

/**
 * Mengakhiri pengukuran backend.
 */
function endMeasurement(startMeasurementData) {
    if (
        !startMeasurementData ||
        typeof startMeasurementData.startTime !== 'bigint' ||
        !startMeasurementData.startCpu
    ) {
        throw new Error('Data awal pengukuran tidak valid.');
    }

    const endTime = process.hrtime.bigint();

    // process.cpuUsage(previousValue) menghasilkan delta
    // penggunaan CPU sejak snapshot awal, dalam mikrodetik.
    const cpuDelta = process.cpuUsage(
        startMeasurementData.startCpu
    );

    const endMemory = process.memoryUsage();

    // Server Processing Time (ms)
    const serverProcessMs = nanosecondsToMs(
        startMeasurementData.startTime,
        endTime
    );

    // CPU Time (ms)
    const cpuUserMs = cpuDelta.user / 1000;
    const cpuSystemMs = cpuDelta.system / 1000;

    const cpuServerMs = cpuUserMs + cpuSystemMs;

    // Memory RSS (MB)
    const ramRssMb = endMemory.rss / (1024 * 1024);

    // Memory Heap (MB)
    const ramHeapMb = endMemory.heapUsed / (1024 * 1024);

    return {
        serverProcessMs,
        cpuServerMs,
        cpuUserMs,
        cpuSystemMs,
        ramRssMb,
        ramHeapMb
    };
}

/**
 * Mengukur operasi synchronous.
 */
function measureCrypto(operation) {
    const start = process.hrtime.bigint();

    const result = operation();

    const end = process.hrtime.bigint();

    const cryptoProcessMs = nanosecondsToMs(start, end);

    return {
        result,
        cryptoProcessMs
    };
}

/**
 * Mengukur operasi asynchronous.
 */
async function measureCryptoAsync(operation) {
    const start = process.hrtime.bigint();

    const result = await operation();

    const end = process.hrtime.bigint();

    const cryptoProcessMs = nanosecondsToMs(start, end);

    return {
        result,
        cryptoProcessMs
    };
}

/**
 * Mengambil penggunaan memory saat ini.
 */
function getMemoryUsage() {
    const memory = process.memoryUsage();

    return {
        ramRssMb: memory.rss / (1024 * 1024),
        ramHeapMb: memory.heapUsed / (1024 * 1024)
    };
}

// Menyimpan data pengukuran batch yang sedang berjalan.
let activeBatchMeasurement = null;

/**
 * Memulai pengukuran CPU dan durasi pada tingkat batch.
 * Hanya satu batch yang boleh berjalan pada satu waktu.
 */
function startBatchMeasurement() {
    if (activeBatchMeasurement) {
        throw new Error('Pengukuran batch masih berlangsung.');
    }

    const batchId = require('crypto').randomUUID();

    activeBatchMeasurement = {
        batchId,
        startTime: process.hrtime.bigint(),
        startCpu: process.cpuUsage()
    };

    return batchId;
}

/**
 * Mengakhiri pengukuran batch.
 */
function endBatchMeasurement(batchId) {
    if (
        !activeBatchMeasurement ||
        activeBatchMeasurement.batchId !== batchId
    ) {
        throw new Error('Batch ID tidak valid atau pengukuran tidak ditemukan.');
    }

    const endTime = process.hrtime.bigint();

    const elapsedMs = nanosecondsToMs(
        activeBatchMeasurement.startTime,
        endTime
    );

    const cpuDelta = process.cpuUsage(
        activeBatchMeasurement.startCpu
    );

    const cpuUserBatchMs = cpuDelta.user / 1000;
    const cpuSystemBatchMs = cpuDelta.system / 1000;

    const cpuTimeBatchMs = cpuUserBatchMs + cpuSystemBatchMs;

    const cpuUtilizationBatchPercent =
        elapsedMs > 0
            ? (cpuTimeBatchMs / elapsedMs) * 100
            : 0;

    const memory = process.memoryUsage();

    const result = {
        batchDurationMs: elapsedMs,
        cpuUserBatchMs,
        cpuSystemBatchMs,
        cpuTimeBatchMs,
        cpuUtilizationBatchPercent,
        ramRssMb: memory.rss / (1024 * 1024),
        ramHeapMb: memory.heapUsed / (1024 * 1024)
    };

    activeBatchMeasurement = null;

    return result;
}

module.exports = {
    getSystemSnapshot,
    startMeasurement,
    endMeasurement,
    measureCrypto,
    measureCryptoAsync,
    getMemoryUsage,
    startBatchMeasurement,
    endBatchMeasurement
};