const { performance } = require('perf_hooks');

/**
 * Mengambil snapshot kondisi proses Node.js.
 */
function getSystemSnapshot() {
    const memory = process.memoryUsage();
    const cpu = process.cpuUsage();

    return {
        timestamp: performance.now(),
        cpu,
        memory
    };
}

/**
 * Memulai pengukuran proses backend.
 */
function startMeasurement() {
    return {
        startTime: process.hrtime.bigint(),
        startCpu: process.cpuUsage(),
        startMemory: process.memoryUsage()
    };
}

/**
 * Mengakhiri pengukuran proses backend.
 *
 * Mengukur:
 * - Server Processing Time
 * - CPU Time
 * - Memory RSS
 * - Memory Heap
 */
function endMeasurement(startMeasurementData) {
    const endTime = process.hrtime.bigint();

    const endCpu = process.cpuUsage(startMeasurementData.startCpu);
    const endMemory = process.memoryUsage();

    // Server Processing Time
    const serverProcessMs = Number(
        (Number(endTime - startMeasurementData.startTime) / 1e6).toFixed(3)
    );

    // CPU Time
    const cpuServerMs = Number(
        ((endCpu.user + endCpu.system) / 1000).toFixed(6)
    );

    // Memory RSS
    const ramRssMb = Number(
        (endMemory.rss / 1024 / 1024).toFixed(2)
    );

    // Memory Heap
    const ramHeapMb = Number(
        (endMemory.heapUsed / 1024 / 1024).toFixed(2)
    );

    return {
        serverProcessMs,
        cpuServerMs,
        ramRssMb,
        ramHeapMb
    };
}

/**
 * Mengukur waktu suatu operasi synchronous.
 */
function measureCrypto(operation) {
    const start = process.hrtime.bigint();
    const result = operation();
    const end = process.hrtime.bigint();
    const cryptoProcessMs = Number(
        (Number(end - start) / 1e6).toFixed(3)
    );

    return {
        result,
        cryptoProcessMs
    };
}

/**
 * Mengukur waktu suatu operasi asynchronous.
 */
async function measureCryptoAsync(operation) {
    const start = process.hrtime.bigint();
    const result = await operation();
    const end = process.hrtime.bigint();
    const cryptoProcessMs = Number(
        (Number(end - start) / 1e6).toFixed(3)
    );

    return {
        result,
        cryptoProcessMs
    };
}

/**
 * Membuat snapshot penggunaan memory.
 */
function getMemoryUsage() {
    const memory = process.memoryUsage();

    return {
        ramRssMb: Number(
            (memory.rss / 1024 / 1024).toFixed(2)
        ),
        ramHeapMb: Number(
            (memory.heapUsed / 1024 / 1024).toFixed(2)
        )
    };
}

module.exports = {
    getSystemSnapshot,
    startMeasurement,
    endMeasurement,
    measureCrypto,
    measureCryptoAsync,
    getMemoryUsage
};