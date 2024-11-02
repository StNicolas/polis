import logger from './logger.js';
export const METRICS_IN_RAM = {};
const SHOULD_ADD_METRICS_IN_RAM = false;
export function addInRamMetric(metricName, val) {
  if (!SHOULD_ADD_METRICS_IN_RAM) {
    return;
  }
  if (!METRICS_IN_RAM[metricName]) {
    METRICS_IN_RAM[metricName] = {
      values: new Array(1000),
      index: 0
    };
  }
  const index = METRICS_IN_RAM[metricName].index;
  METRICS_IN_RAM[metricName].values[index] = val;
  METRICS_IN_RAM[metricName].index = (index + 1) % 1000;
}
export function MPromise(name, f) {
  const p = new Promise(f);
  const start = Date.now();
  setTimeout(() => {
    addInRamMetric(`${name}.go`, 1, start);
  }, 100);
  p.then(
    () => {
      const end = Date.now();
      const duration = end - start;
      setTimeout(() => {
        addInRamMetric(`${name}.ok`, duration, end);
      }, 100);
    },
    () => {
      const end = Date.now();
      const duration = end - start;
      setTimeout(() => {
        addInRamMetric(`${name}.fail`, duration, end);
      }, 100);
    }
  ).catch((err) => {
    logger.error('MPromise internal error', err);
    const end = Date.now();
    const duration = end - start;
    setTimeout(() => {
      addInRamMetric(`${name}.fail`, duration, end);
      logger.error('MPromise internal error', err);
    }, 100);
  });
  return p;
}
export default { addInRamMetric, MPromise };
