import zlib from 'zlib';
import LruCache from 'lru-cache';
import _ from 'underscore';
import Config from '../config.js';
import { queryP_readOnly as pgQueryP_readOnly } from '../db/pg-query.js';
import logger from './logger.js';
import { addInRamMetric } from './metered.js';
const pcaCacheSize = Config.cacheMathResults ? 300 : 1;
const pcaCache = new LruCache({
  max: pcaCacheSize
});
let lastPrefetchedMathTick = -1;
export function fetchAndCacheLatestPcaData() {
  const lastPrefetchPollStartTime = Date.now();
  function waitTime() {
    const timePassed = Date.now() - lastPrefetchPollStartTime;
    return Math.max(0, 2500 - timePassed);
  }
  pgQueryP_readOnly('select * from math_main where caching_tick > ($1) order by caching_tick limit 10;', [
    lastPrefetchedMathTick
  ])
    .then((rows) => {
      if (!rows || !rows.length) {
        logger.info('mathpoll done');
        setTimeout(fetchAndCacheLatestPcaData, waitTime());
        return;
      }
      const results = rows.map((row) => {
        const item = row.data;
        if (row.math_tick) {
          item.math_tick = Number(row.math_tick);
        }
        if (row.caching_tick) {
          item.caching_tick = Number(row.caching_tick);
        }
        logger.info('mathpoll updating', {
          caching_tick: item.caching_tick,
          zid: item.zid
        });
        if (item.caching_tick > lastPrefetchedMathTick) {
          lastPrefetchedMathTick = item.caching_tick;
        }
        processMathObject(item);
        return updatePcaCache(item.zid, item);
      });
      Promise.all(results).then((_a) => {
        setTimeout(fetchAndCacheLatestPcaData, waitTime());
      });
    })
    .catch((err) => {
      logger.error('mathpoll error', err);
      setTimeout(fetchAndCacheLatestPcaData, waitTime());
    });
}
export function getPca(zid, math_tick) {
  let cached = pcaCache.get(zid);
  if (cached && cached.expiration < Date.now()) {
    cached = undefined;
  }
  const cachedPOJO = cached?.asPOJO;
  if (cachedPOJO) {
    if (cachedPOJO.math_tick <= (math_tick || 0)) {
      logger.info('math was cached but not new', {
        zid,
        cached_math_tick: cachedPOJO.math_tick,
        query_math_tick: math_tick
      });
      return Promise.resolve(undefined);
    }
    logger.info('math from cache', { zid, math_tick });
    return Promise.resolve(cached);
  }
  logger.info('mathpoll cache miss', { zid, math_tick });
  const queryStart = Date.now();
  return pgQueryP_readOnly('select * from math_main where zid = ($1) and math_env = ($2);', [zid, Config.mathEnv]).then(
    (rows) => {
      const queryEnd = Date.now();
      const queryDuration = queryEnd - queryStart;
      addInRamMetric('pcaGetQuery', queryDuration);
      if (!rows || !rows.length) {
        logger.info('mathpoll related; after cache miss, unable to find data for', {
          zid,
          math_tick,
          math_env: Config.mathEnv
        });
        return undefined;
      }
      const item = rows[0].data;
      if (rows[0].math_tick) {
        item.math_tick = Number(rows[0].math_tick);
      }
      if (item.math_tick <= (math_tick || 0)) {
        logger.info('after cache miss, unable to find newer item', {
          zid,
          math_tick
        });
        return undefined;
      }
      logger.info('after cache miss, found item, adding to cache', {
        zid,
        math_tick
      });
      processMathObject(item);
      return updatePcaCache(zid, item);
    }
  );
}
function updatePcaCache(zid, item) {
  return new Promise((resolve, reject) => {
    item.zid = undefined;
    const asJSON = JSON.stringify(item);
    const buf = Buffer.from(asJSON, 'utf-8');
    zlib.gzip(buf, (err, jsondGzipdPcaBuffer) => {
      if (err) {
        return reject(err);
      }
      const o = {
        asPOJO: item,
        asJSON: asJSON,
        asBufferOfGzippedJson: jsondGzipdPcaBuffer,
        expiration: Date.now() + 3000
      };
      pcaCache.set(zid, o);
      resolve(o);
    });
  });
}
function processMathObject(o) {
  function remapSubgroupStuff(g) {
    if (_.isArray(g.val)) {
      g.val = g.val.map((x) => {
        return { id: Number(x.id), val: x };
      });
    } else {
      g.val = _.keys(g.val).map((id) => {
        return { id: Number(id), val: g.val[id] };
      });
    }
    return g;
  }
  if (_.isArray(o['group-clusters'])) {
    o['group-clusters'] = o['group-clusters'].map((g) => {
      return { id: Number(g.id), val: g };
    });
  }
  if (!_.isArray(o.repness)) {
    o.repness = _.keys(o.repness).map((gid) => {
      return { id: Number(gid), val: o.repness[gid] };
    });
  }
  if (!_.isArray(o['group-votes'])) {
    o['group-votes'] = _.keys(o['group-votes']).map((gid) => {
      return { id: Number(gid), val: o['group-votes'][gid] };
    });
  }
  if (!_.isArray(o['subgroup-repness'])) {
    o['subgroup-repness'] = _.keys(o['subgroup-repness']).map((gid) => {
      return { id: Number(gid), val: o['subgroup-repness'][gid] };
    });
    o['subgroup-repness'].map(remapSubgroupStuff);
  }
  if (!_.isArray(o['subgroup-votes'])) {
    o['subgroup-votes'] = _.keys(o['subgroup-votes']).map((gid) => {
      return { id: Number(gid), val: o['subgroup-votes'][gid] };
    });
    o['subgroup-votes'].map(remapSubgroupStuff);
  }
  if (!_.isArray(o['subgroup-clusters'])) {
    o['subgroup-clusters'] = _.keys(o['subgroup-clusters']).map((gid) => {
      return { id: Number(gid), val: o['subgroup-clusters'][gid] };
    });
    o['subgroup-clusters'].map(remapSubgroupStuff);
  }
  function toObj(a) {
    const obj = {};
    if (!a) {
      return obj;
    }
    for (let i = 0; i < a.length; i++) {
      obj[a[i].id] = a[i].val;
      obj[a[i].id].id = a[i].id;
    }
    return obj;
  }
  function toArray(a) {
    if (!a) {
      return [];
    }
    return a.map((g) => {
      const id = g.id;
      g = g.val;
      g.id = id;
      return g;
    });
  }
  o.repness = toObj(o.repness);
  o['group-votes'] = toObj(o['group-votes']);
  o['group-clusters'] = toArray(o['group-clusters']);
  o['subgroup-repness'] = undefined;
  o['subgroup-votes'] = undefined;
  o['subgroup-clusters'] = undefined;
  return o;
}
