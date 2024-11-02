import LruCache from 'lru-cache';
import _ from 'underscore';
import {
  queryP as pgQueryP,
  queryP_metered as pgQueryP_metered,
  query_readOnly as pgQuery_readOnly
} from '../db/pg-query.js';
import { MPromise } from './metered.js';
const zidToConversationIdCache = new LruCache({
  max: 1000
});
export function getZinvite(zid, dontUseCache) {
  const cachedConversationId = zidToConversationIdCache.get(zid);
  if (!dontUseCache && cachedConversationId) {
    return Promise.resolve(cachedConversationId);
  }
  return pgQueryP_metered('getZinvite', 'select * from zinvites where zid = ($1);', [zid]).then((rows) => {
    const conversation_id = rows?.[0]?.zinvite || void 0;
    if (conversation_id) {
      zidToConversationIdCache.set(zid, conversation_id);
    }
    return conversation_id;
  });
}
export function getZinvites(zids) {
  if (!zids.length) {
    return Promise.resolve(zids);
  }
  zids = _.map(zids, (zid) => Number(zid));
  zids = _.uniq(zids);
  const uncachedZids = zids.filter((zid) => !zidToConversationIdCache.get(zid));
  const zidsWithCachedConversationIds = zids
    .filter((zid) => !!zidToConversationIdCache.get(zid))
    .map((zid) => ({
      zid: zid,
      zinvite: zidToConversationIdCache.get(zid)
    }));
  function makeZidToConversationIdMap(arrays) {
    const zid2conversation_id = {};
    arrays.forEach((a) => {
      a.forEach((o) => {
        zid2conversation_id[o.zid] = o.zinvite;
      });
    });
    return zid2conversation_id;
  }
  return new MPromise('getZinvites', (resolve, reject) => {
    if (uncachedZids.length === 0) {
      resolve(makeZidToConversationIdMap([zidsWithCachedConversationIds]));
      return;
    }
    pgQuery_readOnly(`select * from zinvites where zid in (${uncachedZids.join(',')});`, [], (err, result) => {
      if (err) {
        reject(err);
      } else {
        resolve(makeZidToConversationIdMap([result.rows, zidsWithCachedConversationIds]));
      }
    });
  });
}
export function getZidForRid(rid) {
  return pgQueryP('select zid from reports where rid = ($1);', [rid]).then((row) => {
    if (!row || !row.length) {
      return null;
    }
    return row[0].zid;
  });
}
