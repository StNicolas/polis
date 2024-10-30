import LruCache from 'lru-cache';
import _ from 'underscore';
import {
  queryP as pgQueryP,
  query_readOnly as pgQuery_readOnly,
  queryP_metered as pgQueryP_metered
} from '../db/pg-query.js';
import { MPromise } from './metered.js';
let zidToConversationIdCache = new LruCache({
  max: 1000
});
export function getZinvite(zid, dontUseCache) {
  let cachedConversationId = zidToConversationIdCache.get(zid);
  if (!dontUseCache && cachedConversationId) {
    return Promise.resolve(cachedConversationId);
  }
  return pgQueryP_metered('getZinvite', 'select * from zinvites where zid = ($1);', [zid]).then(function (rows) {
    let conversation_id = (rows && rows[0] && rows[0].zinvite) || void 0;
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
  zids = _.map(zids, function (zid) {
    return Number(zid);
  });
  zids = _.uniq(zids);
  let uncachedZids = zids.filter(function (zid) {
    return !zidToConversationIdCache.get(zid);
  });
  let zidsWithCachedConversationIds = zids
    .filter(function (zid) {
      return !!zidToConversationIdCache.get(zid);
    })
    .map(function (zid) {
      return {
        zid: zid,
        zinvite: zidToConversationIdCache.get(zid)
      };
    });
  function makeZidToConversationIdMap(arrays) {
    let zid2conversation_id = {};
    arrays.forEach(function (a) {
      a.forEach(function (o) {
        zid2conversation_id[o.zid] = o.zinvite;
      });
    });
    return zid2conversation_id;
  }
  return new MPromise('getZinvites', function (resolve, reject) {
    if (uncachedZids.length === 0) {
      resolve(makeZidToConversationIdMap([zidsWithCachedConversationIds]));
      return;
    }
    pgQuery_readOnly(
      'select * from zinvites where zid in (' + uncachedZids.join(',') + ');',
      [],
      function (err, result) {
        if (err) {
          reject(err);
        } else {
          resolve(makeZidToConversationIdMap([result.rows, zidsWithCachedConversationIds]));
        }
      }
    );
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
