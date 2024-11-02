import LruCache from 'lru-cache';
import pg from './db/pg-query.js';
import logger from './utils/logger.js';
import { MPromise } from './utils/metered.js';
function createXidRecord(ownerUid, uid, xid, x_profile_image_url, x_name, x_email) {
  return pg.queryP(
    'insert into xids (owner, uid, xid, x_profile_image_url, x_name, x_email) values ($1, $2, $3, $4, $5, $6) ' +
      'on conflict (owner, xid) do nothing;',
    [ownerUid, uid, xid, x_profile_image_url || null, x_name || null, x_email || null]
  );
}
function createXidRecordByZid(zid, uid, xid, x_profile_image_url, x_name, x_email) {
  return getConversationInfo(zid).then((conv) => {
    const shouldCreateXidRecord = conv.use_xid_whitelist ? isXidWhitelisted(conv.owner, xid) : Promise.resolve(true);
    return shouldCreateXidRecord.then((should) => {
      if (!should) {
        throw new Error('polis_err_xid_not_whitelisted_2');
      }
      return pg.queryP(
        'insert into xids (owner, uid, xid, x_profile_image_url, x_name, x_email) values ((select org_id from conversations where zid = ($1)), $2, $3, $4, $5, $6) ' +
          'on conflict (owner, xid) do nothing;',
        [zid, uid, xid, x_profile_image_url || null, x_name || null, x_email || null]
      );
    });
  });
}
function getXidRecord(xid, zid) {
  return pg.queryP(
    'select * from xids where xid = ($1) and owner = (select org_id from conversations where zid = ($2));',
    [xid, zid]
  );
}
function isXidWhitelisted(owner, xid) {
  return pg.queryP('select * from xid_whitelist where owner = ($1) and xid = ($2);', [owner, xid]).then((rows) => {
    return !!rows && rows.length > 0;
  });
}
function getConversationInfo(zid) {
  return new MPromise('getConversationInfo', (resolve, reject) => {
    pg.query('SELECT * FROM conversations WHERE zid = ($1);', [zid], (err, result) => {
      if (err) {
        reject(err);
      } else {
        resolve(result.rows[0]);
      }
    });
  });
}
function getConversationInfoByConversationId(conversation_id) {
  return new MPromise('getConversationInfoByConversationId', (resolve, reject) => {
    pg.query(
      'SELECT * FROM conversations WHERE zid = (select zid from zinvites where zinvite = ($1));',
      [conversation_id],
      (err, result) => {
        if (err) {
          reject(err);
        } else {
          resolve(result.rows[0]);
        }
      }
    );
  });
}
const conversationIdToZidCache = new LruCache({
  max: 1000
});
function getZidFromConversationId(conversation_id) {
  return new MPromise('getZidFromConversationId', (resolve, reject) => {
    const cachedZid = conversationIdToZidCache.get(conversation_id);
    if (cachedZid) {
      resolve(cachedZid);
      return;
    }
    pg.query_readOnly('select zid from zinvites where zinvite = ($1);', [conversation_id], (err, results) => {
      if (err) {
        return reject(err);
      }
      if (!results || !results.rows || !results.rows.length) {
        logger.error(`polis_err_fetching_zid_for_conversation_id ${conversation_id}`, err);
        return reject('polis_err_fetching_zid_for_conversation_id');
      }
      const zid = results.rows[0].zid;
      conversationIdToZidCache.set(conversation_id, zid);
      return resolve(zid);
    });
  });
}
export default {
  createXidRecordByZid,
  createXidRecord,
  getXidRecord,
  isXidWhitelisted,
  getConversationInfo,
  getConversationInfoByConversationId,
  getZidFromConversationId
};
