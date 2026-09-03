package com.trieu.authcache.introspection;

/**
 * Central place for every Redis key pattern this module uses, so nobody has to grep for
 * string literals when debugging production Redis. Every key is namespaced under
 * {@code introspect:} to keep it out of the way of whatever else shares this Redis instance.
 */
final class RedisKeys {

    private RedisKeys() {
    }

    /** introspect:cache:{sha256(token)} -> serialized IntrospectionResult */
    static String cache(String tokenHash) {
        return "introspect:cache:" + tokenHash;
    }

    /** introspect:lock:{sha256(token)} -> single-flight lock, prevents a stampede on Keycloak */
    static String lock(String tokenHash) {
        return "introspect:lock:" + tokenHash;
    }

    /**
     * introspect:session:{sid} -> Set<tokenHash>. Every time we cache a token that carries a
     * session id, we SADD its hash into this set. On logout we SMEMBERS this one key and DEL
     * every cache entry it points at, instead of scanning the whole keyspace.
     */
    static String sessionIndex(String sid) {
        return "introspect:session:" + sid;
    }

    /** introspect:revoked:sid:{sid} -> "1", TTL = access-token lifespan. Deny-list. */
    static String revokedSession(String sid) {
        return "introspect:revoked:sid:" + sid;
    }
}
