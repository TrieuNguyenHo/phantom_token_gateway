# token-introspection-lab

Hai cách giữ cho việc validate token với Keycloak nhanh, đặt cạnh nhau để so sánh — dựng cho
**câu 02** trong `phong-van-kinh-nghiem-lam-viec.html` (*"giảm token introspection latency từ
~200ms xuống dưới 5ms bằng Redis caching như thế nào?"*).

> Đang làm việc với Claude Code trong repo này? Đọc **[CLAUDE.md](CLAUDE.md)** — có commands,
> module map, invariants và backlog. File này là phần dành cho người đọc.

## Bài toán

Mặc định của Spring Security là gọi `/protocol/openid-connect/token/introspect` **mỗi request**.
Bình thường ~5–20ms; khi traffic tăng và hàng chục service cùng dội vào một Keycloak thì nó phình
lên hàng trăm ms, và Keycloak trở thành điểm nghẽn của cả hệ thống. Cả hai approach dưới đây đều
xoá bỏ cú round-trip đó khỏi hot path — khác nhau ở **chỗ đặt cache**.

## Approach A — cache trong từng service (`resource-server-cache/`)

Đây là cái đã làm thật ở TTEK và là con số trong CV. Mỗi resource server tự introspect và tự cache.

| Ý trong câu trả lời | Code |
|---|---|
| Key = `sha256(token)`, không bao giờ lưu raw token | `TokenHasher`, `RedisKeys` |
| `TTL = min(thời gian còn lại, 30s)` | `IntrospectionCacheService.putPositive` |
| Negative caching TTL ngắn có jitter (2–5s) | `IntrospectionCacheService.putNegative` |
| Tầng 1 — TTL ngắn | chính cái TTL trên, lớp bảo hiểm cuối |
| Tầng 2 — Keycloak Event Listener SPI | `KeycloakEventWebhookController`, `RedisPubSubEvictionListener` |
| Tầng 3 — OIDC Backchannel Logout | `BackchannelLogoutController` + `LogoutTokenVerifier` |
| Tầng 4 — revocation deny-list | `markSessionRevoked` / `isSessionRevoked`, ép trong `toPrincipal` |
| Evict hàng loạt theo session, không `KEYS`/`SCAN` | `indexForSession` / `evictBySession` |
| Redis chết: fail-closed security, fail-open availability | `RedisCachedOpaqueTokenIntrospector.resolve` + `KeycloakIntrospectionClient` |
| Chống cache stampede | `tryAcquireLock` / `releaseLock` (SET NX + Lua compare-and-delete) |

**Điểm yếu — nên tự nêu trước khi bị hỏi:** N service ⇒ N cache, N nơi phải nhận event
invalidation, N nơi có thể sai, và mỗi service cần client secret để gọi introspect.

## Approach B — phantom token ở gateway (`gateway/` + `resource-service/`)

Đây là mặc định được khuyến nghị hiện nay cho hệ thống public-facing. Gateway là **thành phần duy
nhất** nói chuyện với Keycloak.

```
Client ──Bearer AT──▶ Gateway ──▶ Redis (cache)          Service nội bộ
                        │                                      ▲
                        └──POST /introspect ────▶ Keycloak     │
                           Accept: application/jwt             │
                        └──Bearer <internal JWT>───────────────┘
                                                    verify offline bằng JWKS
```

9 bước đầy đủ:

1. **Login** — Authorization Code + PKCE → Keycloak trả access token.
2. **Call API** — client gọi gateway kèm `Authorization: Bearer <AT>`.
3. **Tra cache** — key `sha256(AT)`. Hit thì nhảy thẳng bước 6.
4. **Introspect** — `POST /introspect` với `Accept: application/jwt`, dùng credential **của
   gateway**. Nhận về `active` + JWT đầy đủ.
5. **Cache** — TTL `min(exp còn lại, 30s)`, index theo `sid`, single-flight lock chống stampede.
6. **Forward** — thay header thành `Authorization: Bearer <internal JWT>` rồi chuyển tiếp.
7. **Validate offline** — service verify chữ ký qua JWKS, check `iss` / `aud` / `exp` / `scope`.
   Không gọi Keycloak. Không Redis. Không client secret.
8. **Response** — trả ngược về client.
9. **Logout / revoke** — backchannel logout → gateway evict theo `sid` + ghi deny-list. Vẫn 4
   tầng vô hiệu hoá như approach A, nhưng chỉ còn **một nơi** phải evict.

### Ba shape response của introspection — chỗ dễ sai nhất

`IntrospectionResponseParser` xử lý cả ba, và cái quyết định là **có token nào được phép forward
hay không**:

| Shape | Content-Type | Forward được? |
|---|---|---|
| RFC 7662 JSON thuần | `application/json` | ❌ chỉ là metadata |
| Keycloak `Accept: application/jwt` | `application/json` + member `jwt` | ✅ chính là full access token |
| RFC 9701 chuẩn | `application/token-introspection+jwt` | ❌ `aud` = gateway ⇒ là *câu trả lời*, không phải credential |

Keycloak hỗ trợ shape 2 từ nhánh 25+ (merge 6/2024) nhưng **phải bật opt-in trên client**. Không
bật thì chạy gateway với `PHANTOM_INTERNAL_TOKEN=ORIGINAL`.

## So sánh nhanh

| | A · cache per-service | B · phantom token @ gateway |
|---|---|---|
| Nơi gọi introspect | Mọi service | Chỉ gateway |
| Số cache phải vận hành | N | 1 |
| Logout / revoke | Fan-out tới N nơi | Evict 1 chỗ |
| Service cần gì | `client_id` + `secret` | Chỉ JWKS public key |
| Token trong nội bộ | Opaque — phải hỏi mới biết là ai | JWT đã verify — đọc claims trực tiếp |
| Hợp lý khi | Không đổi được gateway, ít service | Mặc định khuyến nghị cho public-facing |

## Chạy thử

```bash
docker compose up -d                       # Redis + Keycloak 26.7
# setup realm/client theo ghi chú trong docker-compose.yml
mvn -q clean package
mvn -pl resource-service spring-boot:run   # cổng 8082
mvn -pl gateway spring-boot:run            # cổng 8080
```

```bash
# lấy token từ Keycloak rồi:
curl -H "Authorization: Bearer $AT" http://localhost:8080/api/orders/123
```

Lần đầu: cache miss, gateway gọi Keycloak. Các lần sau trong TTL: Redis trả thẳng. Xem bằng
`redis-cli MONITOR`. Thử `docker compose stop redis` — hệ thống vẫn chạy, chỉ chậm hơn. Thử stop
luôn Keycloak — circuit breaker mở và request bị từ chối nhanh, **không bao giờ được cho qua**.

## Test

```bash
mvn -q clean test
```

Toàn bộ là unit test (mock `StringRedisTemplate` / `JwtDecoder` / collaborators), chạy được mà
không cần Docker hay network. Đáng chú ý: `IntrospectionResponseParserTest` khoá đúng hành vi
"RFC 9701 response không được forward".

> **Lưu ý thật:** code trong repo được viết và review tay theo API của Spring Boot 3.3 /
> Spring Cloud 2023.0.x / Spring Security 6, nhưng **chưa từng được compile** — môi trường dựng
> nó không có network tới Maven Central. Việc đầu tiên khi mở repo: chạy `mvn -q clean test`.

## Phạm vi — nói thẳng trước khi bị hỏi

- **Keycloak Event Listener SPI provider** (jar chạy *bên trong* Keycloak) không nằm trong repo;
  ở đây chỉ có phía consumer. Nó là một module Maven riêng build với `keycloak-server-spi`.
- **Token exchange (RFC 8693)** chưa wire — hiện gateway forward một token cho mọi service. Đây
  là item số 1 trong backlog ở CLAUDE.md, và là câu interviewer hay hỏi: *"`aud` set thế nào để
  service A không dùng được token của service B?"*
- Keycloak **không phát opaque token** (vẫn là feature request mở). Muốn "opaque thật sự" ra
  ngoài thì dùng lightweight access token, hoặc BFF giữ token và phát cookie session.
- Shared secret của event webhook trong `application.yml` là giá trị dev — thay bằng mTLS/HMAC
  trước khi dùng thật.
