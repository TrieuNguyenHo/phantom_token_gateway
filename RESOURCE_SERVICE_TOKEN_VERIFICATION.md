# resource-service — verify token ở đâu, verify những gì

Ghi lại từ một phiên hỏi-đáp với Claude Code, giải thích cơ chế xác thực JWT phía
`resource-service` (approach B — phantom token, xem [CLAUDE.md](CLAUDE.md)). File tham chiếu
chính: `resource-service/src/main/java/com/trieu/resource/config/SecurityConfig.java`.

## 1. Verify ở đâu

Hoàn toàn **offline**, tại `SecurityConfig.java:40-65` — không gọi Keycloak, không dùng Redis,
không có client secret (đúng invariant #6 trong `CLAUDE.md`: downstream không được có dependency
vào Keycloak).

Cơ chế: Spring Security **OAuth2 Resource Server** (`oauth2ResourceServer().jwt(...)`), tự động
chạy trên mọi request tới endpoint được bảo vệ (`anyRequest().authenticated()`, trừ
`/actuator/health/**`).

## 2. Verify những gì

Qua `NimbusJwtDecoder` + validator chain (`SecurityConfig.java:42-53`):

1. **Signature** — `NimbusJwtDecoder.withJwkSetUri(jwksUri)`: fetch JWKS từ Keycloak, cache, tự
   rotate theo `kid` trong header token. Không network call mỗi request (xem mục 4).
2. **Issuer** (`iss`) + **expiry** (`exp`) — qua `JwtValidators.createDefaultWithIssuer(issuerUri)`,
   validator mặc định của Spring.
3. **Audience** (`aud`) — validator tự viết thêm (dòng 44-50): check `jwt.getAudience()` có chứa
   `security.expected-audience` không. Đây là phần chặn replay: thiếu check này thì token mint
   cho service A có thể bị dùng lại (replay) sang service B.

Hai validator được gộp bằng `DelegatingOAuth2TokenValidator` (dòng 51-52) — cả hai phải pass thì
token mới hợp lệ.

**Vì sao được phép self-verify offline** (khác approach A / gateway phải introspect mỗi lần):
real-time revocation check đã xảy ra ở gateway boundary rồi — gateway introspect với Keycloak,
cache kết quả. JWT/EXCHANGE gateway forward xuống là "đã được Keycloak xác nhận sống trong X giây
gần nhất", nên downstream chỉ cần verify chữ ký + claims offline qua JWKS, không cần hỏi lại
Keycloak.

## 3. Dòng `.oauth2ResourceServer(...)` để làm gì

```java
.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder)));
```

Gắn cơ chế xác thực JWT vào Spring Security filter chain: mọi request cần `authenticated()` sẽ
lấy `Authorization: Bearer <token>`, decode/verify bằng `jwtDecoder`, pass thì coi là đã login.

- `http.oauth2ResourceServer(...)` — bật module OAuth2 Resource Server (khác OAuth2 Client — dùng
  để login/redirect).
- `.jwt(...)` — chọn chiến lược **JWT** (so với `.opaqueToken(...)` mà `resource-server-cache`
  dùng ở approach A, gọi introspect endpoint). Nghĩa là "token tự chứa đủ thông tin để verify
  offline".
- `.decoder(jwtDecoder)` — dùng bean `jwtDecoder` custom (dòng 41-54) thay vì decoder mặc định
  của Spring, để có thêm check issuer + audience.

Runtime flow: request tới → Spring Security lấy Bearer token → `jwtDecoder.decode(token)` → qua
JWKS signature check + issuer + audience validator → pass thì build `JwtAuthenticationToken`, set
vào `SecurityContext`, đi tiếp tới `OrdersController`; fail thì trả `401` tự động, không tới
controller.

## 4. `kid` là gì, rotate theo `kid` nghĩa là sao

`kid` = **Key ID**, field trong JWT **header** (không phải payload), định danh cặp
public/private key nào đã ký token này.

```json
{ "alg": "RS256", "typ": "JWT", "kid": "a1b2c3d4-..." }
```

JWKS endpoint (`keycloak.jwks-uri`, thường
`/realms/{realm}/protocol/openid-connect/certs`) trả về **danh sách** public key, mỗi key có
`kid` riêng:

```json
{ "keys": [
  { "kid": "a1b2c3d4-...", "kty": "RSA", "n": "...", "e": "..." },
  { "kid": "e5f6g7h8-...", "kty": "RSA", "n": "...", "e": "..." }
]}
```

**Rotate theo `kid`:**

- Keycloak định kỳ tạo key mới để ký token, nhưng giữ lại key cũ trong JWKS một thời gian (để
  verify các token cũ đã phát hành, chưa hết hạn).
- Mỗi token mang `kid` của đúng key đã ký nó.
- `resource-service` đọc `kid` trong header → tìm đúng key khớp trong JWKS đã cache → verify
  signature bằng key đó. Không thử tất cả key, không giả định luôn dùng key mới nhất.
- Keycloak rotate key mới → `resource-service` không restart, không deploy lại (xem mục 5 — tự
  refetch khi gặp `kid` lạ).

Đây là lý do `resource-service` verify offline được mà vẫn an toàn khi Keycloak đổi key. Liên
quan trực tiếp tới backlog gap #2 trong `CLAUDE.md` ("JWKS rotation test in resource-service") —
cơ chế đã có sẵn từ Spring Security/Nimbus, nhưng chưa có test tự động verify.

## 5. Cache JWKS bao lâu, refresh khi nào

`jwtDecoder` (`NimbusJwtDecoder.withJwkSetUri(jwksUri).build()`) không tự viết cache — dùng cache
mặc định của thư viện Nimbus (`DefaultJWKSetCache`), vì code không truyền `Cache` custom vào
builder.

**Default cache của Nimbus:**

- **Lifespan = 15 phút** — sau 15 phút, JWK set trong cache bị coi là hết hạn hoàn toàn, lần
  decode tiếp theo bắt buộc fetch lại `jwks-uri`, bất kể `kid` khớp hay không.
- **Refresh time = 5 phút** — mốc "nên refresh sớm" (refresh-ahead): cache vẫn dùng được, nhưng
  hệ thống có thể trigger fetch nền để làm mới trước khi hết hạn hẳn, tránh mọi request đều bị
  block đúng lúc cache hết hạn.

**Refresh khi gặp `kid` lạ (quan trọng nhất cho rotation):**

- Token có `kid` **không có** trong JWK set đang cache (Keycloak vừa rotate) → Nimbus **fetch lại
  JWKS ngay lập tức**, không đợi hết 15 phút. Đây là hành vi mặc định khi **không** truyền `Cache`
  custom — đúng cấu hình hiện tại của project.
- Lưu ý: hành vi này từng có bug khi dùng **custom Cache**
  ([spring-security#11621](https://github.com/spring-projects/spring-security/issues/11621)) —
  không refetch đúng như kỳ vọng. Project này dùng cache mặc định nên không bị ảnh hưởng.

**Luồng thực tế:**

1. Request đầu tiên → chưa có cache → fetch JWKS, cache lại, verify.
2. Các request sau, `kid` khớp key đã cache → verify từ cache, không gọi network.
3. Keycloak rotate key → token mới mang `kid` mới → không tìm thấy trong cache → tự động refetch
   JWKS → cache lại → verify.
4. Không có key mới nào xuất hiện, sau 15 phút cache cũng tự hết hạn, fetch lại ở lần dùng tiếp
   theo.

### Nguồn tham khảo

- [DefaultJWKSetCache (Nimbus JOSE + JWT v9.21)](https://www.javadoc.io/static/com.nimbusds/nimbus-jose-jwt/9.21/com/nimbusds/jose/jwk/source/DefaultJWKSetCache.html)
- [RemoteJwkSet is not refreshed when encountering an unknown KID · Issue #11621 · spring-projects/spring-security](https://github.com/spring-projects/spring-security/issues/11621)
- [Enhanced JWK set retrieval · Docs (connect2id)](https://connect2id.com/products/nimbus-jose-jwt/examples/enhanced-jwk-retrieval)
