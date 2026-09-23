# CircuitBreaker + RateLimiter trong gateway — cấu hình và cách phối hợp

Ghi lại từ một phiên hỏi-đáp với Claude Code, giải thích cơ chế resilience4j bọc quanh mọi lời
gọi Keycloak từ gateway (approach B — phantom token, xem [CLAUDE.md](CLAUDE.md)). File tham chiếu
chính: `gateway/src/main/java/com/trieu/gateway/introspection/IntrospectionClient.java` và
`gateway/src/main/java/com/trieu/gateway/exchange/TokenExchangeClient.java` — hai class này dùng
cùng một pattern, chỉ khác tên breaker/limiter (`keycloakIntrospection` vs
`keycloakTokenExchange`) nên trạng thái của introspect và exchange độc lập với nhau.

## 1. Vai trò khác nhau, cùng nhắm 1 kịch bản

Cả hai đều đối phó với kịch bản: Redis chết → cache hết tác dụng → mọi request dồn thẳng vào
Keycloak.

- **CircuitBreaker** — theo dõi *tỷ lệ lỗi*. Khi Keycloak đang lỗi thật sự (sập, timeout hàng
  loạt), fail fast — ngừng gửi request mới, tránh giữ connection/thread chờ vô ích và tránh dội
  thêm tải vào một service đang gặp sự cố.
- **RateLimiter** — giới hạn *thông lượng tuyệt đối*, không quan tâm request có lỗi hay không.
  Kể cả khi Keycloak vẫn khoẻ (breaker CLOSED), gateway cũng không được phép dội quá mạnh — giới
  hạn chủ động, phòng khi traffic tăng đột biến hoặc cache bị bypass hàng loạt.

Cả hai đều **fail-closed** (đúng invariant #3 trong `CLAUDE.md`): bị chặn ở guard nào cũng biến
thành `IntrospectionUnavailableException` / `TokenExchangeUnavailableException`, và
`PhantomTokenFilter` (`:87,89`) `onErrorResume` bắt các exception này để **từ chối request** —
không có nhánh "cho qua" nào.

## 2. Thứ tự áp dụng thực tế trong reactive chain

```java
.timeout(Duration.ofSeconds(2))
.transformDeferred(RateLimiterOperator.of(rateLimiter))
.transformDeferred(CircuitBreakerOperator.of(circuitBreaker))
```

`transformDeferred` gọi sau sẽ **bọc ngoài** cái gọi trước, nên khi subscribe, thứ tự kiểm tra
thực tế là: **CircuitBreaker trước → RateLimiter sau → mới gọi HTTP thật** (bị timeout 2s bọc
trong cùng). Khi breaker đang OPEN, request bị chặn ngay mà không tốn cả rate-limit permit —
permit được dành lại cho lúc breaker đóng trở lại.

Lưu ý: mặc định resilience4j coi **mọi exception** ném ra từ call được bọc là 1 lần lỗi — bao gồm
cả `TimeoutException` từ `.timeout(Duration.ofSeconds(2))`. Keycloak không cần "sập hẳn" (trả
5xx) mới trích breaker — chỉ cần **chậm quá 2s liên tục** cũng bị tính là lỗi y hệt.

## 3. CircuitBreaker — cấu hình và ví dụ

```java
CircuitBreakerConfig.custom()
    .slidingWindowSize(20)
    .minimumNumberOfCalls(10)
    .failureRateThreshold(50)
    .waitDurationInOpenState(Duration.ofSeconds(5))
    .permittedNumberOfCallsInHalfOpenState(5)
    .build()
```

- **`slidingWindowSize(20)`** — breaker chỉ nhớ kết quả (thành công/thất bại) của **20 lần gọi
  Keycloak gần nhất**. Vì `slidingWindowType` không được set, resilience4j dùng mặc định
  `COUNT_BASED` — cửa sổ tính theo *số lượng call*, không phải theo thời gian.
- **`minimumNumberOfCalls(10)`** — dù cửa sổ rộng 20, breaker **không tính tỷ lệ lỗi** (và không
  bao giờ OPEN) cho tới khi đã có ít nhất 10 call ghi nhận. Chống nhiễu: vài request đầu lỗi
  ngẫu nhiên (network glitch thoáng qua) không đủ để kết luận Keycloak đang sập.
- **`failureRateThreshold(50)`** — khi đã đủ ≥10 call, breaker tính % lỗi trên các call hiện có
  (tối đa 20). Vượt 50% → OPEN ngay lập tức, không cần đợi đủ 20 call.

### Ví dụ

Keycloak bắt đầu quá tải, một số request timeout:

| Call # | Kết quả | Số call đã ghi nhận | Breaker |
|---|---|---|---|
| 1–9 | 5 lỗi / 4 thành công | 9 | vẫn **CLOSED** — dù tỷ lệ lỗi đã 55%, chưa đủ `minimumNumberOfCalls=10` nên chưa tính |
| 10 | lỗi | 10 | tỷ lệ = 6/10 = **60% > 50%** → breaker **OPEN** ngay tại call #10 |

Từ thời điểm OPEN:

1. Mọi request trong **5 giây** (`waitDurationInOpenState`) bị chặn tức thì bằng
   `CallNotPermittedException` — không gọi HTTP tới Keycloak nữa, không tốn thread/connection.
2. Sau 5s, breaker tự chuyển **HALF_OPEN**, cho phép đúng `permittedNumberOfCallsInHalfOpenState=5`
   request thăm dò đi thật tới Keycloak:
   - Tỷ lệ lỗi trong 5 call đó vẫn ≥50% (ví dụ 3/5 lỗi) → quay lại **OPEN**, đợi thêm 5s.
   - Tỷ lệ lỗi <50% (ví dụ 1/5 lỗi) → đóng lại **CLOSED**, cửa sổ 20-call reset, traffic bình
     thường trở lại.

Ý nghĩa: `minimumNumberOfCalls` + `failureRateThreshold` tạo ngưỡng "cần đủ bằng chứng mới ngắt";
`waitDurationInOpenState` + `permittedNumberOfCallsInHalfOpenState` tạo chu kỳ tự dò lại mỗi 5s
bằng một lượng traffic nhỏ, tránh vừa phục hồi đã bị dội lại toàn bộ traffic khiến Keycloak sập
lần nữa.

## 4. RateLimiter — cấu hình và ví dụ

```java
RateLimiterConfig.custom()
    .limitForPeriod(200)
    .limitRefreshPeriod(Duration.ofSeconds(1))
    .timeoutDuration(Duration.ofMillis(100))
    .build()
```

- **`limitRefreshPeriod(1s)`** — chia thời gian thành các chu kỳ cố định 1 giây (fixed window,
  không phải sliding). Mỗi chu kỳ mới, bộ đếm permit được nạp lại từ đầu.
- **`limitForPeriod(200)`** — mỗi chu kỳ 1s chỉ có **200 permit**. Request lấy được permit thì
  được gọi Keycloak ngay; hết permit trong chu kỳ hiện tại thì phải chờ.
- **`timeoutDuration(100ms)`** — nếu không có permit ngay, request được chờ (bất đồng bộ, không
  block thread — đúng bản chất reactive của `RateLimiterOperator`) tối đa 100ms để permit mới
  xuất hiện. Hết 100ms vẫn chưa có → ném `RequestNotPermitted` → map thành
  `IntrospectionUnavailableException` → request bị từ chối (fail-closed).

Khác biệt cốt lõi với CircuitBreaker: RateLimiter không quan tâm Keycloak lỗi hay không — kể cả
khi Keycloak khoẻ 100%, vượt 200 req/s vẫn bị chặn.

### Ví dụ

Chu kỳ đang chạy từ `t=0ms` đến `t=1000ms` (reset về 200 permit tại `t=1000ms`).

**Case A — burst đến sớm trong chu kỳ:**

| Request | Thời điểm đến | Permit còn lại | Kết quả |
|---|---|---|---|
| #1–#200 | t=0–50ms | ≥1 | lấy permit ngay, gọi Keycloak ngay lập tức |
| #201 | t=50ms | 0 | permit tiếp theo chỉ có ở t=1000ms → cần chờ 950ms, vượt xa `timeoutDuration=100ms` → sau 100ms chờ vô ích, ném `RequestNotPermitted` → bị từ chối |

Vì `timeoutDuration` (100ms) rất nhỏ so với `limitRefreshPeriod` (1000ms), một khi hết permit
sớm trong chu kỳ, phần lớn request dư thừa fail gần như ngay thay vì bị xếp hàng chờ chu kỳ sau.

**Case B — request đến sát biên chu kỳ:**

| Request | Thời điểm đến | Chờ đến khi nào | Kết quả |
|---|---|---|---|
| #201 | t=920ms | permit mới cấp tại t=1000ms, chỉ cần chờ 80ms | 80ms < 100ms timeout → lấy được permit, gọi Keycloak thành công (trễ ~80ms) |

Request nào tình cờ đến trong khoảng 100ms cuối của chu kỳ vẫn có cơ hội "bắt kịp" đợt permit
tiếp theo; request đến giữa/đầu chu kỳ khi permit đã cạn thì gần như chắc chắn bị từ chối.

### Lưu ý triển khai

Đây là fixed window đếm trong bộ nhớ của **một instance gateway** (resilience4j registry local,
không phải Redis-backed). Nếu scale gateway ra nhiều pod, mỗi pod có bộ đếm 200/s riêng, nên
tổng tải thực tế lên Keycloak là N × 200 req/s chứ không phải một giới hạn toàn cục dùng chung —
khớp với vai trò "chặn từng node dội quá mạnh" chứ không phải "giới hạn tổng traffic hệ thống".
