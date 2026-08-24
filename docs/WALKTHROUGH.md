# Finance Tracker v2: Design Walkthrough

This document explains **why this codebase is built the way it is**. It is written
to be read straight through, one layer at a time, and re-read later.

Every section follows the same shape:

> **The threat.** What actually goes wrong, described concretely.
> **The mechanism.** What the code does instead, with the real code.
> **The cost.** What the decision gave up. Every real choice costs something.

If a section only tells you the mechanism, it is not finished.

## How to use this alongside the drills

There are three pieces of material for this project and they do different jobs.

| | Purpose | When |
|---|---|---|
| **This document** | Read and understand. Continuous, linear, re-readable. | First pass, and any time a concept feels loose |
| **`Assessment Prep` drill module** | Recall under pressure. Chunked, graded, shuffled. | After reading, and repeatedly afterwards |
| **`demos/` scripts** | Watch it happen. Runnable, real output. | Alongside whichever section names them |

Read a layer here, run its demos, then drill it. The drills are deliberately bad
for reading end to end, which is why this document exists.

---

# Layer 1: The API Core

Layer 1 is the backend foundation: who a user is, how they stay signed in, and
what they are allowed to touch. Three sub-layers, built in order.

```
app/
  db.py                       one SQLite connection per request, the schema
  security/
    passwords.py              Argon2id hashing, verification, rehash-on-login
    tokens.py                 session and CSRF token generation and comparison
    auth.py                   cookie policy, current_user, login_required
    csrf.py                   the before_request CSRF gate
  repositories/
    users.py                  the only code that touches the users table
    sessions.py               server-side session storage
    accounts.py               accounts, ownership enforced in the query
    transactions.py           transactions, ownership one hop away
  routes/
    auth.py                   register, login, logout, me
    accounts.py               accounts and transactions endpoints
```

**One architectural decision underpins everything else:** all SQL lives in
`repositories/`. Nothing else in the application talks to the database. When a
reviewer asks "how do you know every query is parameterized?", the answer is not
"I was careful" but "there are about twenty queries and they are all in four
files."

---

## Layer 1A: Data and Credentials

### 1. Parameterized queries

**The threat.** Someone types `' OR '1'='1` into the email field on the login
form. If that string is concatenated into the SQL text, their leading quote
closes the developer's opening quote, `OR '1'='1` becomes live SQL that is true
for every row, and their trailing quote balances the statement so it parses
cleanly. `fetchone()` returns row one, and this query selects `password_hash`.
They now hold a real credential to crack offline, and they never guessed a
password.

The worst part is what does not happen: no error, no warning, no unusual log
line. From the application's side it looks like an ordinary successful lookup.
That silence is why injection survives in codebases for years.

**The mechanism.** The SQL is a fixed constant. The value travels separately.

```python
db.execute(
    "SELECT id, email, password_hash FROM users WHERE email = ?",
    (normalize_email(email),),
)
```

The driver sends the statement and the parameters over two different channels.
The database parses the statement first and then binds the value as data. It is
never re-read as syntax.

**The part people state backwards:** nothing is being escaped or sanitized. Every
quote in that payload survives byte for byte. They simply never get interpreted,
because the shape of the query was decided before the value arrived.

**Why not escaping?** Escaping is a blocklist. You have to enumerate every
dangerous construct correctly, forever, across every dialect. It also fails
entirely in numeric contexts where there are no quotes to escape, and it breaks
legitimate input: O'Brien and D'Angelo are real names.

**The cost.** None worth mentioning. This is the rare control that is free.

> Run `demos/sql_binding.py` to see both queries hit a live database with the
> same payload.

### 2. Argon2id for passwords

**The threat.** Your database is stolen. If passwords are stored in plaintext, it
is over. If they are stored under a fast hash, an attacker runs billions of
guesses per second on commodity hardware and most users fall anyway.

**The mechanism.** Argon2id, which is deliberately slow and, more importantly,
**memory-hard**.

v1 of this project used bcrypt at cost 10. That is not wrong and is still an
acceptable answer. The upgrade reason is memory: bcrypt is expensive in CPU time
but cheap in RAM, so an attacker can pack thousands of parallel bcrypt cores onto
one GPU. Argon2id forces every single guess to allocate a large block of memory,
and RAM is the one resource a GPU cannot cheaply multiply. Same wall-clock cost
for one honest login, far worse economics for an offline cracker.

The stored value is self-describing:

```
$argon2id$v=19$m=65536,t=3,p=4$7OXzGTsOnbaq...$zMk4Wl+1sZkP...
 |         |     |      |   |   |                |
 |         |     |      |   |   |                +-- the hash
 |         |     |      |   |   +------------------- random salt
 |         |     |      |   +----------------------- p=4  parallelism
 |         |     |      +--------------------------- t=3  iterations
 |         |     +---------------------------------- m=65536 KiB (64 MiB)
 |         +---------------------------------------- Argon2 version
 +-------------------------------------------------- the variant
```

Two consequences follow from that string:

**There is no salt column, and there does not need to be one.** The salt is in the
middle of the hash. It does not need to be secret. Its only job is to make two
users who both chose the same password produce different rows, so one precomputed
table cannot cover both.

**`needs_rehash()` is possible at all.** Because the parameters travel with the
hash, code written today can look at a hash written years ago, notice it used
weaker settings, and upgrade it during login. That is the one moment the
plaintext is legitimately in hand. No reset emails, no user action.

The ordering matters and there is a test for it: the rehash runs only **after** a
successful verification. If it ran before, anyone could overwrite any account's
credential by submitting a guess, and the upgrade path would become the attack.

**The cost.** 50 to 100 milliseconds and 64 MiB per login. Worth it.

> Run `demos/salt_demo.py` for a simulated breach: identical rows, a rainbow table
> cracking two accounts from one entry, then the same table going useless once
> salts are added.

### 3. The dummy hash

This is the most interesting branch in Layer 1 and the one almost nobody writes
deliberately.

**The threat.** The obvious way to write `verify_password` bails out early when
the user does not exist. That is functionally identical and it leaks. A real
account runs a full Argon2 verification, 50 to 100 milliseconds. A missing account
with an early return answers in under a millisecond. Both send the same status
code and the same "invalid email or password" body. The difference is in the
clock, and the clock is fully observable to whoever sent the request.

That is **account enumeration**. An attacker submits one junk password against a
million leaked addresses and times each response. Fast means no account, slow
means the account is real. It converts a generic credential-stuffing list into a
targeted one, which is the difference between an attack that gets rate-limited
into uselessness and one that works.

**The mechanism.** Do the same work on both paths.

```python
target = stored_hash if stored_hash is not None else _DUMMY_HASH
try:
    _hasher.verify(target, password)
except (VerifyMismatchError, VerificationError, InvalidHashError):
    return False
return stored_hash is not None
```

Pick a target, always do the work, decide afterwards. The final line is a guard: a
caller holding no hash must never receive `True`, even in the absurd event the
dummy password was guessed.

The same reasoning drives `create_user` returning `None` on a duplicate instead of
raising: the route can then answer identically whether or not the address was
taken, so the signup form is not an enumeration oracle either.

**The cost.** One wasted hash on a request that was always going to fail.

> Run `demos/verify_timing.py`. It measures both versions on your machine. The
> early-return version showed a **426,597x** timing difference while returning
> identical values.

### 4. Letting the database settle the race

**The threat.** The natural way to handle duplicate signups is to check first:

```python
if get_user_by_email(email) is not None:
    return None
db.execute("INSERT INTO users ...")
```

That is a time-of-check to time-of-use race. Two requests can both be inside the
gap:

```
Request A: SELECT ... -> nothing found, looks free
Request B: SELECT ... -> nothing found, looks free
Request A: INSERT     -> succeeds
Request B: INSERT     -> succeeds too
```

Two accounts on one address. Every downstream lookup that assumes uniqueness
silently picks whichever row comes first. Password reset becomes ambiguous. It
only appears under concurrency and never reproduces on your laptop.

**The mechanism.** A `UNIQUE` index on email, and catch the failure:

```python
try:
    cursor = db.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)", ...
    )
except sqlite3.IntegrityError:
    db.rollback()
    return None
```

The check and the write become one atomic operation inside the database. There is
no gap to race into. `IntegrityError` is not really an error here, it is the
database reporting that it already handled the conflict.

An application-level lock would not fix this, because it only covers one process.
The moment you run two workers it breaks. **Put the invariant where the data is,
not where the code is.**

**The cost.** Slightly less obvious code, and you have to know that catching the
error is deliberate rather than lazy.

### 5. Two smaller rules

**Select only what the caller needs.** `get_user_by_email` returns `password_hash`
because login needs it. `get_user_by_id` deliberately does not. Routes leak whole
objects: somebody writes `jsonify(dict(user))` at 5pm on a Friday and the hash is
in the API response. If the query never selected it, that mistake is structurally
impossible rather than dependent on every future author remembering.

**Normalize at exactly one chokepoint.** `normalize_email` is two method calls and
it is called inside both `create_user` and `get_user_by_email`, not at the route
layer. If registration stored the raw string and only login normalized,
`Milton@Example.com` would create an account that could never be logged into. The
user reports that their password stopped working, and you spend a day inside
hashing code that is working perfectly. **The symptom points at the wrong
subsystem**, which is why this is worth a rule rather than a habit.

### 6. Triaging a scanner finding

Ruff's bandit rules failed the build on a line in the test suite:

```
S105  Possible hardcoded password assigned to: "password_hash"
assert row["password_hash"] != "hunter2"
```

Four ways to make it go away, ranked worst to best:

1. **Rename the variable to dodge the matcher.** Worst. Hides the signal, changes
   nothing, and teaches the next person to lie to their tools.
2. **Delete the rule from the config.** Now real hardcoded credentials ship
   silently.
3. **A `# noqa` on the line.** Works, but every new test needs one.
4. **Scope the ignore to `tests/` in `pyproject.toml`.** What shipped.

The finding is a **true observation attached to a false conclusion**. In a test the
literal *is* the fixture: there is no secret because there is no system it unlocks.
The same line inside `app/` would be a genuine finding, and it still fails the
build there.

The sentence worth keeping: **"I suppressed it where the finding cannot be true,
and left it armed everywhere it can."**

---

## Layer 1B: Sessions and CSRF

### 7. Why the session lives on the server

**The threat.** Flask ships with a session for free. It is a signed cookie: the
data lives in the browser, signed with `SECRET_KEY` so the user cannot tamper with
it. Two properties follow, and the second is the problem.

Signed means tamper-proof. Signed does **not** mean secret; the payload is base64,
not encryption. And the server keeps no record that the cookie was ever issued.

If the server has no record, the server cannot revoke. Consider what you cannot
build: "log out everywhere", "my laptop was stolen", "this account is
compromised". Even ordinary logout becomes a polite request, because clearing the
cookie relies on the client discarding it and a copy taken beforehand still works.
The only lever is rotating `SECRET_KEY`, which signs out every user at once and
breaks everything else signed with it.

**The mechanism.** Sessions live in a table. The browser holds an opaque random
string that means nothing on its own.

The primary key is the **hash** of the token, never the token. A read-only leak of
that table yields digests, not cookies anyone can paste into a browser. Same
reasoning as never storing plaintext passwords, applied to the other thing that
grants access.

**The cost.** A database read on every authenticated request. For an app holding
someone's finances, revocability is worth it.

### 8. Two hashes, two reasons

Passwords get Argon2id with 64 MiB. Session tokens get plain SHA-256. Same
codebase, opposite choices, and it is deliberate.

**The reason is entropy.** A password is whatever a human picked, drawn from a
small and heavily skewed distribution. There is no way to make that set bigger, so
the only lever is making each guess expensive. A session token is 32 bytes from
the OS CSPRNG. There is no dictionary and no pattern; brute force is not slow, it
is arithmetically out of reach, and slowing each attempt down changes nothing.

There is also a cost asymmetry: a password is hashed **once per login**, a token
is verified on **every authenticated request**.

The token hash is also deliberately **unsalted**, and that is correct for two
reasons. Salt exists to defeat precomputation against repeated low-entropy inputs,
and random tokens never repeat. And sessions are looked up *by* hash, so a per-row
salt would turn an indexed primary-key lookup into a full table scan on every
request.

**The generalizable idea:** a control is not "stronger" in the abstract, it is
stronger against a specific threat. Argon2 counters offline guessing of
low-entropy secrets. Applied where there is no low-entropy secret, it is pure cost.

> Run `demos/session_lookup.py`.

### 9. The cookie flags

```python
response.set_cookie(
    SESSION_COOKIE, token,
    httponly=True, secure=secure, samesite="Lax", max_age=max_age, path="/",
)
```

Each flag stops a different thing:

- **HttpOnly.** JavaScript cannot read it. This does **not** fix an XSS bug; the
  attacker's script still acts as the user inside that page. What it stops is the
  token *leaving*, so it cannot be exfiltrated and replayed later from another
  machine. That is the difference between an incident and a breach.
- **Secure.** The browser refuses to send it over plain HTTP.
- **SameSite=Lax.** Not attached to cross-site POSTs. A layer, not the answer.
- **Max-Age.** Without it the cookie lives until the browser closes, which on a
  phone is approximately never.
- **Path=/.** And the logout cookie must match these attributes or some browsers
  keep the original, giving you a logout that silently does not.

The CSRF cookie is the deliberate exception: `httponly=False`, because the
frontend has to read it to echo it back. That is not an inconsistency, it is the
mechanism, and it is safe because that value is a challenge rather than a
credential. **HttpOnly belongs on anything that grants access, not on everything.**

`COOKIE_SECURE` defaults to on and the helper is written as `is not False`, so a
missing config key **fails closed**. Getting that backwards would ship plaintext
cookies and no test would fail.

### 10. CSRF

**The threat.** You are logged in here. Another site contains a form that POSTs to
our API. Your browser attaches your session cookie, because **cookies are attached
by destination, not by who asked**. The server sees a perfectly authenticated
request and does what it says.

Notice what does not help. The session cookie does not help, it is the thing being
abused. HttpOnly does not help, the attacker never needs to read it. Checking that
the user is authenticated does not help, they are.

**The mechanism.** Require something the cross-site page cannot *produce*. At
login we mint a CSRF token, store it on the server session, and hand a copy to the
browser in a readable cookie. Our frontend reads it and echoes it in
`X-CSRF-Token`. The attacker's page can cause the cookie to be **sent** but cannot
**read** it, because the same-origin policy stops another site reading our cookies
or responses.

**Why not rely on SameSite alone?** It is real and it kills the classic case, but:

- "Site" means registrable domain, so a compromised subdomain is same-site.
- Lax still sends the cookie on top-level GET navigation.
- Enforcement belongs to the visitor's browser, not to you. A control you cannot
  verify is a control you cannot rely on.

**The gate is a `before_request` hook, not a decorator**, and that is a security
decision. A decorator is opt-in, so protection depends on every future author
remembering it, and the endpoint someone forgets is the one that gets exploited. A
hook is opt-out: a new route is protected the day it exists, and skipping it
requires a visible edit to `EXEMPT_ENDPOINTS` that shows up in a diff. This is
**fail-safe defaults**: the secure path is what you get by doing nothing.

**Known gap, documented rather than hidden.** `auth.register` and `auth.login` are
exempt because no session exists yet to hold a token. That leaves login CSRF, where
an attacker forces you to log into *their* account so your activity lands in their
history. The standard fix is a pre-session token. It is written down in `csrf.py`
as a limitation.

### 11. Rotation on login

**The threat.** Session fixation is the mirror image of hijacking and gets
overlooked because of it. In hijacking the attacker steals a token you have. In
fixation the attacker **gives** you a token they already know, through a link, a
subdomain cookie, or an XSS, and then waits. Your own successful login is what
makes their token powerful.

**The mechanism.** Destroy whatever the caller arrived holding, then issue fresh.

**The general rule, which transfers to any system:** when a credential's privilege
level changes, the credential must change. Login is the obvious case. So is a
password change, an email change, and elevation to an admin role.

It kills only the **presented** token, not every session. Logging in on a phone
must not sign you out on a laptop, and there is a test for exactly that.

### 12. Two expiry clocks

```python
IDLE_TIMEOUT      = timedelta(hours=2)
ABSOLUTE_LIFETIME = timedelta(hours=12)
```

They answer different questions.

The **idle timeout** bounds the unattended session, and it is refreshable on
purpose so active users stay logged in. But refreshable is exactly the problem
once a token is stolen, because a thief will keep it warm. One request an hour
resets the clock forever, so idle timeout alone never expires for the one person
you most want it to expire for.

The **absolute lifetime** ends it regardless of activity. That is what bounds how
long a stolen token is useful.

Either alone leaves a hole. The check uses `>=` so a session sitting exactly on
its limit is expired; with `>` it survives its own expiry by an instant.

> Run `demos/session_clocks.py`. Eleven pings at ninety-minute intervals and the
> idle-only column never once goes False.

---

## Layer 1C: Authorization and Money

### 13. The bug v1 actually shipped

**The threat.** v1 of this project had, in effect:

```python
account = get_account(account_id)   # whatever number was in the URL
return jsonify(account)
```

Change the number, read somebody else's finances. That is an **Insecure Direct
Object Reference**. OWASP files it under Broken Access Control, which has been
number one on the Top 10 since 2021.

It holds that spot for a reason worth articulating: **it has no syntactic
signature.** Injection can be found by a scanner looking for string-built SQL.
Broken access control cannot, because the code is syntactically perfect, the query
is properly parameterized, and the only thing wrong is that the application does
not know who is supposed to own that row. That fact lives in your business rules,
not your syntax.

There is no exploit to write. You log in as yourself and change a seven to an
eight.

**The near-fix that is still wrong.** The instinct is to guard after the fetch:

```python
account = get_account(account_id)
if account["user_id"] != current_user_id:
    abort(403)
```

That is correct, and it is what most codebases contain. Its weakness is
structural: the safety lives in a line somebody had to remember to type, and the
unscoped function is still sitting there, callable. Every new endpoint is a fresh
chance to forget.

**The mechanism.** Ownership is not a check. It is a parameter.

```python
def get_account(user_id: int, account_id: int) -> sqlite3.Row | None:
    return get_db().execute(
        "SELECT id, name, kind, created_at FROM accounts"
        " WHERE id = ? AND user_id = ?",
        (account_id, user_id),
    ).fetchone()
```

A query for someone else's row does not return a row to check. It returns nothing.
**There is deliberately no `get_account(account_id)` overload**, because a function
that cannot be called without an owner cannot be called without an authorization
check.

**The cost.** Every repository function carries an extra parameter, and callers
must have a user in hand. That is the point.

> Run `demos/idor_demo.py`. It runs the v1 bug live, then compares three fixes.

### 14. Ownership one hop away

Transactions have no `user_id`. A transaction belongs to an account and the
account belongs to a user, so the ownership hop runs through the join.

```python
"SELECT t.id, t.account_id, t.amount_cents, ..."
" FROM transactions t"
" JOIN accounts a ON a.id = t.account_id"
" WHERE t.id = ? AND a.user_id = ?"
```

**The join is the authorization**, not a data-shaping convenience.

This is where access control actually breaks in real systems. The parent table
gets its clause because the column is right there. The child table gets forgotten,
because "you can only reach a transaction through its account anyway" is true
right up until somebody adds `GET /transactions/<id>`.

SQLite does not allow a JOIN inside DELETE, so the delete expresses the same rule
as a subquery on account ids. Same control, different syntax. **If you cannot
write the join, you find another way to say it. You do not drop the clause.**

Writes need this more than reads, not less. An unscoped SELECT leaks a record. An
unscoped DELETE destroys one, permanently, in a system of financial record.

### 15. 404, not 403

A resource that exists but is not yours returns **404**.

403 is semantically more correct and more debuggable. It also means "this exists
and you may not have it", which confirms the id is real and lets someone walk the
id space building a map of what other people have. For a finance app, the mere
existence of an account is information about a person.

It has to be the whole response, not just the status: a nonexistent id and someone
else's id return byte-identical bodies, and there is a test asserting it.

**The cost, stated plainly:** a legitimate user with a real permissions problem
sees a confusing 404, and support gets harder. For an internal admin tool the
better choice would probably be 403 with better error messages.

### 16. Money is an integer

`amount_cents` is an `INTEGER`, because binary floating point cannot represent 0.1
exactly:

```
>>> 0.1 + 0.2 == 0.3
False
>>> total = 0.0
>>> for _ in range(10): total += 0.1
>>> total == 1.0
False
```

That is IEEE 754, not a Python quirk; Java, JavaScript and C++ do the same. One
operation is invisible. A ledger runs thousands, and the drift surfaces as a
balance that disagrees with the sum of its own rows, which is a bug a customer
finds rather than a test.

Rounding is the trap answer. It hides the error at the point you look and does
nothing about it accumulating underneath.

The input validation is also stricter than it looks:

```python
if isinstance(amount, bool) or not isinstance(amount, int):
    return jsonify({"error": "amount_cents must be an integer"}), 400
```

**`bool` subclasses `int` in Python**, so `isinstance(True, int)` is `True` and a
JSON body sending `true` would book a one-cent transaction. The check *looks*
complete without that first clause, which is what makes it interesting.

**Validate at the boundary, do not mangle the data.** The route rejects malformed
input but stores well-formed text verbatim, including script tags. Sanitizing on
input destroys data and still does not make output safe, because the same value
may later be rendered into HTML, a CSV, and a JSON body, each needing different
escaping. **Escaping belongs to the renderer.**

---

## The testing lesson

While Layer 1B was being written, a test failed: after logout, the old token still
authenticated. The obvious conclusion was that revocation was broken.

**The obvious conclusion was wrong.** The application was correct; the fixture was
not. It held a Flask application context open for the whole test:

```python
with application.app_context():
    init_db()
    yield application          # held across every request in the test
```

Flask **reuses** an already-pushed application context rather than nesting a new
one. So every request in that test shared one context, which means they shared one
`g`, and `g` is where `current_user()` caches the resolved session. The request
after logout read a cached session that had already been deleted.

It was proven rather than guessed, with a five-line probe:

```
with an outer app context held:     request 1 g empty: True,  request 2: False
without one (what production does): request 1 g empty: True,  request 2: True
```

**The generalizable lesson:** a test harness that does not model production can
hide a working control, or pass a broken one. This time it hid a working one,
which is the lucky direction.

**The habit:** when a test disagrees with your mental model, the test is a
hypothesis too. Find out which one is lying before you change either.

---

## Design decisions ledger

| Decision | Alternative rejected | Why | What it cost |
|---|---|---|---|
| Parameterized queries | Escaping quotes | Blocklist vs structural; fails in numeric contexts; breaks O'Brien | Nothing |
| Argon2id | bcrypt cost 10 | Memory-hard, so GPUs cannot parallelize cheaply | ~100ms and 64 MiB per login |
| Dummy-hash verify | Early return on missing user | Closes the timing enumeration oracle | One wasted hash per failed login |
| UNIQUE index + catch | SELECT-then-INSERT | Removes the TOCTOU gap; survives multiple workers | Less obvious code |
| Server-side sessions | Flask signed cookie | Signed cookies cannot be revoked | A DB read per request |
| SHA-256 for tokens | Argon2 everywhere | 256 random bits cannot be guessed; cost would be per-request | None |
| CSRF as before_request | A `@csrf_required` decorator | Fail-safe defaults; opting out becomes visible | Exempt list must be maintained |
| Rotate token on login | Reuse the presented token | Closes session fixation | None |
| Two expiry clocks | Idle timeout only | Idle alone never expires for an active thief | Slightly more state |
| Ownership in WHERE | Check after fetch | No unscoped function exists to call by mistake | Extra parameter everywhere |
| 404 for not-yours | 403 Forbidden | 403 confirms the id exists, enabling enumeration | Debuggability, support burden |
| Integer cents | Float amounts | Floats drift and the error accumulates | Conversion at the display layer |
| S105 scoped to tests/ | Delete rule, or rename var | Suppressed where it cannot be true, armed where it can | Must stay scoped |

---

## Defend your code

The questions an interviewer would actually ask. If you can answer these out loud,
in your own words, you can walk anyone through this layer cold.

**Layer 1A**

1. Walk me through a signup request, every hop.
2. Your login query takes user input straight from the request. Why is that safe?
   Why is escaping not equivalent?
3. Why Argon2id and not bcrypt? Was bcrypt wrong?
4. Where is the salt? I do not see a salt column.
5. Security doubles the memory parameter next year. What happens to existing users?
6. You verify against a dummy hash for a user that does not exist. That is wasted
   work. Why is it there?
7. You catch IntegrityError instead of checking first. Why?
8. Your linter flagged a hardcoded password in your tests. What did you do?

**Layer 1B**

9. Flask gives you a session for free. Why did you build your own?
10. Why SHA-256 for tokens but Argon2 for passwords? Why is the token hash unsalted?
11. Walk me through the three flags on your session cookie.
12. One of your cookies is readable by JavaScript. Defend that.
13. Explain CSRF to a product manager. Then explain your defense.
14. You already set SameSite=Lax. Why is the token not redundant?
15. Why is CSRF a before_request hook and not a decorator?
16. Why does login destroy the token the caller arrived with?
17. Why two expiry clocks instead of one?
18. What are the known gaps in this design?

**Layer 1C**

19. What is IDOR, and where was it in your v1?
20. Why ownership in the WHERE clause instead of a check after the fetch?
21. Transactions have no user_id. How do you authorize them?
22. Why 404 instead of 403? What did you give up?
23. Why is money an integer?

**Process**

24. Tell me about a bug your own tests caught.

**Three rules for answering.** State the threat before the mechanism. Name the
trade-off, because every real decision cost something. Say what you do not know,
plainly.

---

## Status and what comes next

**Layer 1 is complete.** 112 tests passing, ruff clean, pip-audit clean, and a
four-job CI pipeline running lint-and-test, Semgrep SAST, pip-audit SCA, and
gitleaks secret scanning on every push.

**Layer 2, the React frontend on Vercel.** Brings XSS and output encoding, CORS, and
the CSRF token round trip from the client side.

**Layer 3, the AI insights chatbot.** Brings prompt injection, output handling, and
the interesting one for a finance app: not leaking one user's financial data into
another user's context.

Each layer extends this document and mints its own drills.
