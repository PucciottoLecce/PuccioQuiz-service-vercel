import { useState, useEffect, useRef, useCallback } from "react";
import { isAdminLoggedIn, clearAdminToken } from "./adminAuth.js";
import {
  RED, WHITE, BLACK, CREAM,
  STATUS_CONFIG,
  API_BASE, POLL_INTERVAL,
  formatNextSlot,
  apiGet, apiPost, apiPatch,
  inject,
  MENU_FALLBACK,
} from "./constants.js";
import AdminPanel, { PinScreen } from "./AdminPanel.jsx";
import {
  PucciottoLogo, ActiveOrderBanner, TrackingSearch,
} from "./shared.jsx"; // ✅ era "./CustomerApp.jsx"
import MenuPage from "./MenuPage.jsx";
import CartPage from "./CartPage.jsx";

// ─── APP ──────────────────────────────────────────────────────────────────────
export default function App() {

  // ── Routing ───────────────────────────────────────────────────────────────
  const [page, setPageRaw] = useState(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      if (params.get("token")) return "tracking";
      const savedPage  = sessionStorage.getItem("pucciotto_page");
      const savedOrder = sessionStorage.getItem("pucciotto_order");
      if (savedPage === "tracking" && savedOrder && savedOrder !== "null") return "tracking";
      if (savedPage === "admin" && isAdminLoggedIn()) return "admin";
      if (savedOrder && savedOrder !== "null") return "tracking";
      return "menu";
    } catch { return "menu"; }
  });
  const setPage = (val) => { setPageRaw(val); try { sessionStorage.setItem("pucciotto_page", val); } catch {} };

  // ── State ─────────────────────────────────────────────────────────────────
  const [cart, setCartRaw]           = useState(() => { try { return JSON.parse(localStorage.getItem("pucciotto_cart") || "[]"); } catch { return []; } });
  const [orderType, setOrderTypeRaw] = useState(() => localStorage.getItem("pucciotto_order_type") || "asporto");
  const [restaurantOnline, setRestaurantOnline] = useState(true);
  const [menuItems, setMenuItems]    = useState(MENU_FALLBACK);
  const [order, setOrderRaw]         = useState(() => { try { return JSON.parse(sessionStorage.getItem("pucciotto_order") || "null"); } catch { return null; } });
  const [payMethod, setPayMethod]    = useState("cash");
  const [customerInfo, setCustomerInfoRaw] = useState(() => {
    try { return JSON.parse(sessionStorage.getItem("pucciotto_customer") || "null") || { name: "", email: "", address: "", phone: "", notes: "" }; }
    catch { return { name: "", email: "", address: "", phone: "", notes: "" }; }
  });
  const [trackProgress, setTrackProgress]   = useState(0);
  const [checkoutLoading, setCheckoutLoading] = useState(false);
  const [checkoutError, setCheckoutError]   = useState("");
  const [gdprAccepted, setGdprAccepted]     = useState(false);
  const [adminAuthed, setAdminAuthedRaw]    = useState(() => { try { return isAdminLoggedIn(); } catch { return false; } });
  const [nextSlot, setNextSlot]             = useState(null);
  const [openingHours, setOpeningHours]     = useState(null);
  const [deliveryFee, setDeliveryFee]       = useState(2.50);
  const [minOrder, setMinOrder]             = useState(0);
  const [statusToast, setStatusToast]       = useState(null);
  const toastTimerRef = useRef(null);

  // ── Cookie banner ─────────────────────────────────────────────────────────
  const [cookieBanner, setCookieBanner] = useState(() => {
    try { return !localStorage.getItem("pucciotto_cookie_consent"); } catch { return false; }
  });
  const acceptCookies = () => { try { localStorage.setItem("pucciotto_cookie_consent", "1"); } catch {} setCookieBanner(false); };
  const rejectCookies = () => { try { localStorage.setItem("pucciotto_cookie_consent", "essential"); } catch {} setCookieBanner(false); };

  // ── Persistent wrappers ───────────────────────────────────────────────────
  const cartRef = useRef(cart);
  const setCart = (val) => {
    setCartRaw(prev => {
      const next = typeof val === "function" ? val(prev) : val;
      cartRef.current = next;
      try { localStorage.setItem("pucciotto_cart", JSON.stringify(next)); } catch {}
      return next;
    });
  };
  const setOrderType    = (val) => { setOrderTypeRaw(val); try { localStorage.setItem("pucciotto_order_type", val); } catch {}; };
  const setCustomerInfo = (val) => { setCustomerInfoRaw(prev => { const next = typeof val === "function" ? val(prev) : val; try { sessionStorage.setItem("pucciotto_customer", JSON.stringify(next)); } catch {} return next; }); };
  const setOrder        = (val) => { setOrderRaw(prev => { const next = typeof val === "function" ? val(prev) : val; try { if (next) sessionStorage.setItem("pucciotto_order", JSON.stringify(next)); else sessionStorage.removeItem("pucciotto_order"); } catch {} return next; }); };
  const setAdminAuthed  = (val) => { setAdminAuthedRaw(val); if (!val) { clearAdminToken(); try { sessionStorage.removeItem("pucciotto_admin"); } catch {} } else { try { sessionStorage.setItem("pucciotto_admin", "1"); } catch {} } };
  const clearPersisted  = () => { try { localStorage.removeItem("pucciotto_cart"); localStorage.removeItem("pucciotto_order_type"); sessionStorage.removeItem("pucciotto_customer"); sessionStorage.removeItem("pucciotto_page"); } catch {} };

  // ── Initial load ──────────────────────────────────────────────────────────
  useEffect(() => {
    // Registra Service Worker per notifiche push anche a tab chiusa
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register("/sw.js").catch(() => {});
    }
    apiGet("/api/menu").then(d => { if (d && typeof d === "object") setMenuItems(prev => ({ ...prev, ...d })); }).catch(() => {});
    apiGet("/api/settings").then(d => {
      if (typeof d.is_online === "boolean") setRestaurantOnline(d.is_online);
      if (d.opening_hours) setOpeningHours(d.opening_hours);
      if (d.delivery_fee != null) setDeliveryFee(Number(d.delivery_fee));
      if (d.min_order != null) setMinOrder(Number(d.min_order));
    }).catch(() => {});
    apiGet("/api/settings/next-slot").then(d => { setNextSlot(d.available_now ? null : (d.next_slot || null)); }).catch(() => {});
  }, []);

  // ── Order polling ─────────────────────────────────────────────────────────
  const prevStatusRef   = useRef(null);
  const pollingTokenRef = useRef(null);
  const pollingTimerRef = useRef(null);
  const setOrderLive    = useCallback((live) => {
    setOrderRaw(prev => {
      if (!prev) return prev;
      const next = { ...prev, ...live, items: (live.items && live.items.length) ? live.items : (prev.items || []) };
      try { sessionStorage.setItem("pucciotto_order", JSON.stringify(next)); } catch {}
      return next;
    });
  }, []);

  useEffect(() => {
    const token = order?.token;
    if (!token) { if (pollingTimerRef.current) { clearInterval(pollingTimerRef.current); pollingTimerRef.current = null; } pollingTokenRef.current = null; return; }
    if (pollingTokenRef.current !== token) {
      if (pollingTimerRef.current) { clearInterval(pollingTimerRef.current); pollingTimerRef.current = null; }
      pollingTokenRef.current = token;
      const sessionKey = `pucciotto_ns_${token}`;
      const saved = (() => { try { return sessionStorage.getItem(sessionKey); } catch { return null; } })();
      prevStatusRef.current = saved || null;
    }
    const sessionKey = `pucciotto_ns_${token}`;
    const fetchLive = () => {
      apiGet(`/api/orders/${token}`).then(live => {
        if (!live?.token) return;
        const prevStatus = prevStatusRef.current;
        const newStatus  = live.status;
        setOrderLive(live);
        if (prevStatus === null) { prevStatusRef.current = newStatus; try { sessionStorage.setItem(sessionKey, newStatus); } catch {} return; }
        if (prevStatus === newStatus) return;
        prevStatusRef.current = newStatus;
        try { sessionStorage.setItem(sessionKey, newStatus); } catch {}
        const cfg = STATUS_CONFIG[newStatus];
        const messages = {
          preparing:    "Il tuo ordine è in preparazione! 👨‍🍳",
          almost_ready: "Ancora poco! Il tuo ordine è quasi pronto ⏳",
          ready:        live.order_type === "domicilio" ? "Il tuo ordine è partito! Il corriere è in arrivo 🛵" : "Il tuo ordine è pronto! Vieni a ritirarlo 🎉",
          delivered:    "Ordine consegnato. Buon appetito! 🥙",
          cancelled:    "Il tuo ordine è stato annullato ❌",
        };
        const body = messages[newStatus];
        if (!cfg || !body) return;
        if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
        setStatusToast({ label: cfg.label, emoji: cfg.emoji, color: cfg.color, body });
        toastTimerRef.current = setTimeout(() => setStatusToast(null), 5500);
        const opts = { body, icon: "/favicon.ico", badge: "/favicon.ico", tag: `pucciotto-order-${token}`, renotify: true };
        const sendPush = () => {
          if (navigator.serviceWorker?.controller) {
            navigator.serviceWorker.ready.then(reg => reg.showNotification(`Pucciotto · ${cfg.label}`, opts)).catch(() => { try { new Notification(`Pucciotto · ${cfg.label}`, opts); } catch {} });
          } else { try { new Notification(`Pucciotto · ${cfg.label}`, opts); } catch {} }
        };
        if (typeof Notification !== "undefined") {
          if (Notification.permission === "granted") sendPush();
          else if (Notification.permission === "default") Notification.requestPermission().then(p => { if (p === "granted") sendPush(); }).catch(() => {});
        }
      }).catch(() => {});
    };
    fetchLive();
    pollingTimerRef.current = setInterval(fetchLive, POLL_INTERVAL);
    return () => {
      if (pollingTimerRef.current) { clearInterval(pollingTimerRef.current); pollingTimerRef.current = null; }
    };
  }, [order?.token, setOrderLive]);

  useEffect(() => {
    if (page === "tracking" && order) {
      const statusToProgress = { received: 8, preparing: 35, almost_ready: 70, ready: 100, delivered: 100, cancelled: 0 };
      setTrackProgress(statusToProgress[order.status] ?? 8);
    }
  }, [page, order?.token, order?.status]); // eslint-disable-line

  // ── Cart helpers ──────────────────────────────────────────────────────────
  const isValidEmail   = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test((e || "").trim());
  const isValidPhone   = (p) => /^[\+]?[\d\s\-\(\)]{7,15}$/.test((p || "").trim());
  const isValidAddress = (a) => (a || "").trim().length >= 8;

  const addToCart      = (item) => setCart(p => { const ex = p.find(c => c.id === item.id); return ex ? p.map(c => c.id === item.id ? { ...c, qty: c.qty + 1 } : c) : [...p, { ...item, qty: 1 }]; });
  const removeFromCart = (id) => setCart(p => p.filter(c => c.id !== id));
  const updateQty      = (id, d) => setCart(p => p.map(c => c.id === id ? { ...c, qty: Math.max(1, c.qty + d) } : c));

  const cartTotal      = cart.reduce((s, c) => s + c.price * c.qty, 0);
  const deliveryCost   = orderType === "domicilio" ? deliveryFee : 0;
  const cartTotalFinal = cartTotal + deliveryCost;
  const cartCount      = cart.reduce((s, c) => s + c.qty, 0);
  const minOrderNotMet = orderType === 'domicilio' && minOrder > 0 && cartTotal < minOrder;
  const canProceed     = customerInfo.name.trim().length >= 2
    && isValidEmail(customerInfo.email)
    && (orderType !== "domicilio" || (isValidAddress(customerInfo.address) && isValidPhone(customerInfo.phone)))
    && gdprAccepted;

  const submitOrder = async (method, paypalOrderId = null) => {
    setCheckoutLoading(true); setCheckoutError("");
    try {
      const data = await apiPost("/api/orders", {
        order_type: orderType,
        customer_name: customerInfo.name,
        customer_email: customerInfo.email,
        customer_phone: customerInfo.phone || undefined,
        delivery_address: orderType === "domicilio" ? customerInfo.address : undefined,
        pay_method: method,
        notes: customerInfo.notes || undefined,
        paypal_order_id: paypalOrderId || undefined,
        items: cart.map(i => ({ id: i.id, name: i.name, price: i.price, qty: i.qty })),
      });
      const newOrder = { ...data, items: [...cart], delivery_fee: orderType === "domicilio" ? deliveryFee : 0 };
      setOrder(newOrder);
      // Registra subscription push con order_id per ricevere notifiche solo su questo ordine
      (async () => {
        try {
          if (!("serviceWorker" in navigator) || !("PushManager" in window)) return;
          let perm = Notification.permission;
          if (perm === "default") perm = await Notification.requestPermission();
          if (perm !== "granted") return;
          const vRes = await fetch(`${API_BASE}/api/push/vapid-public-key`);
          if (!vRes.ok) return;
          const { publicKey } = await vRes.json();
          const reg = await navigator.serviceWorker.ready;
          const existing = await reg.pushManager.getSubscription();
          const sub = existing || await reg.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: publicKey,
          });
          await fetch(`${API_BASE}/api/push/subscribe`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ...sub.toJSON(), role: "customer", order_id: newOrder.id, customer_email: customerInfo.email || null }),
          });
        } catch { /* silenzioso */ }
      })();
      setCart([]); clearPersisted(); setPage("tracking");
    } catch { setCheckoutError("Errore nell'invio dell'ordine. Riprova o contattaci."); }
    finally { setCheckoutLoading(false); }
  };

  const toggleRestaurant = async () => { const v = !restaurantOnline; try { await apiPatch("/api/settings/online", { is_online: v }); } catch {} setRestaurantOnline(v); };

  // ── Styles (nav + shared shell) ───────────────────────────────────────────
  const showBanner = order && !["delivered", "cancelled"].includes(order.status) && page !== "tracking";
  const S = {
    wrap:    { minHeight: "100vh", background: CREAM },
    nav:     { background: WHITE, borderBottom: "1px solid #e8e4e0", position: "sticky", top: 0, zIndex: 100, padding: "0 16px" },
    navInner:{ maxWidth: 900, margin: "0 auto", display: "flex", alignItems: "center", justifyContent: "space-between", height: 56, position: "relative" },
    navSocial:{ position: "absolute", left: "50%", transform: "translateX(-50%)", display: "flex", alignItems: "center", gap: 16 },
    logo:    { fontFamily: "Lobster,cursive", fontSize: 22, color: RED, cursor: "pointer" },
    navR:    { display: "flex", alignItems: "center", gap: 12 },
    navBtn:  { border: "none", background: "none", cursor: "pointer", fontSize: 14, color: BLACK, fontFamily: "DM Sans,sans-serif", padding: "6px 12px", borderRadius: 6 },
    cartBtn: { background: RED, color: WHITE, border: "none", borderRadius: 8, padding: "8px 16px", cursor: "pointer", fontFamily: "DM Sans,sans-serif", fontWeight: 600, fontSize: 14, display: "flex", alignItems: "center", gap: 8 },
    adminBtn:{ background: "transparent", color: "#bbb", border: "1px solid #e0dbd5", borderRadius: 8, padding: "7px 13px", cursor: "pointer", fontFamily: "DM Sans,sans-serif", fontSize: 12 },
    // Tracking page
    main:    { maxWidth: 900, margin: "0 auto", padding: "24px 20px", paddingBottom: showBanner ? 90 : 24 },
    trackPage:{ maxWidth: 560, margin: "0 auto" },
    tokBox:  { background: BLACK, color: WHITE, borderRadius: 14, padding: 24, textAlign: "center", marginBottom: 24 },
    tokLbl:  { fontSize: 12, opacity: .5, letterSpacing: 2, textTransform: "uppercase", marginBottom: 8 },
    tokCode: { fontFamily: "Lobster,cursive", fontSize: 36, color: RED, letterSpacing: 4 },
    tokSub:  { fontSize: 12, opacity: .5, marginTop: 8 },
    progWrap:{ background: WHITE, border: "1px solid #e8e4e0", borderRadius: 14, padding: 24, marginBottom: 20 },
    progBar: { height: 6, background: "#f0ece8", borderRadius: 3, overflow: "hidden", marginBottom: 16 },
    progFill:(p) => ({ height: "100%", width: `${p}%`, background: RED, borderRadius: 3, transition: "width .8s linear" }),
    steps:   { display: "flex", justifyContent: "space-between", gap: 2 },
    step:    (d) => ({ textAlign: "center", flex: 1, fontSize: "clamp(9px, 2.5vw, 11px)", color: d ? RED : "#ccc", fontWeight: d ? 600 : 400, minWidth: 0 }),
    recBox:  { background: WHITE, border: "1px solid #e8e4e0", borderRadius: 14, padding: 20 },
    recRow:  { display: "flex", justifyContent: "space-between", fontSize: 13, paddingBottom: 8, marginBottom: 8, borderBottom: "1px solid #f0ece8" },
  };

  // ── ADMIN ─────────────────────────────────────────────────────────────────
  if (page === "admin") {
    if (!adminAuthed) return <PinScreen apiBase={API_BASE} onSuccess={() => setAdminAuthed(true)} />;
    return <AdminPanel
      menuItems={menuItems} setMenuItems={setMenuItems}
      restaurantOnline={restaurantOnline} toggleRestaurant={toggleRestaurant}
      openingHours={openingHours} nextSlot={nextSlot} formatNextSlot={formatNextSlot}
      deliveryFee={deliveryFee} setDeliveryFee={setDeliveryFee}
      minOrder={minOrder} setMinOrder={setMinOrder}
      apiBase={API_BASE}
      onExit={() => { setPage("menu"); setAdminAuthed(false); clearAdminToken(); try { sessionStorage.removeItem("pucciotto_admin"); sessionStorage.removeItem("pucciotto_page"); } catch {} }}
    />;
  }

  // ── CLIENT SHELL ──────────────────────────────────────────────────────────
  return (
    <div style={S.wrap}>
      <style>{inject}</style>

      {/* Cookie banner GDPR */}
      {cookieBanner && (
        <div style={{ position: "fixed", bottom: 0, left: 0, right: 0, background: "#1a1a1a", color: "#f0ece8", padding: "16px 20px", zIndex: 9999, display: "flex", flexWrap: "wrap", gap: 12, alignItems: "center", boxShadow: "0 -4px 20px rgba(0,0,0,.3)", borderTop: "3px solid #c0392b" }}>
          <div style={{ flex: 1, minWidth: 200, fontSize: 13, lineHeight: 1.5 }}>
            🍪 Usiamo <strong>solo cookie tecnici essenziali</strong> per il funzionamento del sito (sessione, carrello, tracking ordine).{" "}
            <a href="/GDPR.html#cookie" target="_blank" rel="noopener" style={{ color: "#e8a090" }}>Dettagli →</a>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button onClick={rejectCookies} style={{ background: "transparent", color: "#aaa", border: "1px solid #444", borderRadius: 8, padding: "9px 16px", fontFamily: "DM Sans,sans-serif", fontSize: 13, cursor: "pointer" }}>Solo essenziali</button>
            <button onClick={acceptCookies} style={{ background: "#c0392b", color: "#fff", border: "none", borderRadius: 8, padding: "9px 16px", fontFamily: "DM Sans,sans-serif", fontWeight: 700, fontSize: 13, cursor: "pointer" }}>Accetta e continua</button>
          </div>
        </div>
      )}

      {showBanner && <ActiveOrderBanner order={order} onGoToTracking={() => setPage("tracking")} />}

      {/* Status toast */}
      {statusToast && (
        <div style={{ position: "fixed", top: 16, left: 16, right: 16, maxWidth: 420, margin: "0 auto", zIndex: 9999, background: WHITE, borderRadius: 14, boxShadow: "0 8px 32px rgba(0,0,0,.18), 0 2px 8px rgba(0,0,0,.10)", border: `2px solid ${statusToast.color}`, padding: "14px 18px", display: "flex", alignItems: "center", gap: 14, animation: "slideDown .3s cubic-bezier(.22,.68,0,1.2) both", cursor: "pointer" }} onClick={() => setStatusToast(null)}>
          <span style={{ fontSize: 28, flexShrink: 0 }}>{statusToast.emoji}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontWeight: 700, fontSize: 13, color: statusToast.color, marginBottom: 2 }}>{statusToast.label}</div>
            <div style={{ fontSize: 13, color: BLACK, lineHeight: 1.4 }}>{statusToast.body}</div>
          </div>
          <span style={{ fontSize: 18, color: "#ccc", flexShrink: 0 }}>✕</span>
        </div>
      )}

      {/* Nav */}
      <nav style={S.nav}>
        <div style={S.navInner}>
          <span style={{ ...S.logo, display: "flex", alignItems: "center", cursor: "pointer" }} onClick={() => setPage("menu")}>
            <svg width="120" height="40" viewBox="223 530 908 300" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M385.467 556.066C384.933 556.466 380.133 557.399 374.8 558.066C369.333 558.866 362 559.932 358.267 560.599C354.667 561.266 348 562.466 343.6 563.132C328.933 565.666 304.4 573.932 287.6 582.066C250.667 599.932 233.6 619.399 254.667 619.399C260 619.399 278.933 613.666 305.6 603.932C311.067 601.932 318 599.799 320.933 599.132C323.867 598.466 328.4 597.399 330.933 596.866C333.467 596.199 338.933 594.999 342.933 594.066C346.933 593.132 352.667 591.932 355.6 591.266C367.867 588.332 378.133 587.132 397.6 586.332C424.667 584.999 465.467 587.266 478.933 590.732C480.8 591.132 484.933 592.199 488.267 592.866C512.8 598.332 525.6 603.799 537.333 613.666C545.467 620.732 548.267 626.332 548.267 636.332C548.267 657.266 524 677.132 482.933 689.799C470.667 693.532 449.467 699.266 442.267 700.599C437.867 701.532 431.867 702.732 428.8 703.399C425.733 704.066 419.333 704.999 414.4 705.532L405.333 706.466L406.4 695.266C406.8 689.132 407.867 682.732 408.4 680.999C409.067 679.266 409.6 670.866 409.6 662.332C409.467 640.466 405.867 632.999 393.867 630.599C383.2 628.466 378.933 641.132 375.6 683.932C374 702.866 373.067 709.799 371.467 711.532C370.133 712.999 366.667 714.066 361.867 714.466C357.733 714.866 349.2 715.799 342.933 716.599C336.667 717.266 325.6 718.599 318.267 719.399C265.867 725.532 254.267 727.799 249.733 733.132C248.4 734.866 248.667 735.532 251.467 737.399C258.533 742.066 286.4 741.266 359.333 734.199C369.2 733.266 369.867 733.399 370.933 735.932C371.467 737.532 372.267 750.466 372.667 764.732C373.333 784.332 374.133 793.266 376.133 801.132C379.6 814.332 380.933 816.732 384.933 816.732C392.4 816.732 397.867 794.466 401.733 748.732C402.533 738.866 403.733 729.932 404.533 728.999C405.333 728.199 407.733 727.399 410 727.399C412.267 727.399 417.733 726.732 422.133 725.932C426.667 725.132 433.333 723.932 436.933 723.399C451.333 720.732 481.467 713.666 490.8 710.599C496.133 708.866 501.467 707.399 502.533 707.399C504.267 707.399 510.267 704.866 526.933 696.999C541.867 689.932 561.6 673.932 568.667 662.866C573.6 655.399 576.267 644.732 576.267 632.866C576.267 622.999 575.733 620.332 572.4 613.132C566.267 600.332 555.467 590.599 536.533 580.999C528 576.599 518 572.199 514.267 570.999C500.133 566.732 488.8 563.666 484.267 562.732C475.333 560.999 463.467 559.132 453.6 557.932C441.733 556.332 386.667 554.866 385.467 556.066Z" fill="#c0392b"/>
              <path d="M952.4 642.199C947.867 643.932 946.133 646.866 944.267 655.399C943.333 659.399 942 663.532 941.333 664.332C940.533 665.266 937.067 666.066 933.467 666.066C924.8 666.066 919.333 671.132 922.667 676.199C924.4 678.732 929.333 680.732 934 680.732C941.6 680.732 941.867 681.666 940.133 707.532C938.4 732.999 939.2 761.666 941.733 772.066C947.467 795.532 961.067 800.466 978.667 785.399C981.733 782.599 985.867 777.532 987.733 773.932C989.467 770.332 991.733 767.399 992.667 767.399C993.6 767.399 995.2 770.466 996.133 774.199C1001.73 795.932 1016.8 800.199 1032.93 784.599C1036.67 780.999 1041.6 774.199 1044.13 769.399C1046.67 764.599 1049.07 760.732 1049.6 760.732C1050 760.732 1052.53 762.866 1055.07 765.532C1062.8 773.532 1067.47 775.799 1078.13 776.199C1092.27 776.866 1096.8 775.132 1106.27 765.532C1116.8 754.999 1120.27 746.332 1120.27 730.999C1120.27 717.132 1116.4 705.532 1109.2 697.132C1101.6 688.599 1095.73 686.066 1083.87 686.066C1075.47 686.066 1073.33 686.599 1068.13 689.799C1058.27 696.066 1053.2 704.332 1044.93 727.799C1040.93 739.266 1028 764.866 1024.93 767.399C1023.87 768.199 1022.53 768.599 1021.73 768.199C1019.33 766.732 1018.8 748.199 1020.13 720.732C1022.27 679.399 1022.27 679.399 1033.87 679.399C1040.8 679.399 1045.6 676.199 1045.6 671.532C1045.6 668.199 1044 667.132 1034.27 664.732L1026.27 662.599L1025.6 655.266C1025.2 651.132 1024.13 646.866 1023.2 645.799C1018.27 639.799 1006 639.932 1001.33 646.066C1000 647.932 998.533 652.599 998 656.466C997.067 664.999 995.333 666.599 988.267 665.532C985.333 665.132 980.533 664.332 977.6 663.932L972.267 663.132V656.466C972.267 648.199 970.533 644.999 964.933 642.599C959.733 640.466 956.933 640.332 952.4 642.199ZM994.133 681.799C996 682.866 994 717.799 991.6 726.066C987.733 738.999 972.667 767.799 969.2 768.466C966.933 768.866 965.867 765.532 964.8 754.466C963.867 744.466 967.867 685.399 969.733 681.932C971.067 679.399 971.867 679.266 982 680.066C988 680.599 993.467 681.399 994.133 681.799ZM1087.6 702.066C1088.67 702.066 1090.8 705.532 1092.4 709.666C1096.27 719.532 1096.8 744.999 1093.33 752.999C1089.07 762.599 1080.53 760.199 1075.73 747.932C1069.2 731.132 1075.07 698.199 1084 701.399C1085.07 701.799 1086.67 702.066 1087.6 702.066Z" fill="#c0392b"/>
              <path d="M820 647.266C808.4 649.666 799.067 660.066 801.067 668.466C803.067 676.732 810.4 680.732 823.6 680.732C837.733 680.732 852.267 671.666 852.267 662.999C852.267 657.932 849.2 652.332 844.8 649.399C840.667 646.732 827.733 645.666 820 647.266Z" fill="#c0392b"/>
              <path d="M685.6 682.999C683.067 683.399 678.933 685.132 676.4 686.999C670.267 691.666 661.067 706.466 658.4 716.066C652 738.332 650.533 742.466 645.067 754.066C640.267 763.799 638.133 766.599 635.867 765.666C632 764.199 631.6 738.732 635.067 717.932C636.667 708.199 635.2 704.066 628.8 701.399C622.933 698.999 614.933 698.732 612 700.999C610.8 701.932 608.267 708.066 606.267 714.732C601.6 730.999 591.067 760.732 588.8 764.332C587.733 766.066 586 767.399 584.8 767.399C583.2 767.399 582.933 765.266 583.733 752.999C584.133 745.132 584.8 737.799 585.2 736.732C585.6 735.666 586.4 729.266 586.933 722.732C587.6 716.066 588.4 707.666 588.933 703.799C590.4 693.932 589.2 690.466 583.867 688.999C575.067 686.599 566.133 689.266 562.4 695.532C559.867 699.799 557.333 728.866 557.067 757.399C556.933 771.932 557.2 773.932 560.267 780.066C562.8 785.132 564.933 787.399 569.867 789.799C579.067 794.599 585.2 793.132 592.267 784.732C595.333 781.132 599.067 774.732 600.8 770.466C604.4 761.666 606.267 760.332 607.333 765.666C608.4 770.866 615.467 780.332 620.667 783.399C626.667 787.132 636 786.866 641.6 782.999C644 781.399 647.867 777.266 650.133 773.799C652.4 770.332 654.933 767.532 655.6 767.532C656.4 767.532 658.8 770.199 660.933 773.399C666 781.132 672.4 785.399 681.6 787.399C695.067 790.199 711.333 783.399 722.667 770.066C725.867 766.466 729.067 763.399 730 763.399C730.933 763.399 732.667 765.799 734.133 768.599C740.933 782.866 754.933 790.466 769.467 787.799C781.467 785.532 788.667 781.399 798.267 771.266C807.2 761.666 809.6 760.332 809.6 764.599C809.6 766.066 810.267 767.666 810.933 768.066C811.733 768.466 812.267 769.932 812.267 770.999C812.267 774.199 817.6 781.532 821.733 783.932C823.733 785.132 827.867 786.066 830.8 786.066C840.933 786.066 848.533 780.199 855.333 767.399C856.8 764.866 858.267 762.332 858.8 761.799C859.333 761.266 863.333 764.066 867.867 767.932C875.733 774.732 876.533 775.132 885.467 776.066C902.933 777.799 913.867 772.466 923.6 757.532C936.267 738.199 931.6 705.132 914.4 692.332C907.6 687.399 903.333 686.066 893.2 686.066C884.133 686.066 883.2 686.332 877.067 691.132C868.4 697.666 862.4 706.732 858.8 718.466C850.8 744.599 842.8 763.932 839.333 765.266C834.8 766.999 833.6 763.666 833.6 748.866C833.6 741.132 834.267 730.866 834.933 726.066C838.133 705.532 838.133 704.199 834.667 700.199C831.867 696.866 830.4 696.466 823.733 696.199C816.667 696.066 815.733 696.332 812.8 700.066C810.133 703.399 809.6 705.532 809.6 712.999C809.6 724.466 805.6 734.332 794.4 751.132C787.733 761.132 778.533 769.399 772.533 770.999C767.6 772.199 762.667 769.932 759.333 764.866C756.8 761.132 756.267 758.599 756.267 750.199C756.267 744.599 757.2 735.799 758.4 730.732C759.467 725.532 760.933 719.266 761.467 716.732C762.933 710.199 766.133 702.999 768.533 700.999C772.933 697.399 773.467 701.799 771.333 720.466C770.267 730.199 769.733 738.999 770.133 740.066C771.067 742.466 778.4 742.599 782.4 740.332C784 739.399 786.8 736.866 788.8 734.599C792 730.732 792.267 729.399 792.267 718.332C792.267 707.932 791.733 705.132 788.4 697.666C783.333 686.199 778.8 683.399 765.867 683.399H756.4L750 689.932C744 696.066 739.6 703.799 734.267 718.066C729.6 730.732 720.133 748.866 714.4 756.332C708.4 764.332 698 771.399 692.533 771.399C691.067 771.399 688 769.932 685.867 768.066C680.8 763.799 678 751.932 680.133 743.932C680.933 741.132 681.6 736.732 681.6 734.199C681.6 729.932 682.4 725.932 686 713.399C687.867 706.732 691.2 700.466 693.333 699.666C696.267 698.732 696.8 703.799 695.067 720.999C693.2 740.332 693.6 742.066 700.8 742.066C710.8 742.066 715.2 734.466 715.067 716.866C715.067 709.932 714.4 703.666 713.6 702.866C712.933 702.199 712.267 700.332 712.267 698.999C712.267 695.132 708 688.866 703.6 686.066C699.067 683.266 692.4 682.199 685.6 682.999ZM899.733 703.532C903.067 706.199 904.933 717.666 904.933 734.332C904.933 749.399 904.667 751.666 902.133 754.999C893.333 766.866 883.467 752.466 883.733 728.066C883.867 709.532 888 699.666 894.933 701.399C896.667 701.932 898.933 702.866 899.733 703.532Z" fill="#c0392b"/>
            </svg>
          </span>
          <div style={S.navSocial}>
            <a href="https://www.instagram.com/pucciotto_lecce/" target="_blank" rel="noopener noreferrer" style={{ display: "flex", alignItems: "center", opacity: 0.55, transition: "opacity .2s" }} onMouseEnter={e => e.currentTarget.style.opacity=1} onMouseLeave={e => e.currentTarget.style.opacity=0.55} aria-label="Instagram">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <defs><radialGradient id="ig" cx="30%" cy="107%" r="150%"><stop offset="0%" stopColor="#fdf497"/><stop offset="5%" stopColor="#fdf497"/><stop offset="45%" stopColor="#fd5949"/><stop offset="60%" stopColor="#d6249f"/><stop offset="90%" stopColor="#285AEB"/></radialGradient></defs>
                <rect x="2" y="2" width="20" height="20" rx="6" fill="url(#ig)"/>
                <circle cx="12" cy="12" r="4.5" stroke="white" strokeWidth="1.8" fill="none"/>
                <circle cx="17.5" cy="6.5" r="1.2" fill="white"/>
              </svg>
            </a>
            <a href="https://www.facebook.com/pucciottolecce/" target="_blank" rel="noopener noreferrer" style={{ display: "flex", alignItems: "center", opacity: 0.55, transition: "opacity .2s" }} onMouseEnter={e => e.currentTarget.style.opacity=1} onMouseLeave={e => e.currentTarget.style.opacity=0.55} aria-label="Facebook">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <rect width="24" height="24" rx="6" fill="#1877F2"/>
                <path d="M15.5 8H13.5C13.2239 8 13 8.22386 13 8.5V11H15.5L15 13H13V20H11V13H9V11H11V8.5C11 7.11929 12.1193 6 13.5 6H15.5V8Z" fill="white"/>
              </svg>
            </a>
            <a href="https://www.tiktok.com/@pucciotto_lecce" target="_blank" rel="noopener noreferrer" style={{ display: "flex", alignItems: "center", opacity: 0.55, transition: "opacity .2s" }} onMouseEnter={e => e.currentTarget.style.opacity=1} onMouseLeave={e => e.currentTarget.style.opacity=0.55} aria-label="TikTok">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <rect width="24" height="24" rx="6" fill="#010101"/>
                <path d="M16 7.5C16 7.5 16.5 10 19 10V12.5C19 12.5 17 12.5 16 11.5V16C16 18.2091 14.2091 20 12 20C9.79086 20 8 18.2091 8 16C8 13.7909 9.79086 12 12 12C12.3506 12 12.6872 12.0474 13 12.1357V14.7C12.7063 14.5979 12.3601 14.5 12 14.5C11.1716 14.5 10.5 15.1716 10.5 16C10.5 16.8284 11.1716 17.5 12 17.5C12.8284 17.5 13.5 16.8284 13.5 16V4H16V7.5Z" fill="white"/>
              </svg>
            </a>
          </div>
          <div style={S.navR}>
            {page !== "menu" && page !== "tracking" && <button style={S.navBtn} onClick={() => setPage("menu")}>← Menu</button>}
            {page !== "cart" && page !== "tracking" && (
              <button style={S.cartBtn} onClick={() => setPage("cart")}>
                🛒 {cartCount > 0 ? `${cartCount} — €${cartTotalFinal.toFixed(2)}` : "Carrello"}
              </button>
            )}
            <button style={S.adminBtn} onClick={() => setPage("admin")}>⚙</button>
          </div>
        </div>
      </nav>

      {/* ── MENU PAGE ── */}
      {page === "menu" && (
        <MenuPage
          restaurantOnline={restaurantOnline}
          nextSlot={nextSlot}
          orderType={orderType} setOrderType={setOrderType}
          minOrder={minOrder}
          deliveryFee={deliveryFee}
          menuItems={menuItems}
          cart={cart}
          addToCart={addToCart}
          removeFromCart={removeFromCart}
          updateQty={updateQty}
          onGoToCart={(o) => { if (o) { setOrder(o); setPage("tracking"); } else { setPage("cart"); } }}
          openingHours={openingHours}
        />
      )}

      {/* ── CART PAGE ── */}
      {page === "cart" && (
        <CartPage
          cart={cart}
          orderType={orderType} setOrderType={setOrderType}
          cartTotal={cartTotal}
          cartTotalFinal={cartTotalFinal}
          deliveryCost={deliveryCost}
          minOrder={minOrder} minOrderNotMet={minOrderNotMet}
          customerInfo={customerInfo} setCustomerInfo={setCustomerInfo}
          gdprAccepted={gdprAccepted} setGdprAccepted={setGdprAccepted}
          payMethod={payMethod} setPayMethod={setPayMethod}
          canProceed={canProceed}
          checkoutLoading={checkoutLoading}
          checkoutError={checkoutError}
          nextSlot={nextSlot}
          submitOrder={submitOrder}
          updateQty={updateQty}
          removeFromCart={removeFromCart}
          onGoToMenu={() => setPage("menu")}
        />
      )}

      {/* ── TRACKING PAGE ── */}
      {page === "tracking" && !order && <TrackingSearch onFound={(o) => setOrder(o)} onBack={() => setPage("menu")} />}
      {page === "tracking" && order && (
        <div style={S.main}>
          <div style={S.trackPage}>
            <div style={S.tokBox}>
              <div style={S.tokLbl}>Il tuo token ordine</div>
              <div style={S.tokCode}>{order.token}</div>
              <div style={S.tokSub}>Una copia è stata inviata a {order.customer_email || ""}</div>
            </div>
            <div style={S.progWrap}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
                <span style={{ fontSize: 14, fontWeight: 600 }}>Stato ordine</span>
                <span style={{ fontSize: 13, color: RED, fontWeight: 600 }}>{STATUS_CONFIG[order.status]?.label || "Ricevuto"}</span>
              </div>
              <div style={S.progBar}><div style={S.progFill(trackProgress)} /></div>
              <div style={S.steps}>
                {[
                  { label: "Ricevuto",        icon: "📋", statuses: ["received", "preparing", "almost_ready", "ready", "delivered"] },
                  { label: "In preparazione", icon: "👨‍🍳", statuses: ["preparing", "almost_ready", "ready", "delivered"] },
                  { label: "Quasi pronto",    icon: "⏳", statuses: ["almost_ready", "ready", "delivered"] },
                  { label: "Pronto",          icon: "✅", statuses: ["ready", "delivered"] },
                ].map(st => {
                  const active = st.statuses.includes(order.status);
                  return (
                    <div key={st.label} style={S.step(active)}>
                      <div style={{ fontSize: 16, marginBottom: 4 }}>{st.icon}</div>
                      <div>{st.label}</div>
                    </div>
                  );
                })}
              </div>
            </div>
            <div style={{ background: "#fff8f0", border: "1px solid #ffe4cc", borderRadius: 12, padding: "16px 20px", marginBottom: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "#996633", marginBottom: 4 }}>⏱ Tempo stimato</div>
              <div style={{ fontFamily: "Lobster,cursive", fontSize: 28, color: RED }}>{order.est_min || 15}–{order.est_max || 25} minuti</div>
            </div>
            <div style={S.recBox}>
              <div style={{ fontFamily: "Lobster,cursive", fontSize: 22, color: BLACK, marginBottom: 16 }}>Ricevuta</div>
              {(order.items || []).map((it, i) => (
                <div key={i} style={S.recRow}>
                  <span>{it.qty}× {it.name}</span>
                  <span style={{ fontWeight: 600 }}>€{(it.price * it.qty).toFixed(2)}</span>
                </div>
              ))}
              {Number(order.delivery_fee) > 0 && (
                <div style={S.recRow}><span>🛵 Spese consegna</span><span style={{ fontWeight: 600 }}>€{Number(order.delivery_fee).toFixed(2)}</span></div>
              )}
              <div style={{ display: "flex", justifyContent: "space-between", paddingTop: 8, fontWeight: 700, fontSize: 16 }}>
                <span>Totale</span>
                <span style={{ fontFamily: "Lobster,cursive", fontSize: 22, color: RED }}>€{Number(order.total).toFixed(2)}</span>
              </div>
              <div style={{ marginTop: 14, paddingTop: 14, borderTop: "1px solid #f0ece8", fontSize: 12, color: "#999" }}>
                Token: <strong style={{ color: BLACK }}>{order.token}</strong>
              </div>
              {order.notes && (
                <div style={{ marginTop: 10, paddingTop: 10, borderTop: "1px solid #f0ece8", fontSize: 12, color: "#996633" }}>
                  📝 Note: <span style={{ color: "#555" }}>{order.notes}</span>
                </div>
              )}
            </div>
            <a href="tel:+393339117296" style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10, marginTop: 16, padding: "13px 20px", background: "#f0fff4", border: "1px solid #b2dfdb", borderRadius: 12, textDecoration: "none", color: "#1b5e20" }}>
              <span style={{ fontSize: 20 }}>📞</span>
              <div>
                <div style={{ fontWeight: 700, fontSize: 14 }}>Chiama il ristorante</div>
                <div style={{ fontSize: 12, opacity: .7 }}>+39 333 911 7296</div>
              </div>
            </a>
            <div style={{ textAlign: "center", marginTop: 16 }}>
              <button style={{ background: RED, color: WHITE, border: "none", borderRadius: 8, padding: "12px 28px", cursor: "pointer", fontFamily: "DM Sans,sans-serif", fontWeight: 600, fontSize: 14 }}
                onClick={() => { const done = ["delivered", "cancelled"].includes(order.status); if (done) setOrder(null); setPage("menu"); }}>
                {["delivered", "cancelled"].includes(order.status) ? "Nuovo ordine" : "← Torna al menu"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
