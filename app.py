import re
import datetime as dt
from typing import List, Dict, Optional

import streamlit as st
import gspread
from oauth2client.service_account import ServiceAccountCredentials

# =========================
# CẤU HÌNH / HẰNG SỐ
# =========================
SHEET_KEY = st.secrets["SHEET_KEY"]  # dán trong Secrets
LOGIN_WS_INDEX = 0                   # worksheet đăng nhập: sheet đầu tiên (dshs)
COL_USERNAME = "username"
COL_PASSWORD = "password"
COL_NAMHOC   = "namhoc"
COL_LOP      = "lop"
COL_NGAYSINH = "ngaysinh"           # dd/mm/yyyy (khuyến nghị)
# Nếu có cột tên học sinh trong sheet đăng nhập, điền 1 trong 2 tên sau:
POSSIBLE_NAME_COLUMNS = ["hoten", "hovaten"]

# =========================
# KẾT NỐI GOOGLE SHEETS
# =========================
@st.cache_resource
def get_gsheet_client():
    # quyền đọc/ghi spreadsheets
    scope = ["https://www.googleapis.com/auth/spreadsheets"]
    creds = ServiceAccountCredentials.from_json_keyfile_dict(
        st.secrets["gcp_service_account"], scopes=scope
    )
    return gspread.authorize(creds)

def open_login_ws():
    """Mở worksheet chứa dữ liệu đăng nhập (sheet đầu tiên)."""
    return get_gsheet_client().open_by_key(SHEET_KEY).get_worksheet(LOGIN_WS_INDEX)

@st.cache_data
def read_login_records() -> List[Dict]:
    """Đọc toàn bộ records (bỏ hàng tiêu đề) từ sheet đăng nhập."""
    return open_login_ws().get_all_records()

def clear_login_cache():
    read_login_records.clear()

# =========================
# TIỆN ÍCH XỬ LÝ DÒNG NGƯỜI DÙNG
# =========================
def find_user_row(username: str) -> Optional[int]:
    """
    Tìm số dòng (1-based) của user trong sheet đăng nhập (bao gồm hàng tiêu đề).
    Trả về None nếu không thấy.
    """
    ws = open_login_ws()
    headers = [h.strip().lower() for h in ws.row_values(1)]
    try:
        idx_username = headers.index(COL_USERNAME)
    except ValueError:
        return None

    # dò từng dòng cột username
    col_letter = gspread.utils.rowcol_to_a1(1, idx_username + 1)[0]  # chữ cái cột
    usernames = ws.col_values(idx_username + 1)
    for i, val in enumerate(usernames, start=1):
        if i == 1:
            continue  # header
        if str(val).strip() == username.strip():
            return i
    return None

def get_headers(ws) -> List[str]:
    return [h.strip() for h in ws.row_values(1)]

def header_index(headers: List[str], name: str) -> Optional[int]:
    """Trả về chỉ số 0-based của header 'name' (không phân biệt hoa thường)."""
    lname = name.strip().lower()
    for i, h in enumerate(headers):
        if h.strip().lower() == lname:
            return i
    return None

def normalize_date_str(s: str) -> Optional[str]:
    """
    Chuẩn hóa chuỗi ngày về định dạng dd/mm/yyyy.
    Hỗ trợ 'dd/mm/yyyy', 'yyyy-mm-dd', 'dd-mm-yyyy', v.v.
    """
    s = s.strip()
    # yyyy-mm-dd
    m = re.match(r"^\s*(\d{4})[-/](\d{1,2})[-/](\d{1,2})\s*$", s)
    if m:
        y, mo, d = map(int, m.groups())
        try:
            return dt.date(y, mo, d).strftime("%d/%m/%Y")
        except ValueError:
            return None
    # dd/mm/yyyy hoặc dd-mm-yyyy
    m = re.match(r"^\s*(\d{1,2})[-/](\d{1,2})[-/](\d{4})\s*$", s)
    if m:
        d, mo, y = map(int, m.groups())
        try:
            return dt.date(y, mo, d).strftime("%d/%m/%Y")
        except ValueError:
            return None
    return None

def weekday_vn(d: dt.date) -> str:
    # ISO weekday: 1=Mon..7=Sun
    mapping = {1:"Thứ 2",2:"Thứ 3",3:"Thứ 4",4:"Thứ 5",5:"Thứ 6",6:"Thứ 7",7:"Chủ nhật"}
    return mapping[d.isoweekday()]

# =========================
# ĐĂNG NHẬP / ĐỔI MẬT KHẨU
# =========================
def validate_login(username: str, password: str) -> bool:
    records = read_login_records()
    hits = [
        r for r in records
        if str(r.get(COL_USERNAME, "")).strip() == username.strip()
        and str(r.get(COL_PASSWORD, "")).strip() == password.strip()
    ]
    return len(hits) == 1

def try_change_password_and_email(
    username: str,
    namhoc_in: str,
    lop_in: str,
    ngaysinh_in: str,
    new_password: str,
    email_in: str
) -> bool:
    """
    Điều kiện đổi mật khẩu:
      - Cùng dòng username khớp: namhoc, lop, ngaysinh (so sánh chuẩn hóa)
      - Lưu mật khẩu mới vào cột 'password'
      - Thêm/ghi 'email' vào cột ngay sau 'ngaysinh' (tự tạo header nếu trống)
    """
    ws = open_login_ws()
    headers = get_headers(ws)

    idx_user = header_index(headers, COL_USERNAME)
    idx_pass = header_index(headers, COL_PASSWORD)
    idx_nh   = header_index(headers, COL_NAMHOC)
    idx_lop  = header_index(headers, COL_LOP)
    idx_ns   = header_index(headers, COL_NGAYSINH)

    if None in (idx_user, idx_pass, idx_nh, idx_lop, idx_ns):
        st.error("Thiếu một trong các cột bắt buộc: username, password, namhoc, lop, ngaysinh.")
        return False

    row = find_user_row(username)
    if not row:
        return False

    # Lấy giá trị hiện có
    row_values = ws.row_values(row)
    # đảm bảo đủ độ dài
    while len(row_values) < len(headers):
        row_values.append("")

    # So khớp năm học, lớp, ngày sinh
    nh_ok   = str(row_values[idx_nh]).strip()  == str(namhoc_in).strip()
    lop_ok  = str(row_values[idx_lop]).strip() == str(lop_in).strip()

    ns_sheet = normalize_date_str(str(row_values[idx_ns]))
    ns_input = normalize_date_str(ngaysinh_in)
    ns_ok    = (ns_sheet is not None and ns_sheet == ns_input)

    if not (nh_ok and lop_ok and ns_ok):
        return False

    # Cột email = cột ngay sau 'ngaysinh'
    email_col_index = idx_ns + 2  # 1-based col: idx 0 -> col 1, +1 nữa để sau ngaysinh
    # nếu header email đang rỗng, điền 'email'
    if len(headers) < email_col_index:
        # thêm cột trống đến vị trí cần
        for _ in range(email_col_index - len(headers)):
            headers.append("")
        ws.update_cell(1, email_col_index, "email")
        headers[email_col_index - 1] = "email"
    elif headers[email_col_index - 1].strip() == "":
        ws.update_cell(1, email_col_index, "email")
        headers[email_col_index - 1] = "email"

    # Cập nhật password + email
    ws.update_cell(row, idx_pass + 1, new_password.strip())
    ws.update_cell(row, email_col_index, email_in.strip())
    clear_login_cache()
    return True

# =========================
# LẤY DANH SÁCH TÊN HỌC SINH (NẾU CÓ)
# =========================
def get_student_list_for_user(username: str) -> List[str]:
    """
    Cố gắng lấy danh sách học sinh cùng lớp/năm học với user (nếu sheet có cột tên).
    Nếu không tìm thấy cột tên → trả về [] để app cho nhập tay.
    """
    ws = open_login_ws()
    headers = [h.strip().lower() for h in ws.row_values(1)]

    idx_user = header_index(headers, COL_USERNAME)
    idx_nh   = header_index(headers, COL_NAMHOC)
    idx_lop  = header_index(headers, COL_LOP)
    if None in (idx_user, idx_nh, idx_lop):
        return []

    row = find_user_row(username)
    if not row:
        return []

    row_vals = ws.row_values(row)
    # đảm bảo độ dài
    while len(row_vals) < len(headers):
        row_vals.append("")
    my_nh = str(row_vals[idx_nh]).strip()
    my_lop = str(row_vals[idx_lop]).strip()

    # Tìm cột tên
    name_idx = None
    for cand in POSSIBLE_NAME_COLUMNS:
        i = header_index(headers, cand)
        if i is not None:
            name_idx = i
            break
    if name_idx is None:
        return []

    # Lọc theo cùng namhoc / lop
    all_rows = ws.get_all_records()
    names = []
    for r in all_rows:
        if str(r.get(COL_NAMHOC, "")).strip() == my_nh and str(r.get(COL_LOP, "")).strip() == my_lop:
            nm = str(r.get(headers[name_idx], "")).strip()
            if nm:
                names.append(nm)
    # unique + sort
    return sorted(list(dict.fromkeys(names)))

# =========================
# LƯU VI PHẠM VÀO SHEET THEO USERNAME
# =========================
def open_or_create_user_sheet(username: str):
    """
    Mở sheet có tên đúng bằng username. Nếu chưa có, tạo mới và đặt header:
    tuan | hoten | thu | noidung
    """
    ss = get_gsheet_client().open_by_key(SHEET_KEY)
    try:
        ws = ss.worksheet(username)
    except gspread.WorksheetNotFound:
        ws = ss.add_worksheet(title=username, rows=1000, cols=6)
        ws.update("A1:D1", [["tuan", "hoten", "thu", "noidung"]])
    return ws

def append_violation(username: str, tuan: str, hoten: str, thu_label: str, noidung: str):
    ws = open_or_create_user_sheet(username)
    ws.append_row([tuan, hoten, thu_label, noidung], value_input_option="USER_ENTERED")

# =========================
# GIAO DIỆN
# =========================
def login_view():
    st.subheader("🔐 Đăng nhập")
    with st.form("login_form"):
        u = st.text_input("Tên đăng nhập ", key="login_user")
        p = st.text_input("Mật khẩu ", type="password", key="login_pw")
        ok = st.form_submit_button("Đăng nhập")
    if ok:
        if not u or not p:
            st.warning("⚠️ Nhập đủ tên đăng nhập và mật khẩu.")
        elif validate_login(u, p):
            st.session_state.logged_in = True
            st.session_state.username = u.strip()
            st.success("✅ Đăng nhập thành công.")
            st.rerun()
        else:
            st.error("❌ Sai tên đăng nhập hoặc mật khẩu.")

def change_password_view():
    st.markdown("### 🔄 Đổi mật khẩu & cập nhật email")
    st.info("Điều kiện đổi mật khẩu: **năm học, lớp, ngày sinh** khớp với thông tin trong Google Sheets.")

    with st.form("change_pw_form"):
        col1, col2 = st.columns(2)
        with col1:
            namhoc = st.text_input("Năm học (cột 'namhoc')", placeholder="VD: 2025-2026")
            lop = st.text_input("Lớp (cột 'lop')", placeholder="VD: 12/1")
        with col2:
            ns_date = st.date_input("Ngày sinh", value=None, format="DD/MM/YYYY")
            email = st.text_input("Email (sẽ lưu ở cột liền sau 'ngaysinh')", placeholder="email@domain.com")

        new_pw = st.text_input("Mật khẩu mới", type="password")
        new_pw2 = st.text_input("Nhập lại mật khẩu mới", type="password")
        commit = st.form_submit_button("Cập nhật")

    if commit:
        if not (namhoc and lop and ns_date and email and new_pw and new_pw2):
            st.warning("⚠️ Vui lòng nhập đầy đủ các trường.")
            return
        if new_pw != new_pw2:
            st.error("❌ Mật khẩu mới không trùng khớp.")
            return
        ns_str = ns_date.strftime("%d/%m/%Y")
        ok = try_change_password_and_email(
            st.session_state.username,
            namhoc, lop, ns_str, new_pw, email
        )
        if ok:
            st.success("✅ Đổi mật khẩu & cập nhật email thành công.")
        else:
            st.error("❌ Không đổi được mật khẩu. Kiểm tra lại Năm học / Lớp / Ngày sinh có khớp với Google Sheets không.")

def violation_form_view():
    st.markdown("### 📝 Nhập dữ liệu vi phạm")
    st.caption("Dữ liệu sẽ lưu vào **sheet có tên đúng bằng username** của bạn, với các cột: tuan | hoten | thu | noidung.")

    # Tuần: 1..35
    tuan = st.selectbox("Tuần thứ", [str(i) for i in range(1, 36)], index=0)

    # Họ tên: ưu tiên dropdown nếu lấy được danh sách; nếu không, nhập tay
    names = get_student_list_for_user(st.session_state.username)
    if names:
        hoten = st.selectbox("Họ và tên học sinh", names)
    else:
        hoten = st.text_input("Họ và tên học sinh (do sheet không có cột tên)")

    # Dropdown 14 ngày tới (thứ + ngày) để chọn
    today = dt.date.today()
    options = []
    for i in range(0, 14):
        d = today + dt.timedelta(days=i)
        options.append(f"{weekday_vn(d)}, {d.strftime('%d/%m/%Y')}")
    thu_label = st.selectbox("Chọn Thứ + Ngày", options)

    noidung = st.text_area("Nội dung vi phạm")

    if st.button("Lưu dữ liệu"):
        if not (tuan and hoten and thu_label and noidung):
            st.warning("⚠️ Vui lòng nhập đủ thông tin.")
            return
        try:
            append_violation(st.session_state.username, tuan, hoten, thu_label, noidung)
            st.success("✅ Đã lưu.")
        except Exception as e:
            st.error(f"❌ Lỗi khi lưu dữ liệu: {e}")

def main():
    st.set_page_config(page_title="Hệ thống đăng nhập & nhập liệu", page_icon="🔐", layout="centered")

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.username = ""

    st.title("🔐 HỆ THỐNG ĐĂNG NHẬP ")

    if not st.session_state.logged_in:
        login_view()
    else:
        st.success(f"Xin chào **{st.session_state.username}**")
        st.markdown("---")

        # Khu đổi mật khẩu + email (luôn hiển thị; nếu Boss muốn "bắt buộc lần đầu", thêm cột flag để kiểm tra)
        with st.expander("Đổi mật khẩu & cập nhật email", expanded=False):
            change_password_view()

        st.markdown("---")
        violation_form_view()

        st.markdown("---")
        if st.button("Đăng xuất"):
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.rerun()

if __name__ == "__main__":
    main()
