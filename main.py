import flet as ft
import sqlite3
import hashlib
import os
from datetime import datetime
import flet_local_auth as auth
from flet.security import encrypt, decrypt

# ==========================================================
# CONFIGURACIÓN
# ==========================================================
DB_NAME = "password_vault.db"
MASTER_ENCRYPTION_KEY = "DH_Super_Secret_Key_200716_ChangeMe!"

# ==========================================================
# BASE DE DATOS
# ==========================================================
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS config (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            created_at TEXT,
            updated_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
    return key.hex(), salt.hex()

def verify_password(password, stored_hash, salt_hex):
    salt = bytes.fromhex(salt_hex)
    new_hash, _ = hash_password(password, salt)
    return new_hash == stored_hash

def get_config():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT username, password_hash, salt FROM config WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    return row

def save_config(username, password):
    pw_hash, salt_hex = hash_password(password)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM config")
    cursor.execute(
        "INSERT INTO config (id, username, password_hash, salt) VALUES (1, ?, ?, ?)",
        (username, pw_hash, salt_hex)
    )
    conn.commit()
    conn.close()

# ==========================================================
# APLICACIÓN
# ==========================================================
def main(page: ft.Page):
    page.title = "Bóveda DH"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 20
    page.scroll = ft.ScrollMode.AUTO

    init_db()
    config = get_config()
    is_first_run = config is None

    # Autenticación biométrica real (Android)
    async def require_auth(reason: str) -> bool:
        local_auth = auth.LocalAuthentication()
        try:
            return await local_auth.authenticate(reason, biometric_only=False)
        except Exception:
            return False

    # --- PANTALLA LOGIN ---
    def show_login_screen():
        page.controls.clear()
        if is_first_run:
            username_field = ft.TextField(label="Elige un usuario", value="DH")
            password_field = ft.TextField(label="Elige una contraseña maestra", password=True, can_reveal_password=True)
            def create_account(e):
                if not username_field.value or not password_field.value:
                    page.snack_bar = ft.SnackBar(ft.Text("Completa todos los campos"))
                    page.snack_bar.open = True
                    page.update()
                    return
                save_config(username_field.value, password_field.value)
                nonlocal config, is_first_run
                config = get_config()
                is_first_run = False
                show_login_screen()
            page.add(
                ft.Text("🔐 Bóveda DH", size=30, weight=ft.FontWeight.BOLD),
                ft.Text("Primer uso: crea tu cuenta", size=16, color=ft.Colors.GREY),
                ft.Divider(),
                username_field, password_field,
                ft.ElevatedButton("Crear Cuenta", on_click=create_account, width=200),
            )
        else:
            stored_username, stored_hash, stored_salt = config
            username_field = ft.TextField(label="Usuario", value="DH")
            password_field = ft.TextField(label="Contraseña", password=True, can_reveal_password=True)
            def login(e):
                if username_field.value == stored_username and verify_password(password_field.value, stored_hash, stored_salt):
                    show_main_screen()
                else:
                    page.snack_bar = ft.SnackBar(ft.Text("Usuario o contraseña incorrectos"))
                    page.snack_bar.open = True
                    page.update()
            page.add(
                ft.Text("🔐 Bóveda DH", size=30, weight=ft.FontWeight.BOLD),
                ft.Text("Inicia sesión", size=16, color=ft.Colors.GREY),
                ft.Divider(),
                username_field, password_field,
                ft.ElevatedButton("Entrar", on_click=login, width=200),
            )
        page.update()

    # --- PANTALLA PRINCIPAL ---
    def show_main_screen():
        page.controls.clear()
        list_view = ft.ListView(expand=True, spacing=10)

        def load_entries():
            list_view.controls.clear()
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT id, identifier FROM vault ORDER BY id DESC")
            rows = cursor.fetchall()
            conn.close()
            for row_id, identifier in rows:
                list_view.controls.append(
                    ft.Card(content=ft.ListTile(
                        leading=ft.Icon(ft.Icons.KEY),
                        title=ft.Text(identifier),
                        trailing=ft.Icon(ft.Icons.CHEVRON_RIGHT),
                        on_click=lambda e, rid=row_id, ident=identifier: asyncio.create_task(open_view_dialog(rid, ident))
                    ))
                )
            page.update()

        def close_dialog(dialog):
            dialog.open = False
            page.update()

        def open_add_dialog(e):
            id_field = ft.TextField(label="ID (ej. Gmail, Banco)", autofocus=True)
            pw_field = ft.TextField(label="Contraseña", password=True, can_reveal_password=True)
            def save_entry(e):
                if not id_field.value or not pw_field.value:
                    return
                encrypted = encrypt(pw_field.value, MASTER_ENCRYPTION_KEY)
                now = datetime.now().isoformat()
                conn = sqlite3.connect(DB_NAME)
                cursor = conn.cursor()
                cursor.execute("INSERT INTO vault (identifier, encrypted_password, created_at, updated_at) VALUES (?, ?, ?, ?)",
                               (id_field.value, encrypted, now, now))
                conn.commit()
                conn.close()
                dialog.open = False
                load_entries()
                page.update()
            dialog = ft.AlertDialog(
                title=ft.Text("Agregar Contraseña"),
                content=ft.Column([id_field, pw_field], tight=True, spacing=15),
                actions=[ft.TextButton("Cancelar", on_click=lambda e: close_dialog(dialog)),
                         ft.ElevatedButton("Almacenar", on_click=save_entry)]
            )
            page.overlay.append(dialog)
            dialog.open = True
            page.update()

        async def open_view_dialog(entry_id, identifier):
            authenticated = await require_auth(f"Ver contraseña de {identifier}")
            if not authenticated:
                return
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT encrypted_password FROM vault WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            conn.close()
            if not row:
                return
            decrypted = decrypt(row[0], MASTER_ENCRYPTION_KEY)
            pw_field = ft.TextField(label="Contraseña", value=decrypted, password=True, can_reveal_password=True)
            def save_edit(e):
                new_encrypted = encrypt(pw_field.value, MASTER_ENCRYPTION_KEY)
                now = datetime.now().isoformat()
                conn = sqlite3.connect(DB_NAME)
                cursor = conn.cursor()
                cursor.execute("UPDATE vault SET encrypted_password = ?, updated_at = ? WHERE id = ?",
                               (new_encrypted, now, entry_id))
                conn.commit()
                conn.close()
                dialog.open = False
                load_entries()
                page.update()
            dialog = ft.AlertDialog(
                title=ft.Text(identifier),
                content=ft.Column([pw_field], tight=True, spacing=10),
                actions=[ft.TextButton("Cerrar", on_click=lambda e: close_dialog(dialog)),
                         ft.ElevatedButton("Guardar cambios", on_click=save_edit)]
            )
            page.overlay.append(dialog)
            dialog.open = True
            page.update()

        def open_settings(e):
            current_pw = ft.TextField(label="Contraseña actual", password=True)
            new_pw = ft.TextField(label="Nueva contraseña", password=True)
            confirm_pw = ft.TextField(label="Confirmar nueva", password=True)
            async def change_master(e):
                auth_ok = await require_auth("Confirma tu identidad para cambiar la contraseña")
                if not auth_ok:
                    return
                stored = get_config()
                if not verify_password(current_pw.value, stored[1], stored[2]):
                    page.snack_bar = ft.SnackBar(ft.Text("Contraseña actual incorrecta"))
                    page.snack_bar.open = True
                    page.update()
                    return
                if new_pw.value != confirm_pw.value or len(new_pw.value) < 4:
                    page.snack_bar = ft.SnackBar(ft.Text("Las contraseñas no coinciden o son muy cortas"))
                    page.snack_bar.open = True
                    page.update()
                    return
                save_config(stored[0], new_pw.value)
                dialog.open = False
                show_login_screen()
            dialog = ft.AlertDialog(
                title=ft.Text("⚙️ Ajustes"),
                content=ft.Column([current_pw, new_pw, confirm_pw], tight=True, spacing=10),
                actions=[ft.TextButton("Cancelar", on_click=lambda e: close_dialog(dialog)),
                         ft.ElevatedButton("Cambiar", on_click=lambda e: asyncio.create_task(change_master(e)))]
            )
            page.overlay.append(dialog)
            dialog.open = True
            page.update()

        app_bar = ft.AppBar(
            title=ft.Text("Bóveda DH"),
            actions=[ft.IconButton(ft.Icons.SETTINGS, on_click=open_settings),
                     ft.IconButton(ft.Icons.ADD, on_click=open_add_dialog)]
        )
        page.add(app_bar, list_view)
        load_entries()
        page.update()

    show_login_screen()

if __name__ == "__main__":
    ft.app(target=main)